/*
 * eitb — command-line demonstrator for the ITB C binding.
 *
 * Subcommands:
 *
 *   eitb version                                   library + binding versions
 *   eitb hashes                                    shipped hash primitive roster
 *   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
 *   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
 *
 * `encrypt` prints the session blob to stderr as hex; feed that hex
 * back to `decrypt` on the receiving side.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "itb.h"

static int usage(void)
{
    fprintf(stderr,
            "usage: eitb version\n"
            "       eitb hashes\n"
            "       eitb encrypt <profile> <in-file> <out-file>\n"
            "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>\n");
    return 2;
}

static int fail_status(const char *what, itb_status st)
{
    fprintf(stderr, "eitb: %s: status %d (%s): %s\n", what, (int)st,
            itb_status_str(st), itb_last_error());
    return 1;
}

/* Reads a whole file into a malloc'd buffer. Returns NULL on error
 * (message printed). */
static uint8_t *read_file(const char *path, size_t *len_out)
{
    *len_out = 0;
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "eitb: cannot open %s\n", path);
        return NULL;
    }
    size_t cap = 65536;
    size_t len = 0;
    uint8_t *buf = malloc(cap);
    if (buf == NULL) {
        fclose(f);
        fprintf(stderr, "eitb: out of memory\n");
        return NULL;
    }
    for (;;) {
        if (len == cap) {
            if (cap > (SIZE_MAX >> 1)) {
                free(buf);
                fclose(f);
                fprintf(stderr, "eitb: %s too large\n", path);
                return NULL;
            }
            cap *= 2;
            uint8_t *grown = realloc(buf, cap);
            if (grown == NULL) {
                free(buf);
                fclose(f);
                fprintf(stderr, "eitb: out of memory\n");
                return NULL;
            }
            buf = grown;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) {
            break;
        }
    }
    if (ferror(f)) {
        free(buf);
        fclose(f);
        fprintf(stderr, "eitb: read error on %s\n", path);
        return NULL;
    }
    fclose(f);
    *len_out = len;
    return buf;
}

/* Profiles whose canonical name begins with "streaming-" route
 * through the one-shot streaming buffered pair instead of the Single
 * Message pair. */
static int is_streaming_profile(const char *profile)
{
    return strncmp(profile, "streaming-", 10) == 0;
}

/* Recursively creates the parent directory of `out` (analogue of
 * `mkdir -p $(dirname out)`). Silent when the directory already
 * exists; returns 0 on success and -1 on genuine filesystem failure. */
static int ensure_parent_dir(const char *out)
{
    /* Locate the last '/' in `out`; anything before it is the parent
     * directory. Nothing to do if there is no parent component. */
    const char *slash = strrchr(out, '/');
    if (slash == NULL || slash == out) {
        return 0;
    }
    size_t parent_len = (size_t)(slash - out);
    char *parent = malloc(parent_len + 1);
    if (parent == NULL) {
        return -1;
    }
    memcpy(parent, out, parent_len);
    parent[parent_len] = '\0';
    /* Walk the path, creating each intermediate directory. */
    for (size_t i = 1; i <= parent_len; i++) {
        if (parent[i] == '/' || parent[i] == '\0') {
            char saved = parent[i];
            parent[i] = '\0';
            if (mkdir(parent, 0755) != 0 && errno != EEXIST) {
                fprintf(stderr, "eitb: mkdir %s: %s\n", parent,
                        strerror(errno));
                free(parent);
                return -1;
            }
            parent[i] = saved;
        }
    }
    free(parent);
    return 0;
}

/* Writes a whole buffer to a file. Returns 0 on success. */
static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    if (ensure_parent_dir(path) != 0) {
        return 1;
    }
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "eitb: cannot create %s\n", path);
        return 1;
    }
    if (len > 0 && fwrite(buf, 1, len, f) != len) {
        fclose(f);
        fprintf(stderr, "eitb: write error on %s\n", path);
        return 1;
    }
    if (fclose(f) != 0) {
        fprintf(stderr, "eitb: close error on %s\n", path);
        return 1;
    }
    return 0;
}

static int cmd_version(void)
{
    const char *v = itb_version();
    if (v == NULL) {
        fprintf(stderr, "eitb: cannot read libitb version\n");
        return 1;
    }
    printf("libitb %s\n", v);
    printf("itb-c %s\n", ITB_C_VERSION);
    return 0;
}

static int cmd_hashes(void)
{
    size_t n = itb_hash_count();
    for (size_t i = 0; i < n; i++) {
        const char *name = itb_hash_name(i);
        if (name == NULL) {
            fprintf(stderr, "eitb: itb_hash_name(%zu) failed\n", i);
            return 1;
        }
        printf("%2zu  %-12s %d bits\n", i, name, itb_hash_width(i));
    }
    return 0;
}

/* Defensive Go-runtime pacing for cipher workloads on large files:
 * a soft memory cap + aggressive GC keep the scratch heap bounded.
 * The setter return values report the previous settings, not an
 * error. */
static void cap_go_runtime(void)
{
    (void)itb_set_memory_limit(512LL << 20); /* 512 MiB soft cap */
    (void)itb_set_gc_percent(20);            /* aggressive GC */
}

static int cmd_encrypt(const char *profile, const char *infile,
                       const char *outfile)
{
    cap_go_runtime();
    size_t plain_len = 0;
    uint8_t *plain = read_file(infile, &plain_len);
    if (plain == NULL) {
        return 1;
    }
    itb_pipeline *pipe = NULL;
    itb_status st = itb_pipeline_init(profile, NULL, &pipe);
    if (st != ITB_STATUS_OK) {
        free(plain);
        return fail_status("init", st);
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (is_streaming_profile(profile)) {
        st = itb_pipeline_encrypt_stream_pump(pipe, plain, plain_len,
                                              &wire, &wire_len);
    } else {
        st = itb_pipeline_encrypt_message(pipe, plain, plain_len,
                                          &wire, &wire_len);
    }
    if (st != ITB_STATUS_OK) {
        free(plain);
        itb_pipeline_free(pipe);
        return fail_status("encrypt", st);
    }
    int rc = write_file(outfile, wire, wire_len);
    if (rc == 0) {
        const uint8_t *blob = itb_pipeline_blob(pipe);
        size_t blob_len = itb_pipeline_blob_len(pipe);
        for (size_t i = 0; i < blob_len; i++) {
            fprintf(stderr, "%02x", blob[i]);
        }
        fprintf(stderr, "\n");
        printf("encrypted %s -> %s (%zu -> %zu bytes)\n", infile, outfile,
               plain_len, wire_len);
    }
    free(plain);
    itb_bytes_free(wire);
    itb_pipeline_free(pipe);
    return rc;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int cmd_decrypt(const char *profile, const char *blob_hex,
                       const char *infile, const char *outfile)
{
    cap_go_runtime();
    size_t hex_len = strlen(blob_hex);
    if (hex_len == 0 || hex_len % 2 != 0) {
        fprintf(stderr, "eitb: blob hex has odd or zero length\n");
        return 1;
    }
    size_t blob_len = hex_len / 2;
    uint8_t *blob = malloc(blob_len);
    if (blob == NULL) {
        fprintf(stderr, "eitb: out of memory\n");
        return 1;
    }
    for (size_t i = 0; i < blob_len; i++) {
        int hi = hex_nibble(blob_hex[2 * i]);
        int lo = hex_nibble(blob_hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(blob);
            fprintf(stderr, "eitb: invalid blob hex\n");
            return 1;
        }
        blob[i] = (uint8_t)((hi << 4) | lo);
    }
    size_t wire_len = 0;
    uint8_t *wire = read_file(infile, &wire_len);
    if (wire == NULL) {
        free(blob);
        return 1;
    }
    itb_pipeline *pipe = NULL;
    itb_status st = itb_pipeline_open(profile, blob, blob_len,
                                      NULL, NULL, 0, NULL, 0, &pipe);
    free(blob);
    if (st != ITB_STATUS_OK) {
        free(wire);
        return fail_status("open", st);
    }
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    if (is_streaming_profile(profile)) {
        st = itb_pipeline_decrypt_stream_pump(pipe, wire, wire_len,
                                              &plain, &plain_len);
    } else {
        st = itb_pipeline_decrypt_message(pipe, wire, wire_len,
                                          &plain, &plain_len);
    }
    if (st != ITB_STATUS_OK) {
        free(wire);
        itb_pipeline_free(pipe);
        return fail_status("decrypt", st);
    }
    int rc = write_file(outfile, plain, plain_len);
    if (rc == 0) {
        printf("decrypted %s -> %s (%zu -> %zu bytes)\n", infile, outfile,
               wire_len, plain_len);
    }
    free(wire);
    itb_bytes_free(plain);
    itb_pipeline_free(pipe);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        return usage();
    }
    if (strcmp(argv[1], "version") == 0 && argc == 2) {
        return cmd_version();
    }
    if (strcmp(argv[1], "hashes") == 0 && argc == 2) {
        return cmd_hashes();
    }
    if (strcmp(argv[1], "encrypt") == 0 && argc == 5) {
        return cmd_encrypt(argv[2], argv[3], argv[4]);
    }
    if (strcmp(argv[1], "decrypt") == 0 && argc == 6) {
        return cmd_decrypt(argv[2], argv[3], argv[4], argv[5]);
    }
    return usage();
}
