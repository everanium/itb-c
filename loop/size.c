/*
 * Size and duration parsing, the monotonic clock, and the human
 * renderings of sizes, rates and durations. Every rendering here is
 * part of the output contract shared with the Go harness and the
 * other bindings' loop utilities, so the formats are fixed to the
 * character, not to taste.
 */

#define _POSIX_C_SOURCE 200809L /* clock_gettime under -std=c11 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "loop.h"

/* Parses a human byte-size string ("16MB", "1MiB", "512K",
 * "1073741824") into a byte count. Every suffix is a binary multiple:
 * K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
 * bytes; matching is case-insensitive and surrounding whitespace is
 * trimmed. Returns 0 on success, -1 on a malformed or negative value. */
int parse_size(const char *s, int64_t *out)
{
    while (isspace((unsigned char)*s)) {
        s++;
    }
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        len--;
    }
    char upper[64];
    if (len == 0 || len >= sizeof(upper)) {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        upper[i] = (char)toupper((unsigned char)s[i]);
    }
    upper[len] = '\0';

    int64_t mult = 1;
    size_t digits = len;
    static const struct {
        const char *suffix;
        int64_t mult;
    } table[] = {
        { "KIB", (int64_t)1 << 10 }, { "KB", (int64_t)1 << 10 }, { "K", (int64_t)1 << 10 },
        { "MIB", (int64_t)1 << 20 }, { "MB", (int64_t)1 << 20 }, { "M", (int64_t)1 << 20 },
        { "GIB", (int64_t)1 << 30 }, { "GB", (int64_t)1 << 30 }, { "G", (int64_t)1 << 30 },
        { "B", 1 },
    };
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        size_t sl = strlen(table[i].suffix);
        if (len >= sl && strcmp(upper + len - sl, table[i].suffix) == 0) {
            mult = table[i].mult;
            digits = len - sl;
            break;
        }
    }
    while (digits > 0 && isspace((unsigned char)upper[digits - 1])) {
        digits--;
    }
    if (digits == 0) {
        return -1;
    }
    for (size_t i = 0; i < digits; i++) {
        if (!isdigit((unsigned char)upper[i])) {
            return -1;
        }
    }
    upper[digits] = '\0';
    errno = 0;
    long long n = strtoll(upper, NULL, 10);
    if (errno != 0 || n < 0 || (mult > 1 && n > INT64_MAX / mult)) {
        return -1;
    }
    *out = (int64_t)n * mult;
    return 0;
}

/* Parses the Go duration grammar — a sequence of decimal numbers each
 * followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
 * "1h30m", "1.5s" — into nanoseconds. Returns 0 on success, -1 on a
 * malformed string. */
int parse_duration(const char *s, int64_t *out_ns)
{
    static const struct {
        const char *unit;
        double ns;
    } units[] = {
        { "ns", 1.0 }, { "us", 1e3 }, { "ms", 1e6 },
        { "s", 1e9 }, { "m", 60e9 }, { "h", 3600e9 },
    };
    if (*s == '\0') {
        return -1;
    }
    double total = 0.0;
    while (*s != '\0') {
        char *end = NULL;
        if (!isdigit((unsigned char)*s) && *s != '.') {
            return -1;
        }
        double v = strtod(s, &end);
        if (end == s || v < 0.0) {
            return -1;
        }
        s = end;
        double mult = 0.0;
        for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
            size_t ul = strlen(units[i].unit);
            if (strncmp(s, units[i].unit, ul) == 0
                && !isalpha((unsigned char)s[ul])) {
                mult = units[i].ns;
                s += ul;
                break;
            }
        }
        if (mult == 0.0) {
            return -1;
        }
        total += v * mult;
    }
    if (total > 9.2e18) {
        return -1;
    }
    *out_ns = (int64_t)total;
    return 0;
}

/* Monotonic wall clock in nanoseconds. */
int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

/* Renders a byte count with a binary-unit suffix: "1.0GiB",
 * "16.0MiB", "4.0KiB", "512B". */
void human_bytes(int64_t n, char *out, size_t cap)
{
    if (n >= ((int64_t)1 << 30)) {
        (void)snprintf(out, cap, "%.1fGiB", (double)n / (double)((int64_t)1 << 30));
    } else if (n >= ((int64_t)1 << 20)) {
        (void)snprintf(out, cap, "%.1fMiB", (double)n / (double)((int64_t)1 << 20));
    } else if (n >= ((int64_t)1 << 10)) {
        (void)snprintf(out, cap, "%.1fKiB", (double)n / (double)((int64_t)1 << 10));
    } else {
        (void)snprintf(out, cap, "%lldB", (long long)n);
    }
}

/* Renders a possibly-negative byte delta with an explicit sign. */
void human_bytes_signed(int64_t n, char *out, size_t cap)
{
    char mag[32];
    if (n < 0) {
        human_bytes(-n, mag, sizeof(mag));
        (void)snprintf(out, cap, "-%s", mag);
    } else {
        human_bytes(n, mag, sizeof(mag));
        (void)snprintf(out, cap, "+%s", mag);
    }
}

/* Binary MiB per second over a nanosecond window; 0 when the window
 * is unmeasured. */
double mb_per_sec(int64_t bytes, int64_t ns)
{
    if (ns <= 0) {
        return 0.0;
    }
    return (double)bytes / (double)(1 << 20) / ((double)ns / 1e9);
}

/* Renders a throughput as "123.4MB/s" (binary MiB per second) or
 * "n/a" for an unmeasured window. */
void human_rate(int64_t bytes, int64_t ns, char *out, size_t cap)
{
    if (ns <= 0) {
        (void)snprintf(out, cap, "n/a");
        return;
    }
    (void)snprintf(out, cap, "%.1fMB/s", mb_per_sec(bytes, ns));
}

/* Appends the fractional part of a nanosecond remainder (0 .. 1e9)
 * as ".ddd" with trailing zeros removed; appends nothing for zero. */
static void append_fraction(char *out, size_t cap, int64_t frac_ns)
{
    if (frac_ns == 0) {
        return;
    }
    char digits[16];
    (void)snprintf(digits, sizeof(digits), "%09lld", (long long)frac_ns);
    size_t n = strlen(digits);
    while (n > 0 && digits[n - 1] == '0') {
        digits[--n] = '\0';
    }
    size_t used = strlen(out);
    (void)snprintf(out + used, cap - used, ".%s", digits);
}

/* Renders a duration the way Go's time.Duration prints: below one
 * second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
 * where the hour part appears when non-zero, the minute part when
 * the hour part appears or the minutes are non-zero, and the seconds
 * carry their fraction with trailing zeros removed ("5s", "5.003s",
 * "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first. */
void human_duration(int64_t ns, char *out, size_t cap)
{
    if (ns < 0) {
        ns = -ns;
    }
    if (ns == 0) {
        (void)snprintf(out, cap, "0s");
        return;
    }
    if (ns < 1000000000LL) {
        int64_t ms = ns / 1000000LL;
        int64_t frac = (ns % 1000000LL) * 1000LL; /* scale to 9 digits */
        (void)snprintf(out, cap, "%lld", (long long)ms);
        append_fraction(out, cap, frac);
        size_t used = strlen(out);
        (void)snprintf(out + used, cap - used, "ms");
        return;
    }
    int64_t hours = ns / 3600000000000LL;
    int64_t rem = ns % 3600000000000LL;
    int64_t minutes = rem / 60000000000LL;
    rem %= 60000000000LL;
    int64_t seconds = rem / 1000000000LL;
    int64_t frac = rem % 1000000000LL;
    out[0] = '\0';
    size_t used = 0;
    if (hours > 0) {
        (void)snprintf(out, cap, "%lldh", (long long)hours);
        used = strlen(out);
    }
    if (hours > 0 || minutes > 0) {
        (void)snprintf(out + used, cap - used, "%lldm", (long long)minutes);
        used = strlen(out);
    }
    (void)snprintf(out + used, cap - used, "%lld", (long long)seconds);
    append_fraction(out, cap, frac);
    used = strlen(out);
    (void)snprintf(out + used, cap - used, "s");
}
