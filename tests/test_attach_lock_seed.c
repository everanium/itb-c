/*
 * test_attach_lock_seed.c — coverage for the low-level
 * itb_seed_attach_lock_seed mutator.
 *
 * Mirrors bindings/rust/tests/test_attach_lock_seed.rs one-to-one. The
 * dedicated lockSeed routes the bit-permutation derivation through its
 * own state instead of the noiseSeed: the per-chunk PRF closure
 * captures BOTH the lockSeed's components AND its hash function, so the
 * lockSeed primitive may legitimately differ from the noiseSeed
 * primitive within the same native hash width — keying-material
 * isolation plus algorithm diversity for defence-in-depth on the
 * bit-permutation channel, without changing the public encrypt /
 * decrypt signatures.
 *
 * The bit-permutation overlay must be engaged via itb_set_bit_soup or
 * itb_set_lock_soup before any encrypt call — without the overlay, the
 * dedicated lockSeed has no observable effect on the wire output, and
 * the Go-side build-PRF guard surfaces as **ITB_ENCRYPT_FAILED**. These
 * tests exercise both the round-trip path with overlay engaged and the
 * attach-time misuse rejections (self-attach, post-encrypt switching,
 * width mismatch).
 *
 * Per-binary fork() isolation gives each test its own libitb
 * process-globals; no in-process serial lock is needed.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "itb.h"

/* Engages set_lock_soup(1) for the duration of the test body, then
 * restores the prior values. The set_lock_soup setter auto-couples
 * BitSoup=1 inside libitb, so both flags are restored on exit. */
static void with_lock_soup_on_begin(int *prev_bs, int *prev_ls) {
    *prev_bs = itb_get_bit_soup();
    *prev_ls = itb_get_lock_soup();
    ck_assert_int_eq(itb_set_lock_soup(1), ITB_OK);
}

static void with_lock_soup_on_end(int prev_bs, int prev_ls) {
    (void) itb_set_bit_soup(prev_bs);
    (void) itb_set_lock_soup(prev_ls);
}

START_TEST(test_attach_lock_seed_roundtrip)
{
    int prev_bs = 0, prev_ls = 0;
    with_lock_soup_on_begin(&prev_bs, &prev_ls);

    static const uint8_t plaintext[] = "attach_lock_seed roundtrip payload";
    size_t pt_len = sizeof(plaintext) - 1;

    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL, *ls = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ds), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ss), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ls), ITB_OK);
    ck_assert_int_eq(itb_seed_attach_lock_seed(ns, ls), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt(ns, ds, ss, plaintext, pt_len, &ct, &ct_len), ITB_OK);
    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_decrypt(ns, ds, ss, ct, ct_len, &pt, &pt_out_len), ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_seed_free(ns);
    itb_seed_free(ds);
    itb_seed_free(ss);
    itb_seed_free(ls);

    with_lock_soup_on_end(prev_bs, prev_ls);
}
END_TEST

START_TEST(test_attach_lock_seed_persistence)
{
    int prev_bs = 0, prev_ls = 0;
    with_lock_soup_on_begin(&prev_bs, &prev_ls);

    static const uint8_t plaintext[] = "cross-process attach lockseed roundtrip";
    size_t pt_len = sizeof(plaintext) - 1;

    /* Day 1 — sender. */
    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL, *ls = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ds), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ss), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ls), ITB_OK);
    ck_assert_int_eq(itb_seed_attach_lock_seed(ns, ls), ITB_OK);

    uint64_t ns_comps[32], ds_comps[32], ss_comps[32], ls_comps[32];
    size_t ns_cn = 0, ds_cn = 0, ss_cn = 0, ls_cn = 0;
    ck_assert_int_eq(itb_seed_components(ns, ns_comps, 32, &ns_cn), ITB_OK);
    ck_assert_int_eq(itb_seed_components(ds, ds_comps, 32, &ds_cn), ITB_OK);
    ck_assert_int_eq(itb_seed_components(ss, ss_comps, 32, &ss_cn), ITB_OK);
    ck_assert_int_eq(itb_seed_components(ls, ls_comps, 32, &ls_cn), ITB_OK);

    uint8_t ns_key[64], ds_key[64], ss_key[64], ls_key[64];
    size_t ns_kl = 0, ds_kl = 0, ss_kl = 0, ls_kl = 0;
    ck_assert_int_eq(itb_seed_hash_key(ns, ns_key, sizeof(ns_key), &ns_kl), ITB_OK);
    ck_assert_int_eq(itb_seed_hash_key(ds, ds_key, sizeof(ds_key), &ds_kl), ITB_OK);
    ck_assert_int_eq(itb_seed_hash_key(ss, ss_key, sizeof(ss_key), &ss_kl), ITB_OK);
    ck_assert_int_eq(itb_seed_hash_key(ls, ls_key, sizeof(ls_key), &ls_kl), ITB_OK);

    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt(ns, ds, ss, plaintext, pt_len, &ct, &ct_len), ITB_OK);

    itb_seed_free(ns);
    itb_seed_free(ds);
    itb_seed_free(ss);
    itb_seed_free(ls);

    /* Day 2 — receiver. */
    itb_seed_t *ns2 = NULL, *ds2 = NULL, *ss2 = NULL, *ls2 = NULL;
    ck_assert_int_eq(itb_seed_from_components("blake3", ns_comps, ns_cn,
                                              ns_key, ns_kl, &ns2), ITB_OK);
    ck_assert_int_eq(itb_seed_from_components("blake3", ds_comps, ds_cn,
                                              ds_key, ds_kl, &ds2), ITB_OK);
    ck_assert_int_eq(itb_seed_from_components("blake3", ss_comps, ss_cn,
                                              ss_key, ss_kl, &ss2), ITB_OK);
    ck_assert_int_eq(itb_seed_from_components("blake3", ls_comps, ls_cn,
                                              ls_key, ls_kl, &ls2), ITB_OK);
    ck_assert_int_eq(itb_seed_attach_lock_seed(ns2, ls2), ITB_OK);

    uint8_t *pt = NULL; size_t pt_out_len = 0;
    ck_assert_int_eq(itb_decrypt(ns2, ds2, ss2, ct, ct_len, &pt, &pt_out_len), ITB_OK);
    ck_assert_uint_eq(pt_out_len, pt_len);
    ck_assert_mem_eq(pt, plaintext, pt_len);

    itb_buffer_free(ct);
    itb_buffer_free(pt);
    itb_seed_free(ns2);
    itb_seed_free(ds2);
    itb_seed_free(ss2);
    itb_seed_free(ls2);

    with_lock_soup_on_end(prev_bs, prev_ls);
}
END_TEST

START_TEST(test_attach_lock_seed_self_attach_rejected)
{
    itb_seed_t *ns = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_attach_lock_seed(ns, ns), ITB_BAD_INPUT);
    itb_seed_free(ns);
}
END_TEST

START_TEST(test_attach_lock_seed_width_mismatch_rejected)
{
    itb_seed_t *ns_256 = NULL; /* width 256 */
    itb_seed_t *ls_128 = NULL; /* width 128 */
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ns_256), ITB_OK);
    ck_assert_int_eq(itb_seed_new("siphash24", 1024, &ls_128), ITB_OK);
    ck_assert_int_eq(itb_seed_attach_lock_seed(ns_256, ls_128), ITB_SEED_WIDTH_MIX);
    itb_seed_free(ns_256);
    itb_seed_free(ls_128);
}
END_TEST

START_TEST(test_attach_lock_seed_post_encrypt_attach_rejected)
{
    int prev_bs = 0, prev_ls = 0;
    with_lock_soup_on_begin(&prev_bs, &prev_ls);

    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL, *ls = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ds), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ss), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ls), ITB_OK);
    ck_assert_int_eq(itb_seed_attach_lock_seed(ns, ls), ITB_OK);

    /* Encrypt once — locks future attach_lock_seed calls. */
    static const uint8_t pre[] = "pre-switch";
    uint8_t *ct = NULL; size_t ct_len = 0;
    ck_assert_int_eq(itb_encrypt(ns, ds, ss, pre, sizeof(pre) - 1,
                                 &ct, &ct_len), ITB_OK);
    itb_buffer_free(ct);

    itb_seed_t *ls2 = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ls2), ITB_OK);
    ck_assert_int_eq(itb_seed_attach_lock_seed(ns, ls2), ITB_BAD_INPUT);

    itb_seed_free(ns);
    itb_seed_free(ds);
    itb_seed_free(ss);
    itb_seed_free(ls);
    itb_seed_free(ls2);

    with_lock_soup_on_end(prev_bs, prev_ls);
}
END_TEST

START_TEST(test_attach_lock_seed_overlay_off_fails_on_encrypt)
{
    int prev_bs = itb_get_bit_soup();
    int prev_ls = itb_get_lock_soup();
    ck_assert_int_eq(itb_set_bit_soup(0), ITB_OK);
    ck_assert_int_eq(itb_set_lock_soup(0), ITB_OK);

    itb_seed_t *ns = NULL, *ds = NULL, *ss = NULL, *ls = NULL;
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ns), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ds), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ss), ITB_OK);
    ck_assert_int_eq(itb_seed_new("blake3", 1024, &ls), ITB_OK);
    ck_assert_int_eq(itb_seed_attach_lock_seed(ns, ls), ITB_OK);

    static const uint8_t pt[] = "overlay off - should fail";
    uint8_t *ct = NULL; size_t ct_len = 0;
    itb_status_t rc = itb_encrypt(ns, ds, ss, pt, sizeof(pt) - 1, &ct, &ct_len);
    ck_assert_int_ne(rc, ITB_OK);
    ck_assert_ptr_null(ct);

    itb_seed_free(ns);
    itb_seed_free(ds);
    itb_seed_free(ss);
    itb_seed_free(ls);

    (void) itb_set_bit_soup(prev_bs);
    (void) itb_set_lock_soup(prev_ls);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("attach_lock_seed");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 60);
    tcase_add_test(tc, test_attach_lock_seed_roundtrip);
    tcase_add_test(tc, test_attach_lock_seed_persistence);
    tcase_add_test(tc, test_attach_lock_seed_self_attach_rejected);
    tcase_add_test(tc, test_attach_lock_seed_width_mismatch_rejected);
    tcase_add_test(tc, test_attach_lock_seed_post_encrypt_attach_rejected);
    tcase_add_test(tc, test_attach_lock_seed_overlay_off_fails_on_encrypt);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
