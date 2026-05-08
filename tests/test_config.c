/*
 * test_config.c — process-global configuration roundtrip tests.
 *
 * Mirrors bindings/rust/tests/test_config.rs one-to-one. Mutates
 * libitb's process-wide atomics (bit_soup, lock_soup, max_workers,
 * nonce_bits, barrier_fill); per-binary fork() isolation gives this
 * test its own libitb global state, so no in-process serial lock is
 * required.
 */

#include <check.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "itb.h"

START_TEST(test_config_bit_soup_roundtrip)
{
    int orig = itb_get_bit_soup();
    ck_assert_int_eq(itb_set_bit_soup(1), ITB_OK);
    ck_assert_int_eq(itb_get_bit_soup(), 1);
    ck_assert_int_eq(itb_set_bit_soup(0), ITB_OK);
    ck_assert_int_eq(itb_get_bit_soup(), 0);
    ck_assert_int_eq(itb_set_bit_soup(orig), ITB_OK);
}
END_TEST

START_TEST(test_config_lock_soup_roundtrip)
{
    int orig = itb_get_lock_soup();
    ck_assert_int_eq(itb_set_lock_soup(1), ITB_OK);
    ck_assert_int_eq(itb_get_lock_soup(), 1);
    ck_assert_int_eq(itb_set_lock_soup(orig), ITB_OK);
}
END_TEST

START_TEST(test_config_max_workers_roundtrip)
{
    int orig = itb_get_max_workers();
    ck_assert_int_eq(itb_set_max_workers(4), ITB_OK);
    ck_assert_int_eq(itb_get_max_workers(), 4);
    ck_assert_int_eq(itb_set_max_workers(orig), ITB_OK);
}
END_TEST

START_TEST(test_config_nonce_bits_validation)
{
    int orig = itb_get_nonce_bits();
    static const int VALID[] = {128, 256, 512};
    for (size_t i = 0; i < sizeof(VALID) / sizeof(VALID[0]); i++) {
        ck_assert_int_eq(itb_set_nonce_bits(VALID[i]), ITB_OK);
        ck_assert_int_eq(itb_get_nonce_bits(), VALID[i]);
    }
    static const int BAD[] = {0, 1, 192, 1024};
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        ck_assert_int_eq(itb_set_nonce_bits(BAD[i]), ITB_BAD_INPUT);
    }
    ck_assert_int_eq(itb_set_nonce_bits(orig), ITB_OK);
}
END_TEST

START_TEST(test_config_barrier_fill_validation)
{
    int orig = itb_get_barrier_fill();
    static const int VALID[] = {1, 2, 4, 8, 16, 32};
    for (size_t i = 0; i < sizeof(VALID) / sizeof(VALID[0]); i++) {
        ck_assert_int_eq(itb_set_barrier_fill(VALID[i]), ITB_OK);
        ck_assert_int_eq(itb_get_barrier_fill(), VALID[i]);
    }
    static const int BAD[] = {0, 3, 5, 7, 64};
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        ck_assert_int_eq(itb_set_barrier_fill(BAD[i]), ITB_BAD_INPUT);
    }
    ck_assert_int_eq(itb_set_barrier_fill(orig), ITB_OK);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("config");
    TCase *tc = tcase_create("core");
    tcase_set_timeout(tc, 30);
    tcase_add_test(tc, test_config_bit_soup_roundtrip);
    tcase_add_test(tc, test_config_lock_soup_roundtrip);
    tcase_add_test(tc, test_config_max_workers_roundtrip);
    tcase_add_test(tc, test_config_nonce_bits_validation);
    tcase_add_test(tc, test_config_barrier_fill_validation);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failures == 0 ? 0 : 1;
}
