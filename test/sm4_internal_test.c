/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal tests for the SM4 module.
 */

#include <string.h>
#include <openssl/opensslconf.h>
#include "testutil.h"

#include <sys/time.h>

#ifndef OPENSSL_NO_SM4
# include "internal/sm4.h"

#include <stdbool.h>
#include <openssl/modes.h>
#include "crypto/modes/modes_lcl.h"

static int test_sm4_ecb(void)
{
    struct timeval tvstart;
    struct timeval tvend;
    unsigned long counrt = 10000000;
    unsigned long costus = 0;

    static const uint8_t k[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    /*
     * This test vector comes from Example 1 of GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     */
    static const uint8_t expected[SM4_BLOCK_SIZE] = {
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
        0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    };

    /*
     * This test vector comes from Example 2 from GB/T 32907-2016,
     * and described in Internet Draft draft-ribose-cfrg-sm4-02.
     * After 1,000,000 iterations.
     */
    static const uint8_t expected_iter[SM4_BLOCK_SIZE] = {
        0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
        0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66
    };

    int i;
    SM4_KEY key;
    uint8_t block[SM4_BLOCK_SIZE];

    SM4_set_key(k, &key);
    memcpy(block, input, SM4_BLOCK_SIZE);

    SM4_encrypt(block, block, &key);
    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected, SM4_BLOCK_SIZE))
        return 0;

    gettimeofday(&tvstart, NULL);
    while (counrt > 0) {
        SM4_encrypt(input, block, &key);
        counrt --;
    }
    gettimeofday(&tvend, NULL);

    costus = (tvend.tv_sec - tvstart.tv_sec) * 1000000
        + (tvend.tv_usec - tvstart.tv_usec);

    printf("cost %ld us\n", costus);

    for (i = 0; i != 999999; ++i)
        SM4_encrypt(block, block, &key);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, expected_iter, SM4_BLOCK_SIZE))
        return 0;

    for (i = 0; i != 1000000; ++i)
        SM4_decrypt(block, block, &key);

    if (!TEST_mem_eq(block, SM4_BLOCK_SIZE, input, SM4_BLOCK_SIZE))
        return 0;

    return 1;
}
#endif

static int test_sm4_block(void)
{
    static const uint8_t k[SM4_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    static const uint8_t input[SM4_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    int i;
    SM4_KEY key;
    uint8_t block[SM4_BLOCK_SIZE];

    SM4_set_key(k, &key);

    SM4_encrypt(input, block, &key);

    for (i=0; i<SM4_BLOCK_SIZE; i++) {
        printf("0x%02x ", block[i]);
        if (i%16 == 15) {
            printf("\n");
        }
    }
    if (i%16 != 0) {
        printf("\n");
    }

    return 1;
}

void SM4_block(const unsigned char in[16],
                            unsigned char out[16], const void *key)
{
    SM4_KEY subkey;
    SM4_set_key(key, &subkey);
    SM4_encrypt(in, out, &subkey);
}

static int test_sm4_xts(void)
{
    uint8_t iv_key[SM4_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    uint8_t pt_key[SM4_BLOCK_SIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    uint8_t pt[SM4_BLOCK_SIZE*2] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    uint8_t iv[SM4_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    uint8_t ct[SM4_BLOCK_SIZE*2] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    int i;

    XTS128_CONTEXT ctx;

    ctx.key1 = pt_key;
    ctx.key2 = iv_key;
    ctx.block1 = SM4_block;
    ctx.block2 = SM4_block;

    CRYPTO_xts128_encrypt(&ctx,
            iv,
            pt,
            ct,
            SM4_BLOCK_SIZE*2,
            true);

    for (i=0; i<SM4_BLOCK_SIZE*2; i++) {
        printf("0x%02x ", ct[i]);
        if (i%16 == 15) {
            printf("\n");
        }
    }
    if (i%16 != 0) {
        printf("\n");
    }

    return 1;
}

int setup_tests(void)
{
#ifndef OPENSSL_NO_SM4
    ADD_TEST(test_sm4_block);
    ADD_TEST(test_sm4_ecb);
    ADD_TEST(test_sm4_xts);
#endif
    return 1;
}
