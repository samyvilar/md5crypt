//
//  md5crypt.c taken from openssl source
//  bcrypt
//
//  Created by Samy Vilar on 05/06/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/evp.h>


#include "md5crypt.h"

char *md5crypt(const char *passwd, const char *salt)
{
    static unsigned const char cov_2char[64]={
            /* from crypto/des/fcrypt.c */
            0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,
            0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,
            0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,
            0x4D,0x4E,0x4F,0x50,0x51,0x52,0x53,0x54,
            0x55,0x56,0x57,0x58,0x59,0x5A,0x61,0x62,
            0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,
            0x6B,0x6C,0x6D,0x6E,0x6F,0x70,0x71,0x72,
            0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A
    };

    const char *magic = "1";
    static char out_buf[6 + 9 + 24 + 2]; /* "$apr1$..salt..$.......md5hash..........\0" */
    unsigned char buf[MD5_DIGEST_LENGTH];
    char *salt_out;
    int n;
    unsigned int i;
    EVP_MD_CTX md,md2;
    size_t passwd_len, salt_len;

    passwd_len = strlen(passwd);
    out_buf[0] = '$';
    out_buf[1] = 0;

    strncat(out_buf, magic, 4);
    strncat(out_buf, "$", 1);
    strncat(out_buf, salt, 8);
    assert(strlen(out_buf) <= 6 + 8); /* "$apr1$..salt.." */
    salt_out = out_buf + 2 + strlen(magic);
    salt_len = strlen(salt_out);
    assert(salt_len <= 8);

    EVP_MD_CTX_init(&md);
    EVP_DigestInit_ex(&md,EVP_md5(), NULL);
    EVP_DigestUpdate(&md, passwd, passwd_len);
    EVP_DigestUpdate(&md, "$", 1);
    EVP_DigestUpdate(&md, magic, strlen(magic));
    EVP_DigestUpdate(&md, "$", 1);
    EVP_DigestUpdate(&md, salt_out, salt_len);

    EVP_MD_CTX_init(&md2);
    EVP_DigestInit_ex(&md2,EVP_md5(), NULL);
    EVP_DigestUpdate(&md2, passwd, passwd_len);
    EVP_DigestUpdate(&md2, salt_out, salt_len);
    EVP_DigestUpdate(&md2, passwd, passwd_len);
    EVP_DigestFinal_ex(&md2, buf, NULL);

    for (i = passwd_len; i > sizeof buf; i -= sizeof buf)
        EVP_DigestUpdate(&md, buf, sizeof buf);
    EVP_DigestUpdate(&md, buf, i);

    n = passwd_len;
    while (n)
    {
        EVP_DigestUpdate(&md, (n & 1) ? "\0" : passwd, 1);
        n >>= 1;
    }
    EVP_DigestFinal_ex(&md, buf, NULL);

    for (i = 0; i < 1000; i++)
    {
        EVP_DigestInit_ex(&md2,EVP_md5(), NULL);
        EVP_DigestUpdate(&md2, (i & 1) ? (unsigned const char *) passwd : buf,
                (i & 1) ? passwd_len : sizeof buf);
        if (i % 3)
            EVP_DigestUpdate(&md2, salt_out, salt_len);
        if (i % 7)
            EVP_DigestUpdate(&md2, passwd, passwd_len);
        EVP_DigestUpdate(&md2, (i & 1) ? buf : (unsigned const char *) passwd,
                (i & 1) ? sizeof buf : passwd_len);
        EVP_DigestFinal_ex(&md2, buf, NULL);
    }
    EVP_MD_CTX_cleanup(&md2);

    {
        /* transform buf into output string */

        unsigned char buf_perm[sizeof buf];
        int dest, source;
        char *output;

        /* silly output permutation */
        for (dest = 0, source = 0; dest < 14; dest++, source = (source + 6) % 17)
            buf_perm[dest] = buf[source];
        buf_perm[14] = buf[5];
        buf_perm[15] = buf[11];
#ifndef PEDANTIC /* Unfortunately, this generates a "no effect" warning */
        assert(16 == sizeof buf_perm);
#endif

        output = salt_out + salt_len;
        assert(output == out_buf + strlen(out_buf));

        *output++ = '$';

        for (i = 0; i < 15; i += 3)
        {
            *output++ = cov_2char[buf_perm[i+2] & 0x3f];
            *output++ = cov_2char[((buf_perm[i+1] & 0xf) << 2) |
                    (buf_perm[i+2] >> 6)];
            *output++ = cov_2char[((buf_perm[i] & 3) << 4) |
                    (buf_perm[i+1] >> 4)];
            *output++ = cov_2char[buf_perm[i] >> 2];
        }
        assert(i == 15);
        *output++ = cov_2char[buf_perm[i] & 0x3f];
        *output++ = cov_2char[buf_perm[i] >> 6];
        *output = 0;
        assert(strlen(out_buf) < sizeof(out_buf));
    }
    EVP_MD_CTX_cleanup(&md);

    return out_buf;
}

