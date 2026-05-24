/*
 * yint-core.c -- yint protocol portable C core, default ("soft") backend.
 *
 * Implements: SHA-256, HMAC-SHA256, AES-256-CBC + PKCS#7, CSPRNG,
 * lowercase hex codec, constant-time compare, key derivation, body
 * construction, request/response signing and verification.
 *
 * The AES implementation is a portable byte-oriented S-box + xtime
 * reference. On x86/x64 the AES-NI backend in yint-aesni.c overrides
 * the AES block dispatch at startup when cpuid reports support.
 */

#if !defined(_GNU_SOURCE)
#  define _GNU_SOURCE 1
#endif
#if !defined(_DEFAULT_SOURCE)
#  define _DEFAULT_SOURCE 1
#endif

#define YINT_BUILDING 1
#include "yint-core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================ */
/* Endian helpers                                                   */
/* ================================================================ */

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) | ((uint32_t)p[3]);
}

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t) v;
}

static void store_be64(uint8_t *p, uint64_t v) {
    store_be32(p,     (uint32_t)(v >> 32));
    store_be32(p + 4, (uint32_t)(v));
}

/* ================================================================ */
/* SHA-256                                                          */
/* ================================================================ */

static const uint32_t SHA256_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static const uint32_t SHA256_H0[8] = {
    0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
    0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
};

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a,b,c,d,e,f,g,hh;
    int i;

    for (i = 0; i < 16; ++i) w[i] = load_be32(block + 4 * i);
    for (i = 16; i < 64; ++i) {
        uint32_t s0 = ROTR32(w[i-15], 7) ^ ROTR32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR32(w[i-2], 17) ^ ROTR32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (i = 0; i < 64; ++i) {
        uint32_t S1 = ROTR32(e,6) ^ ROTR32(e,11) ^ ROTR32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = ROTR32(a,2) ^ ROTR32(a,13) ^ ROTR32(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
    h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

typedef struct {
    uint32_t h[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

static void sha256_init(sha256_ctx *c) {
    int i;
    for (i = 0; i < 8; ++i) c->h[i] = SHA256_H0[i];
    c->total = 0;
    c->buflen = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t dlen) {
    c->total += (uint64_t)dlen;
    if (c->buflen) {
        size_t need = 64 - c->buflen;
        if (dlen < need) {
            memcpy(c->buf + c->buflen, data, dlen);
            c->buflen += dlen;
            return;
        }
        memcpy(c->buf + c->buflen, data, need);
        sha256_compress(c->h, c->buf);
        data += need; dlen -= need; c->buflen = 0;
    }
    while (dlen >= 64) {
        sha256_compress(c->h, data);
        data += 64; dlen -= 64;
    }
    if (dlen) {
        memcpy(c->buf, data, dlen);
        c->buflen = dlen;
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bitlen = c->total * 8u;
    uint8_t pad[64];
    int i;

    pad[0] = 0x80;
    memset(pad + 1, 0, sizeof(pad) - 1);

    if (c->buflen < 56) {
        sha256_update(c, pad, 56 - c->buflen);
    } else {
        sha256_update(c, pad, 64 - c->buflen);
        memset(pad, 0, sizeof(pad));
        sha256_update(c, pad, 56);
    }
    {
        uint8_t lenb[8];
        store_be64(lenb, bitlen);
        sha256_update(c, lenb, 8);
    }
    for (i = 0; i < 8; ++i) store_be32(out + 4 * i, c->h[i]);
}

void yint_sha256(const uint8_t *msg, size_t mlen, uint8_t out[32]) {
    sha256_ctx c;
    sha256_init(&c);
    if (mlen) sha256_update(&c, msg, mlen);
    sha256_final(&c, out);
}

/* ================================================================ */
/* HMAC-SHA256                                                      */
/* ================================================================ */

void yint_hmac_init(yint_hmac_ctx *c, const uint8_t *key, size_t klen) {
    uint8_t kpad[64];
    uint8_t ipad[64];
    sha256_ctx s;
    int i;

    if (klen > 64) {
        uint8_t kh[32];
        yint_sha256(key, klen, kh);
        memcpy(kpad, kh, 32);
        memset(kpad + 32, 0, 32);
    } else {
        memcpy(kpad, key, klen);
        if (klen < 64) memset(kpad + klen, 0, 64 - klen);
    }

    for (i = 0; i < 64; ++i) {
        ipad[i]    = kpad[i] ^ 0x36;
        c->okey[i] = kpad[i] ^ 0x5c;
    }
    c->have_okey = 1;

    sha256_init(&s);
    sha256_update(&s, ipad, 64);

    /* copy state */
    memcpy(c->h, s.h, sizeof(s.h));
    c->total  = s.total;
    c->buflen = s.buflen;
    if (s.buflen) memcpy(c->buf, s.buf, s.buflen);
}

void yint_hmac_update(yint_hmac_ctx *c, const uint8_t *data, size_t dlen) {
    sha256_ctx s;
    memcpy(s.h, c->h, sizeof(s.h));
    s.total  = c->total;
    s.buflen = c->buflen;
    if (c->buflen) memcpy(s.buf, c->buf, c->buflen);
    sha256_update(&s, data, dlen);
    memcpy(c->h, s.h, sizeof(s.h));
    c->total  = s.total;
    c->buflen = s.buflen;
    if (s.buflen) memcpy(c->buf, s.buf, s.buflen);
}

void yint_hmac_final(yint_hmac_ctx *c, uint8_t out[32]) {
    uint8_t inner[32];
    sha256_ctx s;
    memcpy(s.h, c->h, sizeof(s.h));
    s.total  = c->total;
    s.buflen = c->buflen;
    if (c->buflen) memcpy(s.buf, c->buf, c->buflen);
    sha256_final(&s, inner);

    sha256_init(&s);
    sha256_update(&s, c->okey, 64);
    sha256_update(&s, inner, 32);
    sha256_final(&s, out);

    memset(c, 0, sizeof(*c));
}

void yint_hmac_sha256(const uint8_t *key, size_t klen,
                      const uint8_t *msg, size_t mlen,
                      uint8_t out[32]) {
    yint_hmac_ctx c;
    yint_hmac_init(&c, key, klen);
    if (mlen) yint_hmac_update(&c, msg, mlen);
    yint_hmac_final(&c, out);
}

/* ================================================================ */
/* AES-256                                                          */
/* ================================================================ */

static const uint8_t aes_sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t aes_inv_sbox[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t aes_rcon[15] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,
    0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d
};

#define AES_NR 14
#define AES_NK 8
#define AES_RKS ((AES_NR + 1) * 4)  /* 60 32-bit words */

static void aes256_key_expand(const uint8_t key[32], uint32_t rk[AES_RKS]) {
    int i;
    for (i = 0; i < 8; ++i) rk[i] = load_be32(key + 4 * i);
    for (i = 8; i < AES_RKS; ++i) {
        uint32_t t = rk[i - 1];
        if ((i % 8) == 0) {
            uint32_t r = (t << 8) | (t >> 24);
            uint32_t s = ((uint32_t)aes_sbox[(r >> 24) & 0xff] << 24)
                       | ((uint32_t)aes_sbox[(r >> 16) & 0xff] << 16)
                       | ((uint32_t)aes_sbox[(r >>  8) & 0xff] <<  8)
                       | ((uint32_t)aes_sbox[(r      ) & 0xff]      );
            t = s ^ ((uint32_t)aes_rcon[i / 8] << 24);
        } else if ((i % 8) == 4) {
            t = ((uint32_t)aes_sbox[(t >> 24) & 0xff] << 24)
              | ((uint32_t)aes_sbox[(t >> 16) & 0xff] << 16)
              | ((uint32_t)aes_sbox[(t >>  8) & 0xff] <<  8)
              | ((uint32_t)aes_sbox[(t      ) & 0xff]      );
        }
        rk[i] = rk[i - 8] ^ t;
    }
}

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void aes256_encrypt_block(const uint32_t rk[AES_RKS],
                                 const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    int r, i;

    /* AddRoundKey #0 */
    for (i = 0; i < 4; ++i) {
        uint32_t k = rk[i];
        s[4*i+0] = in[4*i+0] ^ (uint8_t)(k >> 24);
        s[4*i+1] = in[4*i+1] ^ (uint8_t)(k >> 16);
        s[4*i+2] = in[4*i+2] ^ (uint8_t)(k >>  8);
        s[4*i+3] = in[4*i+3] ^ (uint8_t)(k);
    }

    for (r = 1; r <= AES_NR; ++r) {
        uint8_t t[16];
        /* SubBytes */
        for (i = 0; i < 16; ++i) t[i] = aes_sbox[s[i]];
        /* ShiftRows -> reorder into s (columns of 4) */
        s[0]  = t[0];  s[1]  = t[5];  s[2]  = t[10]; s[3]  = t[15];
        s[4]  = t[4];  s[5]  = t[9];  s[6]  = t[14]; s[7]  = t[3];
        s[8]  = t[8];  s[9]  = t[13]; s[10] = t[2];  s[11] = t[7];
        s[12] = t[12]; s[13] = t[1];  s[14] = t[6];  s[15] = t[11];

        if (r != AES_NR) {
            /* MixColumns */
            for (i = 0; i < 4; ++i) {
                uint8_t a0 = s[4*i+0], a1 = s[4*i+1], a2 = s[4*i+2], a3 = s[4*i+3];
                uint8_t T  = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                uint8_t T0 = (uint8_t)(a0 ^ T ^ xtime((uint8_t)(a0 ^ a1)));
                uint8_t T1 = (uint8_t)(a1 ^ T ^ xtime((uint8_t)(a1 ^ a2)));
                uint8_t T2 = (uint8_t)(a2 ^ T ^ xtime((uint8_t)(a2 ^ a3)));
                uint8_t T3 = (uint8_t)(a3 ^ T ^ xtime((uint8_t)(a3 ^ a0)));
                s[4*i+0] = T0; s[4*i+1] = T1; s[4*i+2] = T2; s[4*i+3] = T3;
            }
        }

        /* AddRoundKey */
        for (i = 0; i < 4; ++i) {
            uint32_t k = rk[r * 4 + i];
            s[4*i+0] ^= (uint8_t)(k >> 24);
            s[4*i+1] ^= (uint8_t)(k >> 16);
            s[4*i+2] ^= (uint8_t)(k >>  8);
            s[4*i+3] ^= (uint8_t)(k);
        }
    }
    memcpy(out, s, 16);
}

static void aes256_decrypt_block(const uint32_t rk[AES_RKS],
                                 const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    int r, i;

    /* AddRoundKey final */
    for (i = 0; i < 4; ++i) {
        uint32_t k = rk[AES_NR * 4 + i];
        s[4*i+0] = in[4*i+0] ^ (uint8_t)(k >> 24);
        s[4*i+1] = in[4*i+1] ^ (uint8_t)(k >> 16);
        s[4*i+2] = in[4*i+2] ^ (uint8_t)(k >>  8);
        s[4*i+3] = in[4*i+3] ^ (uint8_t)(k);
    }

    for (r = AES_NR - 1; r >= 0; --r) {
        uint8_t t[16];
        /* InvShiftRows */
        t[0]  = s[0];  t[5]  = s[1];  t[10] = s[2];  t[15] = s[3];
        t[4]  = s[4];  t[9]  = s[5];  t[14] = s[6];  t[3]  = s[7];
        t[8]  = s[8];  t[13] = s[9];  t[2]  = s[10]; t[7]  = s[11];
        t[12] = s[12]; t[1]  = s[13]; t[6]  = s[14]; t[11] = s[15];
        /* InvSubBytes */
        for (i = 0; i < 16; ++i) s[i] = aes_inv_sbox[t[i]];
        /* AddRoundKey */
        for (i = 0; i < 4; ++i) {
            uint32_t k = rk[r * 4 + i];
            s[4*i+0] ^= (uint8_t)(k >> 24);
            s[4*i+1] ^= (uint8_t)(k >> 16);
            s[4*i+2] ^= (uint8_t)(k >>  8);
            s[4*i+3] ^= (uint8_t)(k);
        }
        if (r != 0) {
            /* InvMixColumns */
            for (i = 0; i < 4; ++i) {
                uint8_t a0 = s[4*i+0], a1 = s[4*i+1], a2 = s[4*i+2], a3 = s[4*i+3];
                /* multiply by 0e,0b,0d,09 */
                uint8_t b0,b1,b2,b3;
                /* helpers */
                uint8_t a02 = xtime(a0),       a04 = xtime(a02),       a08 = xtime(a04);
                uint8_t a12 = xtime(a1),       a14 = xtime(a12),       a18 = xtime(a14);
                uint8_t a22 = xtime(a2),       a24 = xtime(a22),       a28 = xtime(a24);
                uint8_t a32 = xtime(a3),       a34 = xtime(a32),       a38 = xtime(a34);
                /* 0e = 8^4^2 ; 0b = 8^2^1 ; 0d = 8^4^1 ; 09 = 8^1 */
                b0 = (uint8_t)((a08 ^ a04 ^ a02) ^ (a18 ^ a12 ^ a1) ^ (a28 ^ a24 ^ a2) ^ (a38 ^ a3));
                b1 = (uint8_t)((a08 ^ a0)         ^ (a18 ^ a14 ^ a12) ^ (a28 ^ a22 ^ a2) ^ (a38 ^ a34 ^ a3));
                b2 = (uint8_t)((a08 ^ a04 ^ a0)   ^ (a18 ^ a1)         ^ (a28 ^ a24 ^ a22) ^ (a38 ^ a32 ^ a3));
                b3 = (uint8_t)((a08 ^ a02 ^ a0)   ^ (a18 ^ a14 ^ a1)   ^ (a28 ^ a2)         ^ (a38 ^ a34 ^ a32));
                s[4*i+0] = b0; s[4*i+1] = b1; s[4*i+2] = b2; s[4*i+3] = b3;
            }
        }
    }
    memcpy(out, s, 16);
}

/* ----------- AES backend dispatch (default = soft) ----------- */

static void soft_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                             const uint8_t *in, size_t blocks, uint8_t *out) {
    uint32_t rk[AES_RKS];
    uint8_t prev[16];
    size_t i, j;

    aes256_key_expand(key, rk);
    memcpy(prev, iv, 16);
    for (i = 0; i < blocks; ++i) {
        uint8_t blk[16];
        for (j = 0; j < 16; ++j) blk[j] = (uint8_t)(in[i*16+j] ^ prev[j]);
        aes256_encrypt_block(rk, blk, out + i * 16);
        memcpy(prev, out + i * 16, 16);
    }
}

static void soft_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                             const uint8_t *in, size_t blocks, uint8_t *out) {
    uint32_t rk[AES_RKS];
    uint8_t prev[16];
    size_t i, j;

    aes256_key_expand(key, rk);
    memcpy(prev, iv, 16);
    for (i = 0; i < blocks; ++i) {
        uint8_t blk[16];
        aes256_decrypt_block(rk, in + i * 16, blk);
        for (j = 0; j < 16; ++j) out[i*16+j] = (uint8_t)(blk[j] ^ prev[j]);
        memcpy(prev, in + i * 16, 16);
    }
}

static const yint_aes_backend g_soft_backend = {
    "soft", soft_cbc_encrypt, soft_cbc_decrypt
};

static const yint_aes_backend *g_aes = &g_soft_backend;
static int g_aes_initialized = 0;

void yint__set_aes_backend(const yint_aes_backend *b) {
    if (b) g_aes = b;
}

#if (defined(__i386__) || defined(__x86_64__) || \
     defined(_M_IX86) || defined(_M_X64)) && !defined(YINT_NO_AESNI)
#  define YINT_HAVE_X86 1
#else
#  define YINT_HAVE_X86 0
#endif

#if !YINT_HAVE_X86
void yint_aesni_maybe_install(void) { /* no-op */ }
#endif

static void aes_dispatch_init(void) {
    if (g_aes_initialized) return;
    g_aes_initialized = 1;
#if YINT_HAVE_X86
    yint_aesni_maybe_install();
#endif
}

const char *yint_backend(void) {
    aes_dispatch_init();
    return g_aes->name;
}

const char *yint_version(void) {
    return "1.0.0";
}

/* ================================================================ */
/* PKCS#7 + CBC wrappers                                            */
/* ================================================================ */

int yint_aes256_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                            const uint8_t *p, size_t plen,
                            uint8_t *out, size_t *outlen) {
    size_t pad, total, full, i;
    uint8_t lastblk[16];

    if (!key || !iv || !out || !outlen) return YINT_ERR_INVAL;
    if (plen && !p)                       return YINT_ERR_INVAL;

    pad   = 16 - (plen % 16);  /* PKCS#7: full block when plen%16==0 */
    total = plen + pad;
    if (*outlen < total) { *outlen = total; return YINT_ERR_BUFTOOSMALL; }

    aes_dispatch_init();
    full = plen - (plen % 16);  /* full blocks of plaintext */
    if (full) {
        g_aes->cbc_encrypt(key, iv, p, full / 16, out);
    }
    /* assemble final block: tail bytes + padding */
    {
        size_t tail = plen - full;
        for (i = 0; i < tail; ++i) lastblk[i] = p[full + i];
        for (; i < 16; ++i)        lastblk[i] = (uint8_t)pad;
    }
    {
        const uint8_t *prev = full ? (out + full - 16) : iv;
        g_aes->cbc_encrypt(key, prev, lastblk, 1, out + full);
    }
    *outlen = total;
    return YINT_OK;
}

int yint_aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                            const uint8_t *c, size_t clen,
                            uint8_t *out, size_t *outlen) {
    size_t i;
    uint8_t pad;

    if (!key || !iv || !c || !out || !outlen)   return YINT_ERR_INVAL;
    if (clen == 0 || (clen % 16) != 0)          return YINT_ERR_FORMAT;
    if (*outlen < clen)                         return YINT_ERR_BUFTOOSMALL;

    aes_dispatch_init();
    g_aes->cbc_decrypt(key, iv, c, clen / 16, out);

    pad = out[clen - 1];
    if (pad == 0 || pad > 16) return YINT_ERR_PADDING;
    for (i = 0; i < pad; ++i) {
        if (out[clen - 1 - i] != pad) return YINT_ERR_PADDING;
    }
    *outlen = clen - pad;
    return YINT_OK;
}

/* ================================================================ */
/* CSPRNG                                                           */
/* ================================================================ */

#if defined(_WIN32)
/* RtlGenRandom (advapi32!SystemFunction036) -- works XP through 11. */
#  include <windows.h>
#  ifndef RTL_GENRANDOM_DECL
#    define RTL_GENRANDOM_DECL
typedef BOOLEAN (APIENTRY *RtlGenRandom_t)(PVOID, ULONG);
#  endif
static RtlGenRandom_t g_RtlGenRandom = NULL;

static int win_random_init(void) {
    HMODULE m = LoadLibraryA("advapi32.dll");
    if (!m) return -1;
    /* Cast through void(*)(void) to silence -Wcast-function-type while
     * still going through a recognised function-pointer path. */
    {
        FARPROC pf = GetProcAddress(m, "SystemFunction036");
        g_RtlGenRandom = (RtlGenRandom_t)(void (*)(void))pf;
    }
    return g_RtlGenRandom ? 0 : -1;
}

int yint_random(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    if (!buf && len) return YINT_ERR_INVAL;
    if (!g_RtlGenRandom && win_random_init() != 0) return YINT_ERR_RANDOM;
    while (len) {
        ULONG chunk = (len > 0x7fffffffu) ? 0x7fffffffu : (ULONG)len;
        if (!g_RtlGenRandom(p, chunk)) return YINT_ERR_RANDOM;
        p += chunk; len -= chunk;
    }
    return YINT_OK;
}
#elif defined(__APPLE__)
#  include <stdlib.h>  /* arc4random_buf */
int yint_random(void *buf, size_t len) {
    if (!buf && len) return YINT_ERR_INVAL;
    arc4random_buf(buf, len);
    return YINT_OK;
}
#else
/* Linux: try getrandom(2) once; fall back to /dev/urandom. */
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
#  include <sys/types.h>
#  if defined(__linux__)
#    include <sys/syscall.h>
#    ifndef SYS_getrandom
#      if defined(__x86_64__)
#        define SYS_getrandom 318
#      elif defined(__i386__)
#        define SYS_getrandom 355
#      elif defined(__aarch64__)
#        define SYS_getrandom 278
#      endif
#    endif
#  endif

static int try_getrandom(void *buf, size_t len) {
#if defined(__linux__) && defined(SYS_getrandom)
    long r;
    uint8_t *p = (uint8_t *)buf;
    while (len) {
        r = syscall(SYS_getrandom, p, len, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += r; len -= (size_t)r;
    }
    return 0;
#else
    (void)buf; (void)len;
    return -1;
#endif
}

int yint_random(void *buf, size_t len) {
    int fd;
    uint8_t *p;
    if (!buf && len) return YINT_ERR_INVAL;
    if (try_getrandom(buf, len) == 0) return YINT_OK;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return YINT_ERR_RANDOM;
    p = (uint8_t *)buf;
    while (len) {
        ssize_t r = read(fd, p, len);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return YINT_ERR_RANDOM; }
        if (r == 0) { close(fd); return YINT_ERR_RANDOM; }
        p += r; len -= (size_t)r;
    }
    close(fd);
    return YINT_OK;
}
#endif

/* ================================================================ */
/* hex / consttime                                                  */
/* ================================================================ */

void yint_hex_encode(const uint8_t *in, size_t n, char *out) {
    static const char *H = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; ++i) {
        out[2*i]   = H[(in[i] >> 4) & 0xf];
        out[2*i+1] = H[ in[i]       & 0xf];
    }
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

int yint_hex_decode(const char *in, size_t inlen, uint8_t *out) {
    size_t i;
    if (!in || (inlen & 1)) return YINT_ERR_FORMAT;
    if (inlen && !out) return YINT_ERR_INVAL;
    for (i = 0; i < inlen / 2; ++i) {
        int h = hex_nibble(in[2*i]);
        int l = hex_nibble(in[2*i+1]);
        if (h < 0 || l < 0) return YINT_ERR_FORMAT;
        out[i] = (uint8_t)((h << 4) | l);
    }
    return YINT_OK;
}

int yint_consttime_eq(const void *a, const void *b, size_t n) {
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; ++i) d |= (uint8_t)(x[i] ^ y[i]);
    return d == 0 ? 1 : 0;
}

/* ================================================================ */
/* Protocol layer                                                   */
/* ================================================================ */

void yint_derive_keys(const uint8_t *master, size_t mlen,
                      uint8_t k_enc[32], uint8_t k_mac[32]) {
    yint_hmac_sha256(master, mlen, (const uint8_t *)"yint/enc", 8, k_enc);
    yint_hmac_sha256(master, mlen, (const uint8_t *)"yint/mac", 8, k_mac);
}

int yint_build_body(const uint8_t k_enc[32], const uint8_t iv[16],
                    const uint8_t *plain, size_t plen,
                    uint8_t *body, size_t *body_len) {
    size_t pad, total, cap;
    int rc;

    if (!k_enc || !iv || !body || !body_len) return YINT_ERR_INVAL;
    if (plen && !plain)                      return YINT_ERR_INVAL;

    pad = 16 - (plen % 16);
    total = 16 + plen + pad;
    cap = *body_len;
    if (cap < total) { *body_len = total; return YINT_ERR_BUFTOOSMALL; }

    memcpy(body, iv, 16);
    {
        size_t clen = cap - 16;
        rc = yint_aes256_cbc_encrypt(k_enc, iv, plain, plen, body + 16, &clen);
        if (rc != YINT_OK) return rc;
        *body_len = 16 + clen;
    }
    return YINT_OK;
}

int yint_decrypt_body(const uint8_t k_enc[32],
                      const uint8_t *body, size_t body_len,
                      uint8_t *plain, size_t *plain_len) {
    size_t clen, plen;
    int rc;
    if (!k_enc || !body || !plain_len) return YINT_ERR_INVAL;
    if (body_len < 32 || (body_len % 16) != 0) return YINT_ERR_FORMAT;
    clen = body_len - 16;
    plen = *plain_len;
    if (plen < clen) { *plain_len = clen; return YINT_ERR_BUFTOOSMALL; }
    rc = yint_aes256_cbc_decrypt(k_enc, body, body + 16, clen, plain, &plen);
    if (rc != YINT_OK) return rc;
    *plain_len = plen;
    return YINT_OK;
}

static size_t s_or_strlen(const char *s, size_t given) {
    if (given == (size_t)-1) return strlen(s);
    return given;
}

static void hmac_lf(yint_hmac_ctx *c) {
    static const uint8_t lf = 0x0a;
    yint_hmac_update(c, &lf, 1);
}

int yint_sign_request(const uint8_t k_mac[32],
                      const char *method, size_t mlen,
                      const char *uri,    size_t ulen,
                      const char *ts,     size_t tlen,
                      const char *nonce_hex, size_t nlen,
                      const uint8_t *body, size_t body_len,
                      char out_hex[64]) {
    yint_hmac_ctx c;
    uint8_t mac[32];

    if (!k_mac || !method || !uri || !ts || !nonce_hex || !out_hex) return YINT_ERR_INVAL;
    if (body_len && !body) return YINT_ERR_INVAL;

    mlen = s_or_strlen(method, mlen);
    ulen = s_or_strlen(uri, ulen);
    tlen = s_or_strlen(ts, tlen);
    nlen = s_or_strlen(nonce_hex, nlen);

    yint_hmac_init(&c, k_mac, 32);
    yint_hmac_update(&c, (const uint8_t *)method, mlen); hmac_lf(&c);
    yint_hmac_update(&c, (const uint8_t *)uri,    ulen); hmac_lf(&c);
    yint_hmac_update(&c, (const uint8_t *)ts,     tlen); hmac_lf(&c);
    yint_hmac_update(&c, (const uint8_t *)nonce_hex, nlen); hmac_lf(&c);
    if (body_len) yint_hmac_update(&c, body, body_len);
    yint_hmac_final(&c, mac);
    yint_hex_encode(mac, 32, out_hex);
    return YINT_OK;
}

int yint_sign_response(const uint8_t k_mac[32],
                       const char *status,  size_t slen,
                       const char *resp_ts, size_t rtlen,
                       const char *resp_nonce_hex, size_t rnlen,
                       const char *req_nonce_hex,  size_t qnlen,
                       const uint8_t *body, size_t body_len,
                       char out_hex[64]) {
    yint_hmac_ctx c;
    uint8_t mac[32];

    if (!k_mac || !status || !resp_ts || !resp_nonce_hex || !req_nonce_hex || !out_hex)
        return YINT_ERR_INVAL;
    if (body_len && !body) return YINT_ERR_INVAL;

    slen  = s_or_strlen(status,          slen);
    rtlen = s_or_strlen(resp_ts,         rtlen);
    rnlen = s_or_strlen(resp_nonce_hex,  rnlen);
    qnlen = s_or_strlen(req_nonce_hex,   qnlen);

    yint_hmac_init(&c, k_mac, 32);
    yint_hmac_update(&c, (const uint8_t *)status,         slen);  hmac_lf(&c);
    yint_hmac_update(&c, (const uint8_t *)resp_ts,        rtlen); hmac_lf(&c);
    yint_hmac_update(&c, (const uint8_t *)resp_nonce_hex, rnlen); hmac_lf(&c);
    yint_hmac_update(&c, (const uint8_t *)req_nonce_hex,  qnlen); hmac_lf(&c);
    if (body_len) yint_hmac_update(&c, body, body_len);
    yint_hmac_final(&c, mac);
    yint_hex_encode(mac, 32, out_hex);
    return YINT_OK;
}

int yint_verify_request(const uint8_t k_mac[32],
                        const char *method, size_t mlen,
                        const char *uri,    size_t ulen,
                        const char *ts,     size_t tlen,
                        const char *nonce_hex, size_t nlen,
                        const uint8_t *body, size_t body_len,
                        const char *sign_hex, size_t sign_hex_len) {
    char expect[64];
    int rc;
    if (!sign_hex) return YINT_ERR_INVAL;
    if (sign_hex_len == (size_t)-1) sign_hex_len = strlen(sign_hex);
    if (sign_hex_len != 64) return YINT_ERR_FORMAT;
    rc = yint_sign_request(k_mac, method, mlen, uri, ulen, ts, tlen,
                           nonce_hex, nlen, body, body_len, expect);
    if (rc != YINT_OK) return rc;
    return yint_consttime_eq(expect, sign_hex, 64) ? YINT_OK : YINT_ERR_SIGN;
}

int yint_verify_response(const uint8_t k_mac[32],
                         const char *status,  size_t slen,
                         const char *resp_ts, size_t rtlen,
                         const char *resp_nonce_hex, size_t rnlen,
                         const char *req_nonce_hex,  size_t qnlen,
                         const uint8_t *body, size_t body_len,
                         const char *sign_hex, size_t sign_hex_len) {
    char expect[64];
    int rc;
    if (!sign_hex) return YINT_ERR_INVAL;
    if (sign_hex_len == (size_t)-1) sign_hex_len = strlen(sign_hex);
    if (sign_hex_len != 64) return YINT_ERR_FORMAT;
    rc = yint_sign_response(k_mac, status, slen, resp_ts, rtlen,
                            resp_nonce_hex, rnlen, req_nonce_hex, qnlen,
                            body, body_len, expect);
    if (rc != YINT_OK) return rc;
    return yint_consttime_eq(expect, sign_hex, 64) ? YINT_OK : YINT_ERR_SIGN;
}
