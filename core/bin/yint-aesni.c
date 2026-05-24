/*
 * yint-aesni.c -- AES-NI backend for yint-core, x86/x86_64 only.
 *
 * Built only when targeting x86/x86_64. Detects CPU support at startup
 * (cpuid leaf 1, ECX bits 25 (AES) and 19 (SSE4.1)) and installs a
 * faster AES-256-CBC implementation via yint__set_aes_backend().
 *
 * On CPUs without AES-NI this file is harmless: yint_aesni_maybe_install
 * returns without touching the dispatch table, and the soft backend
 * remains active. The intrinsics in this TU are only ever executed
 * after a positive cpuid check, so older CPUs cannot trip an illegal
 * instruction.
 */

#include "yint-core.h"

#if (defined(__i386__) || defined(__x86_64__) || \
     defined(_M_IX86) || defined(_M_X64)) && !defined(YINT_NO_AESNI)

#include <string.h>
#include <stdint.h>

#if defined(_MSC_VER)
#  include <intrin.h>
#  include <wmmintrin.h>
#  include <smmintrin.h>
#else
#  include <wmmintrin.h>
#  include <smmintrin.h>
#  include <cpuid.h>
#endif

/* ---------------- cpuid ---------------- */

static int cpu_has_aesni_sse41(void) {
#if defined(_MSC_VER)
    int regs[4];
    __cpuid(regs, 0);
    if (regs[0] < 1) return 0;
    __cpuid(regs, 1);
    /* ECX bit 25 = AES, bit 19 = SSE4.1 */
    return ((regs[2] & (1u << 25)) && (regs[2] & (1u << 19))) ? 1 : 0;
#else
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return 0;
    return ((ecx & (1u << 25)) && (ecx & (1u << 19))) ? 1 : 0;
#endif
}

/* ---------------- AES-256 key schedule via AES-NI ---------------- */

static __m128i aes256_assist1(__m128i a, __m128i b) {
    __m128i t;
    b = _mm_shuffle_epi32(b, 0xff);
    t = _mm_slli_si128(a, 0x4); a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 0x4); a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 0x4); a = _mm_xor_si128(a, t);
    a = _mm_xor_si128(a, b);
    return a;
}

static __m128i aes256_assist2(__m128i a, __m128i c) {
    __m128i b, t;
    b = _mm_aeskeygenassist_si128(c, 0x0);
    b = _mm_shuffle_epi32(b, 0xaa);
    t = _mm_slli_si128(a, 0x4); a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 0x4); a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 0x4); a = _mm_xor_si128(a, t);
    a = _mm_xor_si128(a, b);
    return a;
}

static void aesni_expand256(const uint8_t key[32], __m128i rk[15]) {
    __m128i k1, k2, t;
    k1 = _mm_loadu_si128((const __m128i *)(key));
    k2 = _mm_loadu_si128((const __m128i *)(key + 16));
    rk[0] = k1; rk[1] = k2;

    t = _mm_aeskeygenassist_si128(k2, 0x01); k1 = aes256_assist1(k1, t); rk[2]  = k1;
    k2 = aes256_assist2(k2, k1);                                          rk[3]  = k2;
    t = _mm_aeskeygenassist_si128(k2, 0x02); k1 = aes256_assist1(k1, t); rk[4]  = k1;
    k2 = aes256_assist2(k2, k1);                                          rk[5]  = k2;
    t = _mm_aeskeygenassist_si128(k2, 0x04); k1 = aes256_assist1(k1, t); rk[6]  = k1;
    k2 = aes256_assist2(k2, k1);                                          rk[7]  = k2;
    t = _mm_aeskeygenassist_si128(k2, 0x08); k1 = aes256_assist1(k1, t); rk[8]  = k1;
    k2 = aes256_assist2(k2, k1);                                          rk[9]  = k2;
    t = _mm_aeskeygenassist_si128(k2, 0x10); k1 = aes256_assist1(k1, t); rk[10] = k1;
    k2 = aes256_assist2(k2, k1);                                          rk[11] = k2;
    t = _mm_aeskeygenassist_si128(k2, 0x20); k1 = aes256_assist1(k1, t); rk[12] = k1;
    k2 = aes256_assist2(k2, k1);                                          rk[13] = k2;
    t = _mm_aeskeygenassist_si128(k2, 0x40); k1 = aes256_assist1(k1, t); rk[14] = k1;
}

static void invert_for_decrypt(const __m128i rk[15], __m128i drk[15]) {
    int i;
    drk[0]  = rk[14];
    for (i = 1; i < 14; ++i) drk[i] = _mm_aesimc_si128(rk[14 - i]);
    drk[14] = rk[0];
}

/* ---------------- CBC encrypt / decrypt ---------------- */

static void aesni_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16],
                              const uint8_t *in, size_t blocks, uint8_t *out) {
    __m128i rk[15];
    __m128i prev;
    size_t i;
    aesni_expand256(key, rk);
    prev = _mm_loadu_si128((const __m128i *)iv);
    for (i = 0; i < blocks; ++i) {
        __m128i s = _mm_loadu_si128((const __m128i *)(in + 16 * i));
        s = _mm_xor_si128(s, prev);
        s = _mm_xor_si128(s, rk[0]);
        s = _mm_aesenc_si128(s, rk[1]);
        s = _mm_aesenc_si128(s, rk[2]);
        s = _mm_aesenc_si128(s, rk[3]);
        s = _mm_aesenc_si128(s, rk[4]);
        s = _mm_aesenc_si128(s, rk[5]);
        s = _mm_aesenc_si128(s, rk[6]);
        s = _mm_aesenc_si128(s, rk[7]);
        s = _mm_aesenc_si128(s, rk[8]);
        s = _mm_aesenc_si128(s, rk[9]);
        s = _mm_aesenc_si128(s, rk[10]);
        s = _mm_aesenc_si128(s, rk[11]);
        s = _mm_aesenc_si128(s, rk[12]);
        s = _mm_aesenc_si128(s, rk[13]);
        s = _mm_aesenclast_si128(s, rk[14]);
        _mm_storeu_si128((__m128i *)(out + 16 * i), s);
        prev = s;
    }
}

static void aesni_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                              const uint8_t *in, size_t blocks, uint8_t *out) {
    __m128i rk[15], drk[15];
    __m128i prev;
    size_t i;
    aesni_expand256(key, rk);
    invert_for_decrypt(rk, drk);
    prev = _mm_loadu_si128((const __m128i *)iv);
    for (i = 0; i < blocks; ++i) {
        __m128i c = _mm_loadu_si128((const __m128i *)(in + 16 * i));
        __m128i s = _mm_xor_si128(c, drk[0]);
        s = _mm_aesdec_si128(s, drk[1]);
        s = _mm_aesdec_si128(s, drk[2]);
        s = _mm_aesdec_si128(s, drk[3]);
        s = _mm_aesdec_si128(s, drk[4]);
        s = _mm_aesdec_si128(s, drk[5]);
        s = _mm_aesdec_si128(s, drk[6]);
        s = _mm_aesdec_si128(s, drk[7]);
        s = _mm_aesdec_si128(s, drk[8]);
        s = _mm_aesdec_si128(s, drk[9]);
        s = _mm_aesdec_si128(s, drk[10]);
        s = _mm_aesdec_si128(s, drk[11]);
        s = _mm_aesdec_si128(s, drk[12]);
        s = _mm_aesdec_si128(s, drk[13]);
        s = _mm_aesdeclast_si128(s, drk[14]);
        s = _mm_xor_si128(s, prev);
        _mm_storeu_si128((__m128i *)(out + 16 * i), s);
        prev = c;
    }
}

static const yint_aes_backend g_aesni_backend = {
    "aesni",
    aesni_cbc_encrypt,
    aesni_cbc_decrypt
};

void yint_aesni_maybe_install(void) {
    if (cpu_has_aesni_sse41()) {
        yint__set_aes_backend(&g_aesni_backend);
    }
}

#endif /* x86 */
