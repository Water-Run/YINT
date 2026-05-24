/*
 * yint-core.h -- yint protocol portable C core (public API).
 *
 * This header is the binary-stable surface of the yint reference core.
 * It exposes the byte-level primitives (SHA-256 / HMAC-SHA256 /
 * AES-256-CBC with PKCS#7 / CSPRNG / hex / constant-time compare) and
 * the protocol-level helpers (key derivation, body construction,
 * request and response signing) defined by Protocol.md.
 *
 * Targets: C99. Built and tested on Linux 7+, macOS 26 and Windows
 * XP through 11 (MinGW-w64 i686 / x86_64; MSVC).
 */

#ifndef YINT_CORE_H
#define YINT_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(YINT_DLL)
#  ifdef YINT_BUILDING
#    define YINT_API __declspec(dllexport)
#  else
#    define YINT_API __declspec(dllimport)
#  endif
#else
#  define YINT_API
#endif

/* ---------------------------------------------------------------- */
/* Error codes. 0 == success.                                       */
/* ---------------------------------------------------------------- */
#define YINT_OK              0
#define YINT_ERR_INVAL      -1   /* NULL pointer or bogus length */
#define YINT_ERR_BUFTOOSMALL -2  /* output buffer too small */
#define YINT_ERR_FORMAT     -3   /* hex / numeric format */
#define YINT_ERR_TIMESTAMP  -4   /* reserved (validation lives in lib) */
#define YINT_ERR_NONCE      -5   /* reserved */
#define YINT_ERR_SIGN       -6   /* HMAC mismatch */
#define YINT_ERR_PADDING    -7   /* PKCS#7 invalid */
#define YINT_ERR_RANDOM     -8   /* CSPRNG failure */
#define YINT_ERR_INTERNAL   -9

/* Constant sizes. */
#define YINT_SHA256_LEN  32
#define YINT_HMAC_LEN    32
#define YINT_AES_KEY_LEN 32
#define YINT_AES_IV_LEN  16
#define YINT_AES_BLK_LEN 16
#define YINT_NONCE_LEN   16   /* raw bytes; hex form is 32 chars */
#define YINT_NONCE_HEX   32
#define YINT_SIGN_HEX    64

/* ---------------------------------------------------------------- */
/* Library meta                                                     */
/* ---------------------------------------------------------------- */
YINT_API const char *yint_version(void);   /* "1.0.0" */
YINT_API const char *yint_backend(void);   /* "aesni" or "ttable" */

/* ---------------------------------------------------------------- */
/* Hash / MAC                                                       */
/* ---------------------------------------------------------------- */
YINT_API void yint_sha256(const uint8_t *msg, size_t mlen,
                          uint8_t out[32]);

YINT_API void yint_hmac_sha256(const uint8_t *key, size_t klen,
                               const uint8_t *msg, size_t mlen,
                               uint8_t out[32]);

/* Streaming HMAC (used internally for StringToSign assembly,
 * also exposed for advanced callers). */
typedef struct yint_hmac_ctx_s {
    uint32_t h[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   buflen;
    uint8_t  okey[64];
    int      have_okey;
} yint_hmac_ctx;

YINT_API void yint_hmac_init   (yint_hmac_ctx *c,
                                const uint8_t *key, size_t klen);
YINT_API void yint_hmac_update (yint_hmac_ctx *c,
                                const uint8_t *data, size_t dlen);
YINT_API void yint_hmac_final  (yint_hmac_ctx *c, uint8_t out[32]);

/* ---------------------------------------------------------------- */
/* AES-256-CBC + PKCS#7                                             */
/* ---------------------------------------------------------------- */

/* On entry *outlen is the size of the out buffer (must be at least
 * ((plen / 16) + 1) * 16). On success *outlen is set to the produced
 * ciphertext length. */
YINT_API int yint_aes256_cbc_encrypt(const uint8_t key[32],
                                     const uint8_t iv[16],
                                     const uint8_t *p, size_t plen,
                                     uint8_t *out, size_t *outlen);

/* On entry *outlen is the size of the out buffer (>= clen). On
 * success *outlen is set to the plaintext length (after stripping
 * PKCS#7). Returns YINT_ERR_PADDING if the padding is invalid. */
YINT_API int yint_aes256_cbc_decrypt(const uint8_t key[32],
                                     const uint8_t iv[16],
                                     const uint8_t *c, size_t clen,
                                     uint8_t *out, size_t *outlen);

/* ---------------------------------------------------------------- */
/* CSPRNG / hex / consttime                                         */
/* ---------------------------------------------------------------- */
YINT_API int  yint_random(void *buf, size_t len);

/* Returns 1 if equal, 0 otherwise. Constant-time over the prefix. */
YINT_API int  yint_consttime_eq(const void *a, const void *b, size_t n);

/* Writes 2*n lowercase ASCII bytes (NO nul terminator). */
YINT_API void yint_hex_encode(const uint8_t *in, size_t n, char *out);

/* Decodes 2*n lowercase or uppercase hex bytes. Returns YINT_OK or
 * YINT_ERR_FORMAT. */
YINT_API int  yint_hex_decode(const char *in, size_t inlen,
                              uint8_t *out);

/* ---------------------------------------------------------------- */
/* Protocol layer                                                   */
/* ---------------------------------------------------------------- */

/* K_enc = HMAC(master, "yint/enc"); K_mac = HMAC(master, "yint/mac"). */
YINT_API void yint_derive_keys(const uint8_t *master, size_t mlen,
                               uint8_t k_enc[32], uint8_t k_mac[32]);

/* Build BODY = IV || AES-CBC(K_enc, IV, plain).
 * On entry *body_len = capacity of body. On success *body_len is the
 * produced length (always 16 + ceil_to_16(plen + 1) bytes). */
YINT_API int yint_build_body(const uint8_t k_enc[32],
                             const uint8_t iv[16],
                             const uint8_t *plain, size_t plen,
                             uint8_t *body, size_t *body_len);

/* Decrypt BODY = IV || C, recovering plaintext. body_len must be
 * >= 32 and a multiple of 16. */
YINT_API int yint_decrypt_body(const uint8_t k_enc[32],
                               const uint8_t *body, size_t body_len,
                               uint8_t *plain, size_t *plain_len);

/* Compute SIGN = hex(HMAC(K_mac, S_req)).
 * Strings are taken byte-for-byte as defined by Protocol.md. The
 * caller passes either explicit lengths or -1/SIZE_MAX to use strlen.
 *
 * out_hex must be a buffer of at least 64 bytes. NO nul terminator
 * is written.
 */
YINT_API int yint_sign_request(const uint8_t k_mac[32],
                               const char *method, size_t method_len,
                               const char *uri,    size_t uri_len,
                               const char *ts,     size_t ts_len,
                               const char *nonce_hex, size_t nonce_hex_len,
                               const uint8_t *body, size_t body_len,
                               char out_hex[64]);

YINT_API int yint_sign_response(const uint8_t k_mac[32],
                                const char *status,  size_t status_len,
                                const char *resp_ts, size_t resp_ts_len,
                                const char *resp_nonce_hex, size_t resp_nonce_hex_len,
                                const char *req_nonce_hex,  size_t req_nonce_hex_len,
                                const uint8_t *body, size_t body_len,
                                char out_hex[64]);

/* Verifying variants: recompute and constant-time compare against
 * the supplied hex signature. Returns YINT_OK on match,
 * YINT_ERR_SIGN on mismatch, YINT_ERR_FORMAT on bad hex. */
YINT_API int yint_verify_request(const uint8_t k_mac[32],
                                 const char *method, size_t method_len,
                                 const char *uri,    size_t uri_len,
                                 const char *ts,     size_t ts_len,
                                 const char *nonce_hex, size_t nonce_hex_len,
                                 const uint8_t *body, size_t body_len,
                                 const char *sign_hex, size_t sign_hex_len);

YINT_API int yint_verify_response(const uint8_t k_mac[32],
                                  const char *status,  size_t status_len,
                                  const char *resp_ts, size_t resp_ts_len,
                                  const char *resp_nonce_hex, size_t resp_nonce_hex_len,
                                  const char *req_nonce_hex,  size_t req_nonce_hex_len,
                                  const uint8_t *body, size_t body_len,
                                  const char *sign_hex, size_t sign_hex_len);

/* ---------------------------------------------------------------- */
/* AES backend hooks (used by yint-aesni.c at startup).             */
/* Not part of the stable public API; CLI/lib code should not call. */
/* ---------------------------------------------------------------- */
typedef void (*yint_aes_cbc_fn)(const uint8_t key[32],
                                const uint8_t iv[16],
                                const uint8_t *in, size_t blocks,
                                uint8_t *out);

typedef struct yint_aes_backend_s {
    const char     *name;
    yint_aes_cbc_fn cbc_encrypt; /* whole multiple of 16 bytes only */
    yint_aes_cbc_fn cbc_decrypt;
} yint_aes_backend;

/* Internal: install the AES-NI backend if cpuid says it's safe.
 * Called once at first use. Implemented in yint-aesni.c. */
void yint_aesni_maybe_install(void);

/* Internal hook used by the dispatch initialiser. */
void yint__set_aes_backend(const yint_aes_backend *b);

#ifdef __cplusplus
}
#endif

#endif /* YINT_CORE_H */
