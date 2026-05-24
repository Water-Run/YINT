/*
 * yint-cli.c -- command-line driver for yint-core.
 *
 * All inputs and outputs are lowercase hex on stdin/stdout. Errors go
 * to stderr with a stable single-token tag, exit code 1.
 *
 * Subcommands:
 *   info
 *   random       <nbytes>
 *   sha256       <msg_hex>
 *   hmac         <key_hex> <msg_hex>
 *   derive       <master_hex>
 *   aes-enc      <key32_hex> <iv16_hex> <plain_hex>
 *   aes-dec      <key32_hex> <iv16_hex> <cipher_hex>
 *   build-body   <kenc_hex> <iv_hex> <plain_hex>
 *   decrypt-body <kenc_hex> <body_hex>
 *   sign-req     <kmac_hex> <method> <uri> <ts> <nonce_hex> <body_hex>
 *   sign-resp    <kmac_hex> <status> <resp_ts> <resp_nonce_hex> <req_nonce_hex> <body_hex>
 *   verify-req   <kmac_hex> <method> <uri> <ts> <nonce_hex> <sign_hex> <body_hex>
 *   verify-resp  <kmac_hex> <status> <resp_ts> <resp_nonce_hex> <req_nonce_hex> <sign_hex> <body_hex>
 *
 * A "-" placed in any *_hex argument reads the hex value from stdin.
 */

#include "yint-core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <io.h>
#  include <fcntl.h>
#endif

static int die(const char *tag) {
    fprintf(stderr, "%s\n", tag);
    return 1;
}

/* Read all of stdin into a heap buffer (caller frees). */
static char *slurp_stdin(size_t *len) {
    size_t cap = 4096, n = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        size_t got;
        if (n == cap) {
            cap *= 2;
            { char *nb = (char *)realloc(buf, cap); if (!nb) { free(buf); return NULL; } buf = nb; }
        }
        got = fread(buf + n, 1, cap - n, stdin);
        n += got;
        if (got == 0) break;
    }
    /* trim trailing whitespace */
    while (n && (buf[n-1] == '\n' || buf[n-1] == '\r' || buf[n-1] == ' ' || buf[n-1] == '\t'))
        --n;
    *len = n;
    return buf;
}

/* Resolve a possibly "-" argument to a hex source.
 * Returns a malloc'd, NUL-terminated string in *out_hex (caller frees if owned).
 * If owned == 0, *out_hex is not heap-allocated and must not be freed. */
static int resolve_hex_arg(const char *arg, char **out_hex,
                           size_t *out_len, int *owned) {
    if (!arg) return YINT_ERR_INVAL;
    if (strcmp(arg, "-") == 0) {
        size_t n;
        char *s = slurp_stdin(&n);
        if (!s) return YINT_ERR_INTERNAL;
        *out_hex = s;
        *out_len = n;
        *owned = 1;
        return YINT_OK;
    }
    *out_hex = (char *)arg;
    *out_len = strlen(arg);
    *owned = 0;
    return YINT_OK;
}

/* Decode an *_hex argument (allowing "-") into a heap buffer. */
static int decode_hex_arg(const char *arg, uint8_t **out, size_t *out_len) {
    char *src = NULL; size_t slen = 0; int owned = 0;
    int rc = resolve_hex_arg(arg, &src, &slen, &owned);
    uint8_t *buf;
    if (rc != YINT_OK) return rc;
    if (slen & 1) { if (owned) free(src); return YINT_ERR_FORMAT; }
    buf = (uint8_t *)malloc(slen / 2 + 1);
    if (!buf) { if (owned) free(src); return YINT_ERR_INTERNAL; }
    rc = yint_hex_decode(src, slen, buf);
    if (rc != YINT_OK) { free(buf); if (owned) free(src); return rc; }
    *out = buf;
    *out_len = slen / 2;
    if (owned) free(src);
    return YINT_OK;
}

/* Print a hex blob and a trailing LF. */
static void print_hex_line(const uint8_t *b, size_t n) {
    static const char H[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; ++i) {
        putchar(H[(b[i] >> 4) & 0xf]);
        putchar(H[ b[i]       & 0xf]);
    }
    putchar('\n');
}

static int cmd_info(void) {
    printf("yint-core %s backend=%s\n", yint_version(), yint_backend());
    return 0;
}

static int cmd_random(int argc, char **argv) {
    long n;
    uint8_t *buf;
    if (argc != 1) return die("ERR_USAGE");
    n = strtol(argv[0], NULL, 10);
    if (n < 0 || n > (1 << 20)) return die("ERR_FORMAT");
    if (n == 0) { putchar('\n'); return 0; }
    buf = (uint8_t *)malloc((size_t)n);
    if (!buf) return die("ERR_INTERNAL");
    if (yint_random(buf, (size_t)n) != YINT_OK) { free(buf); return die("ERR_RANDOM"); }
    print_hex_line(buf, (size_t)n);
    free(buf);
    return 0;
}

static int cmd_sha256(int argc, char **argv) {
    uint8_t *m = NULL; size_t mlen = 0;
    uint8_t out[32];
    if (argc != 1) return die("ERR_USAGE");
    if (decode_hex_arg(argv[0], &m, &mlen) != YINT_OK) return die("ERR_FORMAT");
    yint_sha256(m, mlen, out);
    print_hex_line(out, 32);
    free(m);
    return 0;
}

static int cmd_hmac(int argc, char **argv) {
    uint8_t *k = NULL, *m = NULL; size_t klen = 0, mlen = 0;
    uint8_t out[32];
    int rc;
    if (argc != 2) return die("ERR_USAGE");
    if (decode_hex_arg(argv[0], &k, &klen) != YINT_OK) return die("ERR_FORMAT");
    if (decode_hex_arg(argv[1], &m, &mlen) != YINT_OK) { free(k); return die("ERR_FORMAT"); }
    yint_hmac_sha256(k, klen, m, mlen, out);
    print_hex_line(out, 32);
    free(k); free(m); (void)rc;
    return 0;
}

static int cmd_derive(int argc, char **argv) {
    uint8_t *master = NULL; size_t mlen = 0;
    uint8_t k_enc[32], k_mac[32];
    char hex_enc[64], hex_mac[64];
    if (argc != 1) return die("ERR_USAGE");
    if (decode_hex_arg(argv[0], &master, &mlen) != YINT_OK) return die("ERR_FORMAT");
    yint_derive_keys(master, mlen, k_enc, k_mac);
    yint_hex_encode(k_enc, 32, hex_enc);
    yint_hex_encode(k_mac, 32, hex_mac);
    fwrite(hex_enc, 1, 64, stdout); putchar(' ');
    fwrite(hex_mac, 1, 64, stdout); putchar('\n');
    free(master);
    return 0;
}

static int cmd_aes_enc(int argc, char **argv) {
    uint8_t *key = NULL, *iv = NULL, *p = NULL;
    size_t klen = 0, ivlen = 0, plen = 0;
    uint8_t *out = NULL;
    size_t outlen, cap;
    int rc;
    if (argc != 3) return die("ERR_USAGE");
    if (decode_hex_arg(argv[0], &key, &klen) != YINT_OK) return die("ERR_FORMAT");
    if (decode_hex_arg(argv[1], &iv,  &ivlen) != YINT_OK) { free(key); return die("ERR_FORMAT"); }
    if (decode_hex_arg(argv[2], &p,   &plen)  != YINT_OK) { free(key); free(iv); return die("ERR_FORMAT"); }
    if (klen != 32 || ivlen != 16) { free(key); free(iv); free(p); return die("ERR_FORMAT"); }
    cap = plen + 16; out = (uint8_t *)malloc(cap); outlen = cap;
    rc = yint_aes256_cbc_encrypt(key, iv, p, plen, out, &outlen);
    if (rc != YINT_OK) { free(key); free(iv); free(p); free(out); return die("ERR_INTERNAL"); }
    print_hex_line(out, outlen);
    free(key); free(iv); free(p); free(out);
    return 0;
}

static int cmd_aes_dec(int argc, char **argv) {
    uint8_t *key = NULL, *iv = NULL, *c = NULL;
    size_t klen = 0, ivlen = 0, clen = 0;
    uint8_t *out = NULL;
    size_t outlen, cap;
    int rc;
    if (argc != 3) return die("ERR_USAGE");
    if (decode_hex_arg(argv[0], &key, &klen) != YINT_OK) return die("ERR_FORMAT");
    if (decode_hex_arg(argv[1], &iv,  &ivlen) != YINT_OK) { free(key); return die("ERR_FORMAT"); }
    if (decode_hex_arg(argv[2], &c,   &clen)  != YINT_OK) { free(key); free(iv); return die("ERR_FORMAT"); }
    if (klen != 32 || ivlen != 16 || clen == 0 || (clen % 16)) {
        free(key); free(iv); free(c); return die("ERR_FORMAT");
    }
    cap = clen; out = (uint8_t *)malloc(cap ? cap : 1); outlen = cap;
    rc = yint_aes256_cbc_decrypt(key, iv, c, clen, out, &outlen);
    if (rc != YINT_OK) {
        free(key); free(iv); free(c); free(out);
        return die(rc == YINT_ERR_PADDING ? "ERR_PADDING" : "ERR_INTERNAL");
    }
    print_hex_line(out, outlen);
    free(key); free(iv); free(c); free(out);
    return 0;
}

static int cmd_build_body(int argc, char **argv) {
    uint8_t *kenc = NULL, *iv = NULL, *p = NULL;
    size_t kl = 0, il = 0, pl = 0;
    uint8_t *body; size_t bl, cap;
    int rc;
    if (argc != 3) return die("ERR_USAGE");
    if (decode_hex_arg(argv[0], &kenc, &kl) != YINT_OK) return die("ERR_FORMAT");
    if (decode_hex_arg(argv[1], &iv, &il) != YINT_OK) { free(kenc); return die("ERR_FORMAT"); }
    if (decode_hex_arg(argv[2], &p, &pl) != YINT_OK) { free(kenc); free(iv); return die("ERR_FORMAT"); }
    if (kl != 32 || il != 16) { free(kenc); free(iv); free(p); return die("ERR_FORMAT"); }
    cap = 16 + pl + 16; body = (uint8_t *)malloc(cap); bl = cap;
    rc = yint_build_body(kenc, iv, p, pl, body, &bl);
    if (rc != YINT_OK) { free(kenc); free(iv); free(p); free(body); return die("ERR_INTERNAL"); }
    print_hex_line(body, bl);
    free(kenc); free(iv); free(p); free(body);
    return 0;
}

static int cmd_decrypt_body(int argc, char **argv) {
    uint8_t *kenc = NULL, *body = NULL;
    size_t kl = 0, bl = 0;
    uint8_t *out; size_t ol, cap;
    int rc;
    if (argc != 2) return die("ERR_USAGE");
    if (decode_hex_arg(argv[0], &kenc, &kl) != YINT_OK) return die("ERR_FORMAT");
    if (decode_hex_arg(argv[1], &body, &bl) != YINT_OK) { free(kenc); return die("ERR_FORMAT"); }
    if (kl != 32 || bl < 32 || (bl % 16)) {
        free(kenc); free(body); return die("ERR_FORMAT");
    }
    cap = bl - 16; out = (uint8_t *)malloc(cap ? cap : 1); ol = cap;
    rc = yint_decrypt_body(kenc, body, bl, out, &ol);
    if (rc != YINT_OK) {
        free(kenc); free(body); free(out);
        return die(rc == YINT_ERR_PADDING ? "ERR_PADDING" : "ERR_INTERNAL");
    }
    print_hex_line(out, ol);
    free(kenc); free(body); free(out);
    return 0;
}

static int cmd_sign_req(int argc, char **argv) {
    uint8_t *kmac = NULL, *body = NULL;
    size_t kl = 0, bl = 0;
    char sig[64];
    int rc;
    if (argc != 6) return die("ERR_USAGE");
    if (decode_hex_arg(argv[0], &kmac, &kl) != YINT_OK) return die("ERR_FORMAT");
    if (decode_hex_arg(argv[5], &body, &bl) != YINT_OK) { free(kmac); return die("ERR_FORMAT"); }
    if (kl != 32) { free(kmac); free(body); return die("ERR_FORMAT"); }
    rc = yint_sign_request(kmac,
                           argv[1], (size_t)-1,
                           argv[2], (size_t)-1,
                           argv[3], (size_t)-1,
                           argv[4], (size_t)-1,
                           body, bl, sig);
    if (rc != YINT_OK) { free(kmac); free(body); return die("ERR_INTERNAL"); }
    fwrite(sig, 1, 64, stdout); putchar('\n');
    free(kmac); free(body);
    return 0;
}

static int cmd_sign_resp(int argc, char **argv) {
    uint8_t *kmac = NULL, *body = NULL;
    size_t kl = 0, bl = 0;
    char sig[64];
    int rc;
    if (argc != 6) return die("ERR_USAGE");
    if (decode_hex_arg(argv[0], &kmac, &kl) != YINT_OK) return die("ERR_FORMAT");
    if (decode_hex_arg(argv[5], &body, &bl) != YINT_OK) { free(kmac); return die("ERR_FORMAT"); }
    if (kl != 32) { free(kmac); free(body); return die("ERR_FORMAT"); }
    rc = yint_sign_response(kmac,
                            argv[1], (size_t)-1,
                            argv[2], (size_t)-1,
                            argv[3], (size_t)-1,
                            argv[4], (size_t)-1,
                            body, bl, sig);
    if (rc != YINT_OK) { free(kmac); free(body); return die("ERR_INTERNAL"); }
    fwrite(sig, 1, 64, stdout); putchar('\n');
    free(kmac); free(body);
    return 0;
}

static int cmd_verify_req(int argc, char **argv) {
    uint8_t *kmac = NULL, *body = NULL;
    size_t kl = 0, bl = 0;
    int rc;
    if (argc != 7) return die("ERR_USAGE");
    if (decode_hex_arg(argv[0], &kmac, &kl) != YINT_OK) return die("ERR_FORMAT");
    if (decode_hex_arg(argv[6], &body, &bl) != YINT_OK) { free(kmac); return die("ERR_FORMAT"); }
    if (kl != 32) { free(kmac); free(body); return die("ERR_FORMAT"); }
    rc = yint_verify_request(kmac,
                             argv[1], (size_t)-1,
                             argv[2], (size_t)-1,
                             argv[3], (size_t)-1,
                             argv[4], (size_t)-1,
                             body, bl,
                             argv[5], (size_t)-1);
    free(kmac); free(body);
    if (rc == YINT_OK) { puts("OK"); return 0; }
    return die(rc == YINT_ERR_FORMAT ? "ERR_FORMAT" : "ERR_SIGN");
}

static int cmd_verify_resp(int argc, char **argv) {
    uint8_t *kmac = NULL, *body = NULL;
    size_t kl = 0, bl = 0;
    int rc;
    if (argc != 7) return die("ERR_USAGE");
    if (decode_hex_arg(argv[0], &kmac, &kl) != YINT_OK) return die("ERR_FORMAT");
    if (decode_hex_arg(argv[6], &body, &bl) != YINT_OK) { free(kmac); return die("ERR_FORMAT"); }
    if (kl != 32) { free(kmac); free(body); return die("ERR_FORMAT"); }
    rc = yint_verify_response(kmac,
                              argv[1], (size_t)-1,
                              argv[2], (size_t)-1,
                              argv[3], (size_t)-1,
                              argv[4], (size_t)-1,
                              body, bl,
                              argv[5], (size_t)-1);
    free(kmac); free(body);
    if (rc == YINT_OK) { puts("OK"); return 0; }
    return die(rc == YINT_ERR_FORMAT ? "ERR_FORMAT" : "ERR_SIGN");
}

static int usage(void) {
    fputs(
"yint-core CLI -- see README.md.\n"
"Usage: yint <subcommand> [args ...]\n"
"  info\n"
"  random       <nbytes>\n"
"  sha256       <msg_hex>\n"
"  hmac         <key_hex> <msg_hex>\n"
"  derive       <master_hex>\n"
"  aes-enc      <key32_hex> <iv16_hex> <plain_hex>\n"
"  aes-dec      <key32_hex> <iv16_hex> <cipher_hex>\n"
"  build-body   <kenc_hex> <iv16_hex> <plain_hex>\n"
"  decrypt-body <kenc_hex> <body_hex>\n"
"  sign-req     <kmac_hex> <method> <uri> <ts> <nonce_hex> <body_hex>\n"
"  sign-resp    <kmac_hex> <status> <resp_ts> <resp_nonce_hex> <req_nonce_hex> <body_hex>\n"
"  verify-req   <kmac_hex> <method> <uri> <ts> <nonce_hex> <sign_hex> <body_hex>\n"
"  verify-resp  <kmac_hex> <status> <resp_ts> <resp_nonce_hex> <req_nonce_hex> <sign_hex> <body_hex>\n"
"Any *_hex argument may be \"-\" to read from stdin.\n",
    stderr);
    return 1;
}

int main(int argc, char **argv) {
    const char *cmd;

#if defined(_WIN32)
    /* avoid CRLF translation on stdout */
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stdin),  _O_BINARY);
#endif

    if (argc < 2) return usage();
    cmd = argv[1];

    if      (!strcmp(cmd, "info"))         return cmd_info();
    else if (!strcmp(cmd, "random"))       return cmd_random(argc - 2, argv + 2);
    else if (!strcmp(cmd, "sha256"))       return cmd_sha256(argc - 2, argv + 2);
    else if (!strcmp(cmd, "hmac"))         return cmd_hmac(argc - 2, argv + 2);
    else if (!strcmp(cmd, "derive"))       return cmd_derive(argc - 2, argv + 2);
    else if (!strcmp(cmd, "aes-enc"))      return cmd_aes_enc(argc - 2, argv + 2);
    else if (!strcmp(cmd, "aes-dec"))      return cmd_aes_dec(argc - 2, argv + 2);
    else if (!strcmp(cmd, "build-body"))   return cmd_build_body(argc - 2, argv + 2);
    else if (!strcmp(cmd, "decrypt-body")) return cmd_decrypt_body(argc - 2, argv + 2);
    else if (!strcmp(cmd, "sign-req"))     return cmd_sign_req(argc - 2, argv + 2);
    else if (!strcmp(cmd, "sign-resp"))    return cmd_sign_resp(argc - 2, argv + 2);
    else if (!strcmp(cmd, "verify-req"))   return cmd_verify_req(argc - 2, argv + 2);
    else if (!strcmp(cmd, "verify-resp"))  return cmd_verify_resp(argc - 2, argv + 2);
    return usage();
}
