#define _POSIX_C_SOURCE 200809L
/* NEITH-ACE crypto shim for the F' capture adapter.
   Byte-compatible with neith_ace.py: same enc(), same keyed Ascon-CXOF128 MAC,
   same SHAKE128 digest, same XMSS. Validated against the Python reference. */
#include "neith_shim.h"
#include <stdlib.h>
#include <string.h>

/* ---- from the vendored native code (link libasconcxof_ref, libxmss / fips202) ---- */
int crypto_cxof(unsigned char* out, unsigned long long outlen,
                const unsigned char* in, unsigned long long inlen,
                const unsigned char* cs, unsigned long long cslen);
void shake128(unsigned char* out, unsigned long long outlen,
              const unsigned char* in, unsigned long long inlen);
int xw_init(const char* name, unsigned long long* pkb, unsigned long long* skb, unsigned long long* sigb);

/* ---- growable byte buffer ---- */
typedef struct { unsigned char* p; size_t n, cap; } buf_t;
static void bput(buf_t* b, const void* d, size_t n) {
    if (b->n + n > b->cap) { b->cap = (b->n + n) * 2 + 64; b->p = (unsigned char*)realloc(b->p, b->cap); }
    memcpy(b->p + b->n, d, n); b->n += n;
}
static void bu32(buf_t* b, unsigned int v) { unsigned char t[4] = { v>>24, v>>16, v>>8, v }; bput(b, t, 4); }
static void bi64(buf_t* b, long long v) {
    unsigned long long u = (unsigned long long)v;
    unsigned char t[8] = { u>>56,u>>48,u>>40,u>>32,u>>24,u>>16,u>>8,u }; bput(b, t, 8);
}
/* enc() field emitters */
static void enc_hdr(buf_t* b, unsigned int nfields) { bu32(b, nfields); }
static void enc_str(buf_t* b, const char* s) { size_t n=strlen(s); bput(b,"s",1); bu32(b,(unsigned)n); bput(b,s,n); }
static void enc_int(buf_t* b, long long v) { bput(b,"i",1); bi64(b,v); }
static void enc_bytes(buf_t* b, const unsigned char* d, unsigned n) { bput(b,"y",1); bu32(b,n); bput(b,d,n); }
static void enc_bool(buf_t* b, int v) { bput(b,"b",1); unsigned char t=v?1:0; bput(b,&t,1); }

/* H = SHAKE128 truncated to 32, as in the kit's default hash backend */
void neith_digest(const uint8_t* payload, size_t len, uint8_t out[32]) {
    shake128(out, 32, payload, (unsigned long long)len);
}

/* tag = CXOF( key(16) || enc("chunk",e,i,s) || payload , cs="NEITH-ACE-MAC" ) */
void neith_mac_chunk(const uint8_t key[16], uint32_t epoch, uint16_t sensor,
                     uint32_t seq, const uint8_t* payload, size_t len, uint8_t tag[32]) {
    buf_t m = {0};
    bput(&m, key, 16);                       /* 16-byte key prefix */
    enc_hdr(&m, 4);
    enc_str(&m, "chunk"); enc_int(&m, epoch); enc_int(&m, sensor); enc_int(&m, seq);
    bput(&m, payload, len);
    crypto_cxof(tag, 32, m.p, m.n, (const unsigned char*)"NEITH-ACE-MAC", 13);
    free(m.p);
}

/* manifest-chain genesis: H(0x09 || enc(epoch, sensor)) */
void neith_manifest_genesis(uint32_t epoch, uint16_t sensor, uint8_t out[32]) {
    buf_t b = {0}; unsigned char tag = 0x09; bput(&b, &tag, 1);
    enc_hdr(&b, 2); enc_int(&b, epoch); enc_int(&b, sensor);
    shake128(out, 32, b.p, b.n); free(b.p);
}

/* manifest body = enc("mf", e, i, v, s_hat, prev, final, [(s,digest)...]);
   returns the message to sign, H(0x0a || body), and updates prev := H(0x0a || body). */
size_t neith_manifest_signmsg(uint32_t epoch, uint16_t sensor, uint32_t v, int64_t s_hat,
                              const uint8_t prev[32], int final,
                              const uint32_t* seqs, const uint8_t (*digests)[32], size_t count,
                              uint8_t signmsg[32], uint8_t next_prev[32]) {
    buf_t body = {0};
    enc_hdr(&body, 8);
    enc_str(&body, "mf"); enc_int(&body, epoch); enc_int(&body, sensor);
    enc_int(&body, v); enc_int(&body, s_hat); enc_bytes(&body, prev, 32); enc_bool(&body, final);
    /* items: a list field -> 'l' + enc(item0, item1, ...), each item 'l' + enc(seq, digest) */
    bput(&body, "l", 1);
    buf_t items = {0}; enc_hdr(&items, (unsigned)count);
    for (size_t j = 0; j < count; j++) {
        bput(&items, "l", 1);
        buf_t it = {0}; enc_hdr(&it, 2); enc_int(&it, seqs[j]); enc_bytes(&it, digests[j], 32);
        bput(&items, it.p, it.n); free(it.p);
    }
    bput(&body, items.p, items.n); free(items.p);

    buf_t sm = {0}; unsigned char tag = 0x0a; bput(&sm, &tag, 1); bput(&sm, body.p, body.n);
    shake128(signmsg, 32, sm.p, sm.n);       /* message handed to XMSS sign */
    if (next_prev) memcpy(next_prev, signmsg, 32);  /* prev := H(0x0a||body) */
    size_t bn = body.n; free(body.p); free(sm.p);
    return bn;
}

/* ---- XMSS: stateful, persisted. Mirrors the XMSS class in neith_ace.py. ---- */
#include <stdio.h>
#include <unistd.h>
int xw_keypair(unsigned char* pk, unsigned char* sk);
int xw_sign(unsigned char* sk, unsigned char* sig, const unsigned char* m, unsigned long long mlen);
int xw_verify(const unsigned char* pk, const unsigned char* sig, const unsigned char* m, unsigned long long mlen);

#include <stdlib.h>
struct neith_xmss_ctx {
    unsigned char pk[132], sk[4096];
    unsigned long long pkl, skl, sigl;
    char state[512];
};

static int persist_state(const neith_xmss_ctx* c) {
    char tmp[560]; snprintf(tmp, sizeof(tmp), "%s.tmp", c->state);
    FILE* f = fopen(tmp, "wb"); if (!f) return -1;
    fwrite(c->sk, 1, (size_t)c->skl, f); fflush(f);
    fsync(fileno(f));                       /* one-time-key index reaches storage before release */
    fclose(f);
    return rename(tmp, c->state);
}
neith_xmss_ctx* neith_xmss_open(const char* param, const char* state_path) {
    /* Fresh key per epoch, as the reference adapter does; persist the advancing state so
       each signature's one-time index is durable before the signature is used. Production
       cross-run resume (load state on restart and REJECT a rolled-back index) is the one
       remaining obligation; it is intentionally not auto-loaded here to avoid serving a
       public key we did not re-derive. Parameter set is process-global (xw_init); every
       adapter in a deployment uses the same set, keys and state are per handle. */
    neith_xmss_ctx* c = (neith_xmss_ctx*)calloc(1, sizeof *c); if (!c) return NULL;
    if (xw_init(param, &c->pkl, &c->skl, &c->sigl)) { free(c); return NULL; }
    snprintf(c->state, sizeof(c->state), "%s", state_path);
    if (xw_keypair(c->pk, c->sk)) { free(c); return NULL; }
    if (persist_state(c)) { free(c); return NULL; }
    return c;
}
int neith_xmss_pubkey(const neith_xmss_ctx* c, uint8_t* pk, size_t* pk_len) {
    if (!c || *pk_len < c->pkl) return -1; memcpy(pk, c->pk, (size_t)c->pkl); *pk_len = (size_t)c->pkl; return 0;
}
int neith_xmss_sign(neith_xmss_ctx* c, const uint8_t* msg, size_t len, uint8_t* sig, size_t* sig_len) {
    if (!c || *sig_len < c->sigl) return -1;
    int r = xw_sign(c->sk, sig, msg, (unsigned long long)len);
    if (r) return r;                          /* non-zero: key exhausted */
    *sig_len = (size_t)c->sigl;
    return persist_state(c);                   /* state durable before signature is used */
}
void neith_xmss_close(neith_xmss_ctx* c) { if (c) { memset(c->sk, 0, sizeof c->sk); free(c); } }

/* Custody receipt message = enc("rcpt", e, t, N) || T(32) || bitmap. Signed directly by the
   store's XMSS key (not hashed), matching Store.accept() in neith_ace.py. */
size_t neith_receipt_msg(uint32_t epoch, uint32_t t, uint32_t N, const uint8_t T[32],
                         const uint8_t* bitmap, size_t bmlen, uint8_t* out, size_t outcap) {
    buf_t b = {0};
    enc_hdr(&b, 4);
    enc_str(&b, "rcpt"); enc_int(&b, epoch); enc_int(&b, t); enc_int(&b, N);
    bput(&b, T, 32);
    bput(&b, bitmap, bmlen);
    size_t n = b.n;
    if (n <= outcap) memcpy(out, b.p, n);
    free(b.p);
    return n;   /* caller signs out[0..n) with neith_xmss_sign */
}
