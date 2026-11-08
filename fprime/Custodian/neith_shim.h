/* Thin C shim: the only NEITH-ACE crypto the F' component calls. Backed by the same
   ascon-c and xmss-reference code the Python reference loads, so F' numbers and
   reference numbers come from identical primitives. Link against libasconcxof and
   libxmss (see build.sh in the kit). */
#ifndef NEITH_SHIM_H
#define NEITH_SHIM_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Keyed Ascon-CXOF128 MAC over enc("chunk",e,i,s)||payload -> 32-byte tag. */
void neith_mac_chunk(const uint8_t key[16], uint32_t epoch, uint16_t sensor,
                     uint32_t seq, const uint8_t *payload, size_t len, uint8_t tag[32]);

/* SHAKE128 digest (32 bytes) of a chunk payload, for the manifest entry. */
void neith_digest(const uint8_t *payload, size_t len, uint8_t out[32]);

/* XMSS context bound to a persisted state file. Returns 0 on success. The state index
   is advanced and fsync'd before sign() returns; a non-zero return from sign means the
   one-time-key budget is exhausted (raise KeyExhausted). */
typedef struct neith_xmss_ctx neith_xmss_ctx;   /* one per adapter instance */
neith_xmss_ctx* neith_xmss_open(const char *param, const char *state_path);   /* NULL on failure */
int  neith_xmss_pubkey(const neith_xmss_ctx *c, uint8_t *pk, size_t *pk_len);
int  neith_xmss_sign(neith_xmss_ctx *c, const uint8_t *msg, size_t len, uint8_t *sig, size_t *sig_len);
void neith_xmss_close(neith_xmss_ctx *c);

void neith_manifest_genesis(uint32_t epoch, uint16_t sensor, uint8_t out[32]);
size_t neith_manifest_signmsg(uint32_t epoch, uint16_t sensor, uint32_t v, int64_t s_hat,
                              const uint8_t prev[32], int final,
                              const uint32_t* seqs, const uint8_t (*digests)[32], size_t count,
                              uint8_t signmsg[32], uint8_t next_prev[32]);

size_t neith_receipt_msg(uint32_t epoch, uint32_t t, uint32_t N, const uint8_t T[32],
                         const uint8_t* bitmap, size_t bmlen, uint8_t* out, size_t outcap);
#ifdef __cplusplus
}
#endif
#endif
