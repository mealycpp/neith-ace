/* Thin ctypes-friendly wrapper over xmss-reference (BDS fast core). */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "params.h"
#include "xmss.h"
static uint32_t g_oid; static xmss_params g_p;
int xw_init(const char *name, unsigned long long *pkb, unsigned long long *skb, unsigned long long *sigb){
  if (xmss_str_to_oid(&g_oid, name)) return -1;
  if (xmss_parse_oid(&g_p, g_oid)) return -2;
  *pkb = g_p.pk_bytes + 4; *skb = g_p.sk_bytes + 4; *sigb = g_p.sig_bytes; return 0;
}
int xw_keypair(unsigned char *pk, unsigned char *sk){ return xmss_keypair(pk, sk, g_oid); }
int xw_sign(unsigned char *sk, unsigned char *sig, const unsigned char *m, unsigned long long mlen){
  /* heap scratch: two adapters sign concurrently on their own F' threads */
  unsigned long long smlen; unsigned long long cap = mlen + g_p.sig_bytes;
  unsigned char *sm = (unsigned char*)malloc((size_t)cap); if (!sm) return -3;
  int r = xmss_sign(sk, sm, &smlen, m, mlen);
  if (!r) memcpy(sig, sm, g_p.sig_bytes);
  free(sm); return r;
}
int xw_verify(const unsigned char *pk, const unsigned char *sig, const unsigned char *m, unsigned long long mlen){
  static unsigned char sm[1<<16], out[1<<16]; unsigned long long outlen;
  if (mlen + g_p.sig_bytes > sizeof sm) return -3;
  memcpy(sm, sig, g_p.sig_bytes); memcpy(sm + g_p.sig_bytes, m, mlen);
  return xmss_sign_open(out, &outlen, sm, g_p.sig_bytes + mlen, pk);
}
