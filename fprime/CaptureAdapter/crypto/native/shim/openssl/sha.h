/* Shim: NEITH-ACE uses only XMSS-SHAKE256 parameter sets; SHA-2 paths abort. */
#ifndef NEITH_SHIM_SHA_H
#define NEITH_SHIM_SHA_H
#include <stddef.h>
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md);
#endif
