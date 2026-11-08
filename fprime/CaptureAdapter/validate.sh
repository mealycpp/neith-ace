#!/usr/bin/env bash
# Prove neith_shim is byte-compatible with the reference kit, then XMSS round-trip.
# Usage: ./validate.sh /path/to/neith-ace-kit
set -e
KIT=${1:?usage: ./validate.sh /path/to/neith-ace-kit}
A=$KIT/vendor/ascon-c; X=$KIT/vendor/xmss-reference
gcc -O2 -I. -I$A/crypto_cxof/asconcxof128/ref -I$A/tests -I$X -I$KIT/native/shim \
  validate_shim.c neith_shim.c $A/crypto_cxof/asconcxof128/ref/hash.c \
  $KIT/native/xmss_wrap.c $KIT/native/sha_shim.c \
  $X/{params,hash,fips202,hash_address,randombytes,wots,xmss,xmss_core_fast,xmss_commons,utils}.c \
  -o /tmp/neith_validate
echo "== C shim =="; /tmp/neith_validate | tee /tmp/c.txt
echo "== Python reference =="; (cd "$KIT" && python3 - <<'PY' | tee /tmp/py.txt
import neith_ace as na
H=na.hash_backends()["shake128"]; mac=na.mac_backends()["ascon-cxof128-keyed"]
key=bytes(range(16)); p=bytes((i*7)&0xff for i in range(40))
print("MAC", mac(key, na.enc("chunk",1,0,5)+p).hex())
print("DIG", H(p).hex())
gen=H(b"\x09"+na.enc(1,0)); print("GEN", gen.hex())
items=[(0,H(p)),(1,H(p[:20]))]
print("SIGNMSG", H(b"\x0a"+na.enc("mf",1,0,1,5,gen,False,items)).hex())
PY
)
echo "== diff (MAC/DIG/GEN/SIGNMSG must match) =="
if diff <(grep -E 'MAC|DIG|GEN|SIGNMSG' /tmp/c.txt) <(grep -E 'MAC|DIG|GEN|SIGNMSG' /tmp/py.txt); then
  echo "PASS: shim is byte-compatible with the reference"; else echo "MISMATCH"; exit 1; fi
