#!/usr/bin/env bash
# Builds the native libraries NEITH-ACE needs. Run once per node (Pi 5 and each Pi Zero 2 W).
set -euo pipefail
cd "$(dirname "$0")"
CC=${CC:-gcc}; CF="-O3 -fPIC -shared"
mkdir -p build
A=vendor/ascon-c
echo "[build] Ascon-XOF128 opt64 (native optimized C)"
$CC $CF -I$A/crypto_hash/asconxof128/opt64 -I$A/tests $A/crypto_hash/asconxof128/opt64/{hash,permutations}.c -o build/libasconxof_opt64.so
echo "[build] Ascon-XOF128 ref (portable C)"
$CC $CF -I$A/crypto_hash/asconxof128/ref -I$A/tests $A/crypto_hash/asconxof128/ref/hash.c -o build/libasconxof_ref.so
echo "[build] Ascon-CXOF128 ref (keyed MAC option)"
$CC $CF -I$A/crypto_cxof/asconcxof128/ref -I$A/tests $A/crypto_cxof/asconcxof128/ref/hash.c -o build/libasconcxof_ref.so
echo "[build] XMSS (xmss-reference, BDS fast core, SHAKE256 sets)"
X=vendor/xmss-reference
$CC $CF -Inative/shim -I$X native/xmss_wrap.c native/sha_shim.c \
  $X/{params,hash,fips202,hash_address,randombytes,wots,xmss,xmss_core_fast,xmss_commons,utils}.c -o build/libxmss.so
echo "[build] python deps"
python3 -c "import Crypto" 2>/dev/null || pip3 install --user --break-system-packages pycryptodome blake3 || pip3 install --user pycryptodome blake3 || true
python3 -c "import Crypto; print('[build] ok: pycryptodome', Crypto.__version__)"
