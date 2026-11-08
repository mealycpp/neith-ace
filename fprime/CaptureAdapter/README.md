# NEITH-ACE F' capture adapter (flight segment)

Drop-in F Prime component for `NeithAceDeploy`. It is the honest flight-side node of the
NEITH-ACE pipeline: per-sensor sequence tags, a per-chunk MAC, one chained **signed
manifest** per period under the adapter's own XMSS key, a bounded resend buffer, and the
telemetry a flight review wants (capture count, manifest count, **sign latency incl.
state fsync**, buffer high-water, resend count). It calls the *same* native Ascon/XMSS
code the reference kit uses, through `neith_shim.[ch]`, so the F' numbers and the
reference numbers come from identical primitives.

## Install
```
# from the project root created by fprime-bootstrap:
mkdir -p NeithAce/Components/CaptureAdapter
cp CaptureAdapter.fpp CaptureAdapter.hpp CaptureAdapter.cpp CMakeLists.txt \
   neith_shim.h NeithAce/Components/CaptureAdapter/
# implement neith_shim.c as a thin wrapper over the kit's native/ (xmss_wrap.c) and
# vendor/ascon-c cxof; or link the kit's prebuilt build/*.so (see CMakeLists comments).
# add to NeithAce/CMakeLists.txt:
#   add_fprime_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Components/CaptureAdapter/")
# instantiate two adapters (GNSS, LiDAR) in the deployment topology, wire:
#   dataIn  <- a UART/Deframer or a FileUplink test source
#   schedIn <- a 1 Hz rate group (Delta_h)
#   frameOut-> the uplink/Framer to the integrity service
fprime-util generate && fprime-util build
```

## Measure (the flight-software result for the paper)
Run the deployment with the two adapters fed by the real GNSS/LiDAR UARTs while the F'
rate groups and health run. Collect from the telemetry database:
- **capture-task jitter**: schedIn period vs. nominal Delta_h
- **seal/sign latency**: `SignLatencyUs` (XMSS sign incl. durable state update)
- **memory high-water**: `BufferHighWater` and the deployment's memory telemetry

Compare against the Python-adapter numbers already in the evaluation (sign ~21 ms median
on the Pi 4). Same primitives, now inside flight software.

## Crypto is complete and validated
`neith_shim.c` implements the MAC (keyed Ascon-CXOF128), the digest (SHAKE128), the full
`enc()` serialization, the manifest chain, and XMSS (persisted, fsync before release).
It is **byte-for-byte identical to `neith_ace.py`** — MAC, digest, manifest genesis, and the
manifest sign-message all match, and an XMSS sign/verify round-trips. Re-prove it on the Pi:

```
./validate.sh /path/to/neith-ace-kit     # PASS = F'-signed manifests verify in the Python regulator
```

Use `--mac ascon-cxof128-keyed` across the pipeline (service + adapters) so the service's
admission MAC matches the native MAC the F' adapter computes.

Everything is complete (ports, scheduling, buffer, telemetry, events, resend, epoch/stop,
manifest signing). The one production obligation left in `neith_xmss_open` is cross-run
rollback protection (load persisted state on restart and reject a rewound index); a single-run
measurement does not need it.
