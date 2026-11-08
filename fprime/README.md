# NEITH-ACE F´ components

Two F´ (F Prime) active components that put the NEITH-ACE roles where they would run on a spacecraft and its ground segment. They wrap the same C primitives the Python reference loads (`neith_shim.c`: keyed Ascon-CXOF128, SHAKE128 digests, enc() bodies, XMSS-SHAKE256 with persisted, fsync'd state), so F´ output and reference output come from identical code.

| Component | Role | Built on |
|---|---|---|
| `CaptureAdapter/` | flight-side capture adapter: tags chunks, keeps the resend buffer, seals and signs chained manifests on the rate group, declares FINAL | Raspberry Pi 4 (ClusterHAT host), inside a running deployment |
| `Custodian/` | ground-side storage custodian: verifies handoffs, signs custody receipts; `--malicious` path alters stored bytes after receipting | 32-bit ARMv7 SBC, component library built and linked |

## Layout and build

Each directory is a self-contained F´ module: `*.fpp`, `*.hpp/.cpp`, `neith_shim.{h,c}`, the vendored crypto under `crypto/`, and a `CMakeLists.txt` using `SOURCE_FILES` + `register_fprime_module()`. Drop it under your project's `Components/`, add `add_fprime_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Components/CaptureAdapter/")` **before** `register_fprime_deployment`, and instance it as `Components.CaptureAdapter` in the topology. Call `configure(sensorId, key, "XMSS-SHAKE256_10_256", statePath, manifestPeriodTicks, bufSize)` from `configureTopology`. Each instance owns its own XMSS key and state file; instances may sign concurrently.

F´ 4.4.x notes: on ARMv8.0 hosts (Pi 4) the bundled `fpp-*` natives need LSE and abort; replace them with wrappers that run `fpp.jar` under a JVM.

## Validation

`CaptureAdapter/validate.sh <kit-dir>` compiles the shim with a small driver and byte-compares MAC / digest / manifest genesis / manifest body against the Python reference, then round-trips an XMSS signature across two independent handles.

## Measurement mode

`setReplay(path, blockBytes, chunksPerTick, epoch)` feeds a recorded sensor stream through the capture path at the rate group so the component can be measured without a UART driver. `results/fprime/fprime_run2.log` is the run reported in the paper: real GNSS (656 chunks, 9 manifests incl. FINAL) and LiDAR (280 blocks, 14 manifests) on the Pi 4, 1 Hz cadence, 54.8 ms median seal time dominated by the durable key-state write.

F´ provides scheduling, buffering and telemetry around these components. It provides none of the security guarantee; that rests on the adapter's key and the verifier's checks.
