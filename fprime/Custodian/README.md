# NEITH-ACE F' custodian (ground segment, SOBEK)

The adversarial ground node. Receives chunk/manifest frames, persists them, signs one
custody receipt per window with its **own** XMSS key, and in malicious mode alters a stored
chunk it already signed for. Pair it with the F' capture adapter on the ClusterHAT and the
picture is literal: **F' flight node -> F' ground node that tampers -> independent regulator
catches it**. The regulator stays a separate process (Python `live.py` verifier): custodian
and regulator must not share keys.

Uses the same validated `neith_shim` (receipt message byte-matches `Store.accept` in the kit;
XMSS sign persists state with fsync before release).

## Install on SOBEK
```
# SOBEK already runs F' (the AKER build). If its fpp native tools don't run (32-bit ARMv7),
# apply the same JVM wrapper used on the ClusterHAT (there is an fpp.jar in fprime_fpp;
# a JRE is required). Then:
mkdir -p <fprime-project>/Components/Custodian
cp Custodian.* neith_shim.* CMakeLists.txt <fprime-project>/Components/Custodian/
./validate.sh ~/neith-ace/kit/v4        # same validator; expect PASS (copy it from CaptureAdapter)
# add_fprime_subdirectory(".../Components/Custodian/") to the project CMakeLists
fprime-util generate && fprime-util build --target Custodian
```

## Demo
Instantiate in the ground deployment, wire `frameIn` from the uplink, `schedIn` to a rate
group, `receiptOut` to the service and the regulator. Run with `SET_MALICIOUS true`; the
regulator returns ACCOUNTED with CustodyLoss on exactly the tampered chunks --- the same
result the Python live run produced, now with the attack originating in SOBEK's F'.

## Scaffold status
Crypto complete and validated (receipt signing). Left as wire integration, same as the
capture adapter: deframing `frameIn` into (window, sensor, seq, payload, T) and the on-disk
persist/rewrite in `frameIn_handler`/`tamperOne` (marked with comments). Component model,
scheduling, receipt signing, malicious lifecycle, telemetry, and events are complete.
