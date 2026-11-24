"""Run three small NEITH-ACE missions and print what the verifier concludes.

  1. honest mission                         -> COMPLETE
  2. the link drops a burst of chunks       -> ACCOUNTED, every lost chunk listed as IngestAbsent
  3. the link drops a burst, resends allowed -> REPAIRED, the lost chunks came back

Run from the repository root after ./build.sh:  python3 examples/quickstart.py
"""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import neith_ace as na
import attacks as at

cfg = na.Config(decl="signed")                         # adapters sign their manifests with XMSS
H = na.hash_backends()["shake128"]
mac = na.mac_backends()["kmac128"]
keys = at.Keys("XMSS-SHAKE256_10_256")                 # one-time XMSS key generation, a few seconds
W, L = 12, 8192                                        # 12 telemetry windows, 8 KiB chunks

cases = [("honest mission", lambda cfg, W: ({}, None)),
         ("link drops a burst", at.sc_drop_burst),
         ("link drops a burst, resends allowed", at.sc_repair_burst)]

for name, build in cases:
    hooks, _ = build(cfg, W)
    hooks.pop("W", None)
    res = at.mission(random.Random(f"quickstart-{name}"), cfg, H, mac, keys, W, L, **hooks)
    print(f"{name:38s} verdict {res['verdict']:9s} missing {len(res['absences'])}")
    for sensor, number, cls in res["absences"][:5]:
        print(f"{'':40s}sensor {sensor} chunk {number}: {cls}")
