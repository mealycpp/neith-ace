# NEITH-ACE

Code, attack injector, and measurement logs for

> M. El-Hadedy, "NEITH-ACE: Authenticated Telemetry Completeness and Loss Attribution for Small-Spacecraft Flight Software," submitted to the *Journal of Hardware and Systems Security* (Springer), November 2026.

NEITH-ACE extends NEITH (IEEE SATC 2026). NEITH proves that what reached the onboard logger was not changed. NEITH-ACE also proves the record is complete: each capture adapter signs chained manifests of the chunks it captured, under a key the logger never holds, so a verifier can tell what is missing and where the evidence for each missing chunk ends, even if the logger is compromised.

The verifier returns one of Complete, Repaired, Accounted, Prefix, Stale, Withheld, or Invalid, together with the exact set of missing chunks.

## Build

```bash
./build.sh   # builds the Ascon and XMSS native libraries, installs pycryptodome
python3 -c "import neith_ace as na; na.XMSS('XMSS-SHAKE256_10_256'); print('ok')"
```

Tested on a Raspberry Pi 4 and on x86-64 Linux.

## Reproduce the paper

| Paper item | Command | Result in this repo |
|---|---|---|
| Attack table (Online Resource 1) | `python3 attacks.py --trials 8 --out results/x` (add `--decl mac` for the MAC-only run) | `results/attacks_rev16_signed/`, `results/attacks_rev16_mac/` |
| Table 4, comparison | `python3 sota.py --out results/x` | `results/sota_rev17/` |
| Fig. 3(a), repair and custody results | `live.py` over three machines (below) | `results/live/` |
| Fig. 3(b), measured capacity | `python3 capacity.py` (about 25 min on a Pi 4) | `results/capacity/` |
| Cost figures in Section 6 | `python3 bench.py` | `results/bench_clusterhat.json` |
| F′ adapter timing | see `fprime/README.md` | `results/fprime/` |
| Edge-case tests | `python3 tests/test_pending_custody.py`, `python3 tests/test_receipts_openings.py` | |

`attacks.py` and `sota.py` use the fixed seed 2026. `attacks.py` simulates time so it can run many missions; its cryptography is real.

### Live run over three machines

```bash
# store and verifier (start first); --malicious 1 makes the store cheat
python3 live.py store --port 7701 --xmss XMSS-SHAKE256_10_256 --out results/net [--malicious 1]

# integrity service; --drop injects link loss, --repair requests resends
python3 live.py serve --windows 32 --drop 0.05 --repair 1 --store <STORE_IP>:7701 --out results/net

# capture adapters with real sensors
python3 live.py adapter --connect <SERVICE_IP>:7700 --id 0 --source serial:/dev/ttyACM0 --out results/net &
python3 live.py adapter --connect <SERVICE_IP>:7700 --id 1 --source serialblock:/dev/ttyUSB0:8192 --out results/net &
```

## Files

| Path | Contents |
|---|---|
| `neith_ace.py` | the scheme: adapter, manifests, integrity service, store, verifier |
| `attacks.py` | the 44 attack scenarios, checked against ground truth |
| `sota.py` | reimplementations of existing mechanisms for the comparison |
| `live.py` | real-time pipeline over TCP (`adapter`, `serve`, `store`) |
| `capacity.py` | capacity sweep behind Fig. 3(b) |
| `bench.py` | cost of hashes, MACs, and XMSS signing |
| `baselines.py` | earlier internal baselines, kept for reference |
| `make_tables.py` | builds the LaTeX tables from the results |
| `fprime/` | F′ capture adapter and custodian components |
| `tests/` | edge-case tests |
| `native/`, `vendor/` | C glue and vendored ascon-c, xmss-reference, pyascon |

## Citation

Until the journal article appears, please cite the conference paper:

```bibtex
@inproceedings{elhadedy2026neith,
  author    = {El-Hadedy, Mohamed},
  title     = {{NEITH}: Networked Evidence Integrity for Telemetry Hashing},
  booktitle = {2026 IEEE 2nd International Conference on Secure IoT, Assured and Trusted Computing (SATC)},
  year      = {2026},
  pages     = {1--5},
  doi       = {10.1109/SATC69565.2026.11542491}
}
```

## License

MIT (`LICENSE`). Code under `vendor/` is CC0-1.0 by its original authors.

## Acknowledgements

Developed in the Reconfigurable Space Computing Lab, California State Polytechnic University, Pomona. Supported by the U.S. Navy Naval Engineering Education Consortium (N00174-23-1-0002), the ONR Summer Faculty Research Program, the U.S. Army Research Office (W911NF-24-1-0265), and the Air Force Research Laboratory (FA8650-24-2-2403). AMD provided development boards. The views expressed are the author's and do not necessarily represent those of AFRL or the U.S. Government.
