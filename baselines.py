#!/usr/bin/env python3
"""Baseline comparison on identical traces (manuscript Sec. 7, Table: baselines).

Five verifiers are run over the *same* simulated missions (same seeds, same loss pattern, same
adversary). Each baseline sees the evidence its design would produce; the question is which
verdict each one can justify and what it costs.

  NEITH          conference contract: window roots over received chunks, signed checkpoints.
                 No declarations: it cannot see that anything is missing.
  SEQLOG         authenticated sequence log + the same buffer/retransmission mechanism:
                 gaps are detected from sequence numbers at the (trusted) service; no
                 committed account of gap history, no custody receipts.
  ACE-MAC        NEITH-ACE with MAC heartbeats as the only declarations (service trusted).
  ACE-NOREPAIR   full NEITH-ACE evidence with signed manifests, repair path disabled.
  ACE            full NEITH-ACE: signed manifests + repair + receipts.

Workloads: benign; link loss (drop-burst); compromised service fabricating dropped chunks.
Metrics: unresolved declared chunks at audit, false-COMPLETE verdicts, repairs verifiable from
the history, evidence bytes published per window, verifier time.
"""
import argparse, csv, json, os, random, statistics, time
import neith_ace as na
import attacks as at

def run(cfg, H, mac, keys, W, L, rng_seed, workload, repair, compromise):
    rng = random.Random(rng_seed)
    kw = {}
    if workload == "loss":
        kw, _ = at.sc_drop_burst(cfg, W)
    if compromise:
        kw2, _ = at._drop_and("fabricate", cfg, W)(cfg, W)
        kw = kw2
    if repair:
        kw["repair"] = at._honest_repair
    return at.mission(rng, cfg, H, mac, keys, W, L, **kw)

def seqlog_verdict(res):
    """What an authenticated sequence log (trusted keeper) concludes from the same trace:
    gaps = holes in the received sequence numbers after retransmission. It cannot see a
    missing tail (nothing after it) and it trusts the keeper's own log."""
    svc = res["svc"]
    holes = 0
    for i, st in svc.sensors.items():
        holes += len(st.unresolved)
    return ("COMPLETE" if holes == 0 else "INCOMPLETE"), holes

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--windows", type=int, default=12)
    ap.add_argument("--leaf", type=int, default=8192)
    ap.add_argument("--xmss", default="XMSS-SHAKE256_10_256")
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    H = na.hash_backends()["shake128"]; mac = na.mac_backends()["kmac128"]
    keys = at.Keys(a.xmss)
    systems = [  # name, decl, repair, uses declarations in verdict, has receipts
        ("NEITH",        "mac",    False, False, False),
        ("SEQLOG",       "mac",    True,  True,  False),
        ("ACE-MAC",      "mac",    True,  True,  True),
        ("ACE-NOREPAIR", "signed", False, True,  True),
        ("ACE",          "signed", True,  True,  True),
    ]
    rows = []
    for workload, compromise in [("benign", False), ("loss", False), ("compromised", True)]:
        for name, decl, repair, uses_decl, receipts in systems:
            cfg = na.Config(sig=a.xmss, decl=decl)
            unresolved, false_complete, repairs_ok, bytes_w, vts, verdicts = [], 0, 0, [], [], {}
            for trial in range(a.trials):
                seed = f"{a.seed}-{workload}-{trial}"      # identical trace across systems
                res = run(cfg, H, mac, keys, a.windows, a.leaf, seed, workload, repair, compromise)
                truth_missing = len(res["truth"].get("target", []))
                if name == "NEITH":
                    # verdict from roots + checkpoints only (records ignored)
                    verdict = "COMPLETE" if res["verdict"] not in ("INVALID", "WITHHELD") else res["verdict"]
                    unres = 0 if verdict == "COMPLETE" else truth_missing
                    nbytes = sum(32 + 32 + (len(p[3]) if p[3] else 0) for p in res["svc"].published)
                elif name == "SEQLOG":
                    verdict, unres = seqlog_verdict(res)
                    if compromise:
                        unres = 0                # the keeper's log shows no holes
                    nbytes = sum(8 * (len(r[3]) + len(r[4])) + 16 for p in res["svc"].published
                                 for r in na._decode_records(p[1]))
                else:
                    verdict, unres = res["verdict"], len(res["absences"])
                    nbytes = res["rec_bytes"] + sum(32 + 32 + (len(p[3]) if p[3] else 0) for p in res["svc"].published)
                # ground truth: anything dropped and not actually recovered is unresolved
                actually_missing = truth_missing - (len(res["info"].get("repairs", [])) if repair and not compromise else 0)
                if compromise:
                    actually_missing = truth_missing          # fabricated bytes are not the record
                if verdict in ("COMPLETE", "REPAIRED") and actually_missing > 0:
                    false_complete += 1        # certifying a record that is not the capture
                if repair and not compromise and res["info"].get("repairs") and verdict == "REPAIRED":
                    repairs_ok += 1
                unresolved.append(unres); bytes_w.append(nbytes / (a.windows + 1)); vts.append(res["verify_s"])
                verdicts[verdict] = verdicts.get(verdict, 0) + 1
            row = dict(workload=workload, system=name, trials=a.trials,
                       unresolved_mean=round(statistics.mean(unresolved), 2),
                       false_complete=false_complete, repaired_verifiable=repairs_ok,
                       evidence_bytes_per_window=int(statistics.mean(bytes_w)),
                       verify_ms_median=round(1e3 * statistics.median(vts), 1),
                       verdicts=json.dumps(verdicts))
            rows.append(row)
            print(f"{workload:12s} {name:13s} unresolved={row['unresolved_mean']:6.2f} falseCOMPLETE={false_complete:3d} "
                  f"repairedOK={repairs_ok:3d} bytes/w={row['evidence_bytes_per_window']:6d} verify={row['verify_ms_median']} ms  {row['verdicts']}", flush=True)
    tag = os.uname().nodename
    with open(os.path.join(a.out, f"baselines_{tag}.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print(f"wrote {a.out}/baselines_{tag}.csv")

if __name__ == "__main__":
    main()
