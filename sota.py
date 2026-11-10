#!/usr/bin/env python3
"""State-of-the-art comparison on identical traces (manuscript Sec. 7, Table: sota).

Every system is judged on the same simulated missions (same seeds, same loss pattern, same
adversary). Each prior system is reduced to its completeness mechanism and given exactly the
evidence that mechanism would hold; the verdict it can justify is scored against ground truth.

  LOGGER-MERKLE  RFC 6962/9162 Certificate Transparency, Crosby-Wallach history trees:
                 the service appends what it received to a Merkle log and signs tree heads;
                 auditors check consistency and that every logged entry is retrievable.
  SYSLOG-SIGN    RFC 5848: the originator signs Signature Blocks listing hashes of its own
                 messages, numbered by a Global Block Counter; a collector stores blocks and
                 messages, and a verifier checks every listed hash against the stored messages.
                 No end-of-session marker, no custody receipts, no retransmission.
  SDLS+CFDP      CCSDS SDLS frame authentication with anti-replay counters and CFDP class-2
                 NAK retransmission: the receiver authenticates, detects, and repairs gaps,
                 then declares the transfer complete. Its declaration is the evidence; nothing
                 is committed for a third party, and the stored copy is not covered.
  SYSLOG-FRESH   SYSLOG-SIGN plus a freshness check: the verifier knows the mission end and
                 the block period and flags a source whose last block is too old (STALE).
  DASLOG         Sarenche et al. 2023: every source signs a hash chain of its records and a
                 final message carries each source's signature on its last record (anchored on
                 a ledger, assumed honest here). Modelled with the adapters' signed manifests
                 and FINAL: same source evidence as NEITH-ACE, but no stage attribution, no
                 repair, no custody receipts.
  NITRO          Zhao et al., CCS 2025: the logger tags every entry it logs with a forward-secure
                 MAC and folds the tags into a MAC combiner; a verifier holding the initial key
                 checks every logged entry and locates tampered or deleted ones. Its evidence
                 starts at the logger: it trusts the logger to log what it received, so it is
                 blind to chunks that never arrived, and a logger compromised from the start
                 holds the keys. No source declaration, repair, or custody receipts.
  NEITH-ACE      full protocol: signed manifests + FINAL, repair, receipts, checkpoints.

Verdict classes: COMPLETE, REPAIRED (complete after verified recovery), DETECTED (incomplete,
no boundary), ACCOUNTED (incomplete, every absence at an authenticated boundary), PREFIX,
STALE, INVALID, WITHHELD. A COMPLETE or REPAIRED verdict on a record that lacks captured
chunks, or holds content the adapter never produced, is a false completeness.
"""
import argparse, csv, json, os, random, statistics
from collections import Counter
import neith_ace as na
import attacks as at

SYSTEMS = ["LOGGER-MERKLE", "NITRO", "SYSLOG-SIGN", "SYSLOG-FRESH", "SDLS+CFDP", "DASLOG", "NEITH-ACE"]
HAS_REPAIR = {"LOGGER-MERKLE": False, "NITRO": False, "SYSLOG-SIGN": False, "SYSLOG-FRESH": False,
              "SDLS+CFDP": True, "DASLOG": False, "NEITH-ACE": True}

def workloads(cfg, W):
    """name -> (kwargs builder(repair: bool), compromised service?, record actually whole?)."""
    def plain(builder):
        def b(repair):
            kw, _ = builder(cfg, W)
            if repair:
                kw["repair"] = at._honest_repair
            return kw
        return b
    def fabricate(repair):
        kw, _ = at._drop_and("fabricate", cfg, W)(cfg, W)
        if repair:
            kw["repair"] = at._honest_repair
        return kw
    def hide(repair):
        kw, _ = at.sc_cis_hide_newest(cfg, W)
        return kw
    return [
        ("benign",            plain(lambda c, w: at.sc_benign()), False),
        ("link loss",         plain(at.sc_drop_burst),            False),
        ("store deletes",     plain(at.sc_store_delete),          False),
        ("service fabricates", fabricate,                          True),
        ("service hides newest", hide,                             True),
    ]

def leaves_committed(res):
    return {(p[0][0], pos) for p in res["svc"].published for pos in range(p[0][1])}

def logger_merkle(res):
    if res["verdict"] in ("INVALID", "WITHHELD") and "publication" in res["info"].get("why", ""):
        return res["verdict"]
    missing = [k for k in leaves_committed(res) if res["store"].get(*k) is None]
    return "DETECTED" if missing else "COMPLETE"

def nitro(res, H, compromised):
    """Logger-side MAC log: every entry the service logged must be in storage, unmodified.
    A compromised service holds the logging key, so its log verifies whatever it contains."""
    if compromised:
        return "COMPLETE"
    for p in res["svc"].published:
        t, N = p[0][0], p[0][1]
        for pos in range(N):
            if res["store"].get(t, pos) is None:
                return "DETECTED"
    return "COMPLETE"

def syslog_sign(res, H):
    declared, ok = {}, True
    for p in res["svc"].published:
        for r in na._decode_records(p[1]):
            i = r[0]
            for m in (r[11] if len(r) > 11 else []):
                v, items = m[0], m[4]
                declared.setdefault(i, {})[v] = items
    for i, blocks in declared.items():                 # Global Block Counter must be contiguous
        vs = sorted(blocks)
        if vs and vs != list(range(1, vs[-1] + 1)):
            ok = False
    stored = {}
    for (i, s, c, *_rest) in res["store"].data.values():
        stored.setdefault((i, s), set()).add(H(c))
    for i, blocks in declared.items():
        for items in blocks.values():
            for (s, d) in items:
                if d not in stored.get((i, s), set()):
                    ok = False
    return "COMPLETE" if ok else "DETECTED"

def _manifests(res):
    out = {}
    for p in res["svc"].published:
        for r in na._decode_records(p[1]):
            for m in (r[11] if len(r) > 11 else []):
                out.setdefault(r[0], []).append(m)
    return out

def syslog_fresh(res, H, cfg, W):
    """SYSLOG-SIGN plus freshness: the last signature block of each source must be no older
    than one and a half block periods before the mission end."""
    v = syslog_sign(res, H)
    mf = _manifests(res)
    end = W * cfg.delta
    for i in at.SENSORS:
        vs = [m[0] for m in mf.get(i, [])]
        last_time = max(vs) * cfg.delta_m if vs else 0.0      # block v is cut near v * delta_m
        if last_time < end - 1.5 * cfg.delta_m:
            return "STALE"
    return v

def daslog(res, H):
    """Source-signed hash chains closed by a final signed message; every declared record must
    be in storage with the signed digest. No attribution, no repair."""
    mf = _manifests(res)
    stored = {}
    for (i, s, c, *_r) in res["store"].data.values():
        stored.setdefault((i, s), set()).add(H(c))
    committed = {(i, s) for (i, s, c, *_r) in res["store"].data.values()}
    for i in at.SENSORS:
        ms = mf.get(i, [])
        vs = [m[0] for m in ms]
        if not ms or vs != list(range(1, len(vs) + 1)) or not ms[-1][3]:
            return "DETECTED"                 # chain broken or no final message
        declared = {s for m in ms for (s, d) in m[4]}
        for m in ms:
            for (s, d) in m[4]:
                if bytes(d) not in stored.get((i, s), set()):
                    return "DETECTED"
        if any(ii == i and s not in declared for (ii, s) in committed):
            return "DETECTED"                 # stored record the source never signed
    return "COMPLETE"

def sdls_cfdp(res, compromised):
    if compromised:                     # the receiver is the compromised party; its word is the verdict
        return "COMPLETE"
    gaps = sum(len(st.unresolved) for st in res["svc"].sensors.values())
    return "COMPLETE" if gaps == 0 else "DETECTED"

def truth_whole(res, workload, repaired):
    """Ground truth: is the stored record exactly what the adapters captured?"""
    if workload == "benign":
        return True
    if workload == "link loss":
        return repaired                  # whole only if every dropped chunk was really recovered
    return False                         # deletion, fabrication, hiding: never whole

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--windows", type=int, default=12)
    ap.add_argument("--leaf", type=int, default=8192)
    ap.add_argument("--xmss", default="XMSS-SHAKE256_10_256")
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    H = na.hash_backends()["shake128"]; mac = na.mac_backends()["kmac128"]
    keys = at.Keys(a.xmss)
    cfg = na.Config(sig=a.xmss, decl="signed")
    rows = []
    for wname, build, compromised in workloads(cfg, a.windows):
        tally = {s: Counter() for s in SYSTEMS}; false_c = Counter(); correct = Counter()
        for trial in range(a.trials):
            seed = f"{a.seed}-{wname}-{trial}"
            runs = {}
            for rep in (False, True):          # identical trace; with and without a repair path
                runs[rep] = at.mission(random.Random(seed), cfg, H, mac, keys, a.windows, a.leaf, **build(rep))
            for sysname in SYSTEMS:
                rep = HAS_REPAIR[sysname] and wname == "link loss"
                res = runs[rep]
                if sysname == "LOGGER-MERKLE":
                    v = logger_merkle(res)
                elif sysname == "NITRO":
                    v = nitro(res, H, compromised)
                elif sysname == "SYSLOG-SIGN":
                    v = syslog_sign(res, H)
                elif sysname == "SYSLOG-FRESH":
                    v = syslog_fresh(res, H, cfg, a.windows)
                elif sysname == "DASLOG":
                    v = daslog(res, H)
                elif sysname == "SDLS+CFDP" and wname == "store deletes":
                    v = "N/A"                  # CFDP does not cover the stored copy
                elif sysname == "SDLS+CFDP":
                    v = sdls_cfdp(res, compromised)
                    if v == "COMPLETE" and rep and res["info"].get("repairs"):
                        v = "REPAIRED"
                else:
                    v = res["verdict"]
                repaired = rep and not compromised and bool(res["info"].get("repairs")) and \
                    sum(len(st.unresolved) for st in res["svc"].sensors.values()) == 0
                whole = truth_whole(res, wname, repaired)
                tally[sysname][v] += 1
                claims_whole = v in ("COMPLETE", "REPAIRED")
                if v == "N/A":
                    continue
                if claims_whole and not whole:
                    false_c[sysname] += 1
                if claims_whole == whole:
                    correct[sysname] += 1
        for sysname in SYSTEMS:
            row = dict(workload=wname, system=sysname, trials=a.trials,
                       verdicts=json.dumps(dict(tally[sysname])),
                       false_complete=false_c[sysname], correct=correct[sysname])
            rows.append(row)
            print(f"{wname:22s} {sysname:14s} false_complete={false_c[sysname]:3d} "
                  f"correct={correct[sysname]:3d}/{a.trials}  {dict(tally[sysname])}", flush=True)
    tag = os.uname().nodename
    with open(os.path.join(a.out, f"sota_{tag}.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print(f"wrote {a.out}/sota_{tag}.csv")

if __name__ == "__main__":
    main()
