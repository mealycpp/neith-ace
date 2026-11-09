#!/usr/bin/env python3
"""NEITH-ACE attack-injection evaluation (manuscript Table: attack coverage).

Each trial runs a complete mission in virtual time: adapters emit chunks and heartbeats,
links deliver them to the integrity service, windows close on schedule, the store verifies
and receipts each window, and a settlement window ends the epoch. One attack is applied per
trial; the verifier must return the expected verdict AND exactly the expected absence set.
Cryptography (hashing, MACs, XMSS) is real; only time is simulated.
"""
import argparse, copy, csv, json, os, random, statistics, sys, time
import neith_ace as na

SENSORS = {0: ("gnss", 5.529), 1: ("lidar", 1.432)}   # measured SaTC rates (Hz)

class Keys:
    """Reuses XMSS keys across trials; regenerates before a key runs out."""
    def __init__(self, param):
        self.param, self.is_key, self.st_key, self.used = param, None, None, 10**9
        self.ad_keys = {}
        self.cap = 2 ** int(param.split("_")[1])
        self.keygen_s = []
    def get(self, need):
        if self.used + need > self.cap:
            self.is_key = na.XMSS(self.param); self.st_key = na.XMSS(self.param)
            self.ad_keys = {i: na.XMSS(self.param) for i in SENSORS}
            self.keygen_s += [self.is_key.keygen_s, self.st_key.keygen_s] + [k.keygen_s for k in self.ad_keys.values()]
            self.used = 0
        self.used += need
        return self.is_key, self.st_key

def schedule(rng, W, cfg, L):
    """Per-sensor chunk and heartbeat emission times over W telemetry windows."""
    ev = []
    end = W * cfg.delta
    for i, (_, rate) in SENSORS.items():
        t = rng.uniform(0, 1 / rate)
        while t < end - 0.05:
            ev.append((t, i, "C", rng.randbytes(L)))
            t += rng.expovariate(rate) * 0.5 + 0.5 / rate      # bursty but rate-preserving
        t = rng.uniform(0, cfg.delta_h)
        while t < end:
            ev.append((t, i, "B", None)); t += cfg.delta_h
        if cfg.decl == "signed":        # manifests: one per delta_m, plus a final one at stop
            t = cfg.delta_m - 0.2
            while t < end:
                ev.append((t, i, "M", None)); t += cfg.delta_m
            ev.append((end - 0.02, i, "MF", None))     # FINAL manifest at stop
    ev.sort(key=lambda e: e[0])
    return ev

def mission(rng, cfg, H, mac, keys, W, L, link=None, publish=None, custody=None, handoff=None,
            repair=None, compromise=None, audit_at=None):
    """repair: None (no resend path) or a function (rng, requests, attempt, truth) -> requests
    that the adversarial link lets through to the adapters (identity = honest link)."""
    is_key, st_key = keys.get(need=W + 2 + int(W * cfg.delta / cfg.delta_m) + 3)
    adapter_keys = {i: rng.randbytes(16) for i in SENSORS}
    ad = {i: na.Adapter(cfg, i, adapter_keys[i], mac, H=H, signer=keys.ad_keys[i]) for i in SENSORS}
    ad_pubs = {i: keys.ad_keys[i].public() for i in SENSORS} if cfg.decl == "signed" else {}
    svc = na.IntegrityService(cfg, adapter_keys, is_key, H, mac, adapter_pubs=ad_pubs, store_pub=st_key.public())
    if compromise:
        compromise(rng, svc, truth_ref := {})
    store = na.Store(cfg, H, st_key)
    # emit
    msgs = []; emitted_at = {}
    for (tau, i, kind, c) in schedule(rng, W, cfg, L):
        m = (ad[i].chunk(c) if kind == "C" else ad[i].heartbeat() if kind == "B"
             else ad[i].manifest(final=(kind == "MF")))
        if kind == "C":
            emitted_at[(i, m[2])] = tau
        msgs.append([tau + 0.004 + rng.uniform(0, 0.002), m])   # link latency 4-6 ms, FIFO enough
    msgs.sort(key=lambda x: x[0])
    truth = {"msgs": msgs}
    if compromise:
        truth.update(truth_ref)
    if link:
        msgs = link(rng, msgs, truth)
    # deliver + close windows on schedule
    mi = 0; receipts_in_flight = []
    t_close_list = [(cfg.delta * (t + 1) + cfg.gamma, t) for t in range(W + 1)]
    for close_at, t in t_close_list:
        while mi < len(msgs) and msgs[mi][0] < close_at:
            tau, m = msgs[mi]; mi += 1
            {"C": svc.on_chunk, "B": svc.on_heartbeat, "M": svc.on_manifest}[m[0]](m, tau)
        for rt in [r for r in receipts_in_flight if r[0] <= close_at]:
            svc.on_receipt(*rt[1]); receipts_in_flight.remove(rt)
        settle = (t == W)
        if settle:  # settlement window: deliver every outstanding receipt first
            for rt in receipts_in_flight:
                svc.on_receipt(*rt[1])
            receipts_in_flight = []
        R, recs, pkg = svc.close(t, close_at, force_checkpoint=settle, settlement=settle)
        if repair is not None and not settle:
            reqs = svc.resend_requests()
            truth.setdefault("requests", []).append((t, len(reqs)))
            for (kind, i, s) in repair(rng, reqs, t, truth):   # requests cross the lossy link
                if kind == "RM":
                    m = ad[i].resend_manifest(s)
                else:
                    if emitted_at.get((i, s), float("inf")) > close_at:
                        continue  # virtual-time guard: a real adapter has not produced s yet
                    m = ad[i].resend(s)
                if m is not None:                               # ... and so do the resends
                    import bisect
                    bisect.insort(msgs, [close_at + 0.004 + rng.uniform(0, 0.002), m], key=lambda x: x[0])
        if handoff:
            pkg = handoff(rng, t, pkg, truth)
        refuse = custody.get("refuse", set()) if isinstance(custody, dict) else set()
        rt = store.accept(pkg, refuse=refuse)
        if not (isinstance(custody, dict) and rt[0] in custody.get("withhold", set())):
            receipts_in_flight.append((close_at + 0.05, rt))
    published = list(svc.published)
    if publish:
        published = publish(rng, published, svc, is_key, H, cfg, truth)
    if callable(custody):
        custody(rng, store, svc, truth)
    v = na.Verifier(cfg, H, is_key.public(), st_key.public(), svc.genesis, adapter_pubs=ad_pubs)
    t0 = time.perf_counter()
    now = audit_at if audit_at is not None else cfg.delta * (W + 1) + cfg.gamma + cfg.theta + 1e-6
    # the verifier reads receipts from the store's side: every receipt the store issued, including
    # those still in flight to the service when the mission ended (withheld ones were never issued)
    receipts = dict(svc.receipt_archive)
    for _, (t_r, q_r, bm_r) in receipts_in_flight:
        receipts.setdefault(t_r, (q_r, bm_r))
    verdict, absences, info = v.verify(published, receipts, store=store, now=now)
    vt = time.perf_counter() - t0
    return dict(verdict=verdict, absences=sorted(absences), info=info, verify_s=vt,
                roots=[p[2] for p in svc.published], svc=svc, store=store, truth=truth,
                resends=sum(x.resends for x in ad.values()),
                rec_bytes=sum(len(p[1]) for p in svc.published))

def telemetry_view(res):
    """Committed telemetry without custody fields (receipt signatures are stateful and differ
    between runs by design): tree root, leaf count, and records minus (K, r)."""
    out = []
    for (t, N, T, D), rec_enc, R, cp in res["svc"].published:
        recs = [r[:6] + r[8:11] + [[m[:5] for m in r[11]] if len(r) > 11 else []]
                for r in na._decode_records(rec_enc)]
        out.append((t, N, T, recs))
    return out

# ------------------------------------------------------------ helpers to pick targets
def chunk_msgs(msgs, lo=None, hi=None):
    return [k for k, (tau, m) in enumerate(msgs) if m[0] == "C"
            and (lo is None or tau >= lo) and (hi is None or tau < hi)]

def mid(cfg, W):
    return cfg.delta * 1, cfg.delta * (W - 2)

# ------------------------------------------------------------ scenarios
def S(name, position, attack, expect):
    return dict(name=name, position=position, attack=attack, expect=expect)

def sc_benign():
    return {}, lambda r, tr: ("COMPLETE", [])

def sc_retransmit():
    def link(rng, msgs, tr):
        out = list(msgs)
        for k in rng.sample(chunk_msgs(msgs), 5):
            tau, m = msgs[k]; out.append([tau + rng.uniform(0.01, 3.0), m])
        return sorted(out, key=lambda x: x[0])
    return {"link": link}, lambda r, tr: ("COMPLETE", [])

def sc_drop_chunk(cfg, W):
    def link(rng, msgs, tr):
        k = rng.choice(chunk_msgs(msgs, *mid(cfg, W))); m = msgs[k][1]
        tr["target"] = [(m[1], m[2], "IngestAbsent")]
        return [x for j, x in enumerate(msgs) if j != k]
    return {"link": link}, lambda r, tr: ("ACCOUNTED", tr["target"])

def sc_drop_burst(cfg, W):
    def link(rng, msgs, tr):
        ks = chunk_msgs(msgs, *mid(cfg, W)); start = rng.randrange(len(ks) - 10)
        drop = set(ks[start:start + rng.randint(2, 8)])
        tr["target"] = sorted((msgs[k][1][1], msgs[k][1][2], "IngestAbsent") for k in drop)
        return [x for j, x in enumerate(msgs) if j not in drop]
    return {"link": link}, lambda r, tr: ("ACCOUNTED", tr["target"])

def sc_silence(cfg, W):
    def link(rng, msgs, tr):
        i = rng.choice(list(SENSORS)); cut = rng.uniform(cfg.delta * 2, cfg.delta * (W - 1))
        return [x for x in msgs if not (x[1][1] == i and x[0] >= cut)]
    return {"link": link}, lambda r, tr: ("STALE", None)          # absence set not prescribed

def sc_modify(cfg, W):
    def link(rng, msgs, tr):
        out = [list(x) for x in msgs]
        k = rng.choice(chunk_msgs(msgs, *mid(cfg, W))); tau, m = out[k]
        c = bytearray(m[3]); c[rng.randrange(len(c))] ^= 1 << rng.randrange(8)
        out[k][1] = (m[0], m[1], m[2], bytes(c), m[4])
        tr["target"] = [(m[1], m[2], "IngestAuthFail")]
        return out
    return {"link": link}, lambda r, tr: ("ACCOUNTED", tr["target"])

def sc_inject(cfg, W):
    def link(rng, msgs, tr):
        out = list(msgs)
        for _ in range(10):
            tau = rng.uniform(0, cfg.delta * W); i = rng.choice(list(SENSORS))
            s = rng.randrange(0, 60)
            out.append([tau, ("C", i, s, rng.randbytes(64), rng.randbytes(32))])   # forged tag
            out.append([tau, ("B", i, 10**6, 10**6, rng.randbytes(32))])            # forged heartbeat
        return sorted(out, key=lambda x: x[0])
    return {"link": link}, lambda r, tr: ("COMPLETE", [])

def sc_replay(cfg, W):
    def link(rng, msgs, tr):
        out = list(msgs)
        for k in rng.sample(chunk_msgs(msgs, 0, cfg.delta * 3), 5):
            out.append([rng.uniform(cfg.delta * 4, cfg.delta * W), msgs[k][1]])
        return sorted(out, key=lambda x: x[0])
    return {"link": link}, lambda r, tr: ("COMPLETE", [])

def sc_reorder(cfg, W):
    def link(rng, msgs, tr):
        out = [list(x) for x in msgs]
        for t in range(W):   # permute delivery order inside each window, times unchanged
            ks = [k for k, (tau, m) in enumerate(msgs) if m[0] == "C"
                  and cfg.delta * t + 0.1 < tau < cfg.delta * (t + 1) - 0.1]
            perm = ks[:]; rng.shuffle(perm)
            ms = [msgs[k][1] for k in perm]
            for k, m in zip(ks, ms):
                out[k][1] = m
        return out
    return {"link": link}, lambda r, tr: ("COMPLETE", [])

def sc_late(cfg, W):
    def link(rng, msgs, tr):
        out = [list(x) for x in msgs]
        k = rng.choice(chunk_msgs(msgs, cfg.delta * 2, cfg.delta * (W - 3)))
        out[k][0] += cfg.delta * 1.2                                  # crosses a window boundary
        return sorted(out, key=lambda x: x[0])
    return {"link": link}, lambda r, tr: ("REPAIRED", [])

def _pub_mut(fn):
    return {"publish": fn}

def sc_pub_delete(cfg, W):
    def pub(rng, P, svc, key, H, cfg_, tr):
        j = rng.randrange(1, len(P) - 1); return P[:j] + P[j + 1:]
    return _pub_mut(pub), lambda r, tr: ("INVALID", None)

def sc_pub_insert(cfg, W):
    def pub(rng, P, svc, key, H, cfg_, tr):
        j = rng.randrange(1, len(P) - 1); fake = copy.deepcopy(P[j])
        return P[:j] + [fake] + P[j:]
    return _pub_mut(pub), lambda r, tr: ("INVALID", None)

def sc_pub_swap(cfg, W):
    def pub(rng, P, svc, key, H, cfg_, tr):
        j = rng.randrange(1, len(P) - 2); P = list(P); P[j], P[j + 1] = P[j + 1], P[j]; return P
    return _pub_mut(pub), lambda r, tr: ("INVALID", None)

def sc_pub_truncate(cfg, W):
    def pub(rng, P, svc, key, H, cfg_, tr):
        last_cp = max(j for j, p in enumerate(P[:-1]) if p[3] is not None)
        return P[:rng.randint(1, last_cp)]          # drop at least the final checkpoint(s)
    return _pub_mut(pub), lambda r, tr: ("WITHHELD", None)

def sc_pub_substitute(cfg, W):
    """Adversary rewrites a record (hides a gap) and recomputes every later root consistently."""
    def pub(rng, P, svc, key, H, cfg_, tr):
        P = [list(p) for p in P]; j = rng.randrange(1, len(P) - 1)
        recs = na._decode_records(P[j][1]); recs[0][9] += 1          # tweak heartbeat counter
        P[j][1] = na.enc(*[tuple(x) for x in recs])
        prev = svc.genesis
        for p in P:
            t, N, T, D = p[0]; D = H(b"\x02" + p[1]); p[0] = (t, N, T, D)
            p[2] = H(b"\x05" + na.enc(cfg_.epoch, t, N) + T + D + prev); prev = p[2]
        return [tuple(p) for p in P]                                   # old signatures kept
    return _pub_mut(pub), lambda r, tr: ("INVALID", None)

def sc_pub_forge_cp(cfg, W):
    def pub(rng, P, svc, key, H, cfg_, tr):
        P = [list(p) for p in P]
        j = rng.choice([k for k, p in enumerate(P) if p[3] is not None])
        P[j][3] = rng.randbytes(len(P[j][3])); return [tuple(p) for p in P]
    return _pub_mut(pub), lambda r, tr: ("INVALID", None)

def sc_receipt_withhold(cfg, W):
    t_target = {}
    def handoff(rng, t, pkg, tr):
        if "t" not in tr and 1 <= t < W - 1 and pkg[0][1] > 0:
            tr["t"] = t
            tr["target"] = sorted((i, s, "HandoffAbsent") for (pos, i, s, c, sib) in pkg[1])
        return pkg
    class Withhold(dict):
        pass
    cust = Withhold()
    def wrap_handoff(rng, t, pkg, tr):
        pkg = handoff(rng, t, pkg, tr)
        if tr.get("t") == t:
            cust["withhold"] = {t}
        return pkg
    return {"handoff": wrap_handoff, "custody": cust}, lambda r, tr: ("ACCOUNTED", tr["target"])

def sc_handoff_tamper(cfg, W):
    """Link between service and store corrupts one chunk; the store must refuse to receipt it."""
    def handoff(rng, t, pkg, tr):
        if "target" not in tr and 1 <= t < W - 1 and pkg[0][1] > 0:
            items = list(pkg[1]); k = rng.randrange(len(items))
            pos, i, s, c, sib = items[k]
            items[k] = (pos, i, s, bytes([c[0] ^ 1]) + c[1:], sib)
            tr["target"] = [(i, s, "HandoffAbsent")]
            return (pkg[0], items)
        return pkg
    return {"handoff": handoff}, lambda r, tr: ("ACCOUNTED", tr["target"])

def sc_store_delete(cfg, W):
    def custody(rng, store, svc, tr):
        key = rng.choice([k for k in store.data if k[0] < W]); i, s = store.data[key][:2]
        del store.data[key]; tr["target"] = [(i, s, "CustodyLoss")]
    return {"custody": custody}, lambda r, tr: ("ACCOUNTED", tr["target"])

def sc_store_substitute(cfg, W):
    def custody(rng, store, svc, tr):
        key = rng.choice([k for k in store.data if k[0] < W]); i, s, c, sib = store.data[key]
        store.data[key] = (i, s, rng.randbytes(len(c)), sib); tr["target"] = [(i, s, "CustodyLoss")]
    return {"custody": custody}, lambda r, tr: ("ACCOUNTED", tr["target"])

# ------------------------------------------------------------ repair scenarios
def _honest_repair(rng, reqs, attempt, tr):
    return reqs

def sc_repair_burst(cfg, W):
    """Burst loss on the link; the resend path is intact. Every gap must close."""
    kw, _ = sc_drop_burst(cfg, W)
    kw["repair"] = _honest_repair
    def expect(r, tr):
        return "REPAIRED", []
    return kw, expect

def sc_repair_modify(cfg, W):
    """A modified chunk is recorded as an auth failure; the authentic resend closes it."""
    kw, _ = sc_modify(cfg, W)
    kw["repair"] = _honest_repair
    return kw, lambda r, tr: ("REPAIRED", [])

def sc_repair_retry(cfg, W):
    """First resend of every gap is lost on the link too; the second attempt gets through."""
    kw, _ = sc_drop_burst(cfg, W)
    seen = set()
    def rep(rng, reqs, attempt, tr):
        out = []
        for q in reqs:
            if q[1:] in seen:
                out.append(q)
            else:
                seen.add(q[1:])
        return out
    kw["repair"] = rep
    return kw, lambda r, tr: ("REPAIRED", [])

def sc_repair_suppressed(cfg, W):
    """Adversary drops the chunks and every resend request: the gap stays accounted."""
    kw, exp = sc_drop_burst(cfg, W)
    kw["repair"] = lambda rng, reqs, attempt, tr: []
    return kw, exp

def sc_repair_forged_requests(cfg, W):
    """Adversary injects resend requests for chunks that were never lost."""
    def rep(rng, reqs, attempt, tr):
        return reqs + [("R", rng.choice(list(SENSORS)), rng.randrange(0, 40)) for _ in range(8)]
    return {"repair": rep}, lambda r, tr: ("COMPLETE", [])

# ------------------------------------------------------------ compromised integrity service
# The service holds the adapters' MAC keys and its own signing key. It drops a burst of
# chunks and tries to publish a history that verifies as COMPLETE.
def _drop_and(policy, cfg, W):
    def build(c, W_):
        kw, _ = sc_drop_burst(c, W_)
        def compromise(rng, svc, tr):
            if policy == "erase":
                def tamper(t, records):
                    out = []
                    for rec in records:
                        rec = list(rec)
                        i, a, b, miss, auth = rec[:5]
                        got = set(range(a, b + 1)) - set(miss) - set(auth)
                        # shrink the frontier to the highest received chunk; interior gaps
                        # cannot be hidden without breaking the tiling, so erase tail gaps only
                        nb = max([a - 1] + [x for x in got])
                        rec[2] = nb
                        rec[3] = [x for x in miss if x <= nb]; rec[4] = [x for x in auth if x <= nb]
                        rec[8] = min(rec[8], nb) if rec[8] >= 0 else rec[8]       # forged s_hat
                        out.append(tuple(rec))
                    return out
                svc.tamper = tamper
            elif policy == "fabricate":
                def pre_tree(t, recv, T_close):
                    recv = dict(recv)
                    for i, st in svc.sensors.items():
                        hb = [h for h in st.hbs if h[0] < T_close]
                        s_hat = hb[-1][1] if hb else -1
                        got = {s for (j, s) in recv if j == i}
                        lo = st.b + 1
                        for s in range(lo, s_hat + 1):
                            if s not in got and s not in st.unresolved:
                                recv[(i, s)] = rng.randbytes(64)       # invented content
                        for s in sorted(st.unresolved):
                            recv[(i, s)] = rng.randbytes(64)
                    return recv
                svc.pre_tree = pre_tree
            elif policy == "omit":
                def tamper(t, records):
                    out = []
                    for rec in records:
                        rec = list(rec)
                        gaps = set(rec[3]) | set(rec[4])
                        if len(rec) > 11:
                            rec[11] = [m for m in rec[11] if not any(s in gaps for (s, d) in m[4])]
                        rec[3] = []; rec[4] = []
                        i, a, b = rec[0], rec[1], rec[2]
                        got = set(range(a, b + 1)) - gaps
                        rec[2] = max([a - 1] + list(got))
                        out.append(tuple(rec))
                    return out
                svc.tamper = tamper
        kw["compromise"] = compromise
        return kw, None
    return build

def sc_cis_erase(cfg, W):
    kw, _ = _drop_and("erase", cfg, W)(cfg, W)
    # MAC-only declarations: the forged history verifies as COMPLETE (false completeness).
    # Signed declarations: the adapter's manifest still declares the dropped numbers.
    # Tail-only erasure: interior gaps cannot be erased without breaking the tiling, so this
    # concealment fails in both modes; the fabrication policy below is the one that succeeds.
    return kw, lambda r, tr: ("ACCOUNTED", None)

def sc_cis_fabricate(cfg, W):
    kw, _ = _drop_and("fabricate", cfg, W)(cfg, W)
    def expect(r, tr):
        return ("COMPLETE", None) if cfg.decl == "mac" else ("INVALID", None)
    return kw, expect

def sc_cis_omit(cfg, W):
    kw, _ = _drop_and("omit", cfg, W)(cfg, W)
    def expect(r, tr):
        if cfg.decl == "mac":
            return ("INVALID", None)   # erasing interior gaps breaks the tiling
        return ("WITHHELD", None)    # the manifest chain breaks
    return kw, expect

def sc_cis_hide_newest(cfg, W):
    """Compromised service presents an older complete prefix as the whole mission: it drops
    the final telemetry windows' manifests and chunks (publication truncation is caught by
    checkpoints; here the service re-signs a consistent shorter history)."""
    def compromise(rng, svc, tr):
        cut = {}
        def tamper(t, records):
            out = []
            for rec in records:
                rec = list(rec); i = rec[0]
                if t >= W - 2:
                    cut.setdefault(i, rec[1] - 1)
                    rec[1] = cut[i] + 1; rec[2] = cut[i]; rec[3] = []; rec[4] = []; rec[5] = []
                    rec[8] = cut[i]
                    if len(rec) > 11: rec[11] = []
                out.append(tuple(rec))
            return out
        def pre_tree(t, recv, T_close):
            return {} if t >= W - 2 else recv
        svc.tamper = tamper; svc.pre_tree = pre_tree
    def expect(r, tr):   # signed: STALE (newest windows carry no fresh declaration)
        return ("COMPLETE", None) if cfg.decl == "mac" else ("STALE", None)
    return {"compromise": compromise}, expect

def sc_dup_inflate(cfg, W):
    """Link duplicates many chunks; duplicates must add nothing (counts, leaves, verdict)."""
    def link(rng, msgs, tr):
        out = list(msgs)
        for k in rng.sample(chunk_msgs(msgs), 40):
            out.append([msgs[k][0] + rng.uniform(0.001, 0.5), msgs[k][1]])
        return sorted(out, key=lambda x: x[0])
    return {"link": link}, lambda r, tr: ("COMPLETE", [])

def sc_receipt_wrong_window(cfg, W):
    """Store returns a valid receipt but for the wrong window (replayed/misbound)."""
    def custody(rng, store, svc, tr):
        ts = sorted(t for t in svc.receipt_archive if 1 <= t < W - 1)
        a_, b_ = rng.sample(ts, 2)
        svc.receipt_archive[a_] = svc.receipt_archive[b_]
    return {"custody": custody}, lambda r, tr: ("ACCOUNTED", None)


def sc_cis_fake_gap_fabricate(cfg, W):
    """Compromised service records a 'missing' number far outside the window's interval and
    later commits a fabricated leaf for it as a 'late arrival' (review PoC)."""
    X = 2000
    def compromise(rng, svc, tr):
        def pre_tree(t, recv, T):
            if t == W: recv[(0, X)] = b"FABRICATED PAYLOAD"
            return recv
        def tamper(t, recs):
            out = []
            for r in recs:
                r = list(r)
                if r[0] == 0 and t == 0: r[3] = list(r[3]) + [X]
                if r[0] == 0 and t == W: r[5] = list(r[5]) + [X]
                out.append(tuple(r))
            return out
        svc.pre_tree, svc.tamper = pre_tree, tamper
    return {"compromise": compromise}, lambda r, tr: ("INVALID", None)

def sc_cis_fake_gap_duplicate(cfg, W):
    """Compromised service re-lists an already committed number as missing, then commits it
    again as a late arrival with other content (review PoC)."""
    def compromise(rng, svc, tr):
        def pre_tree(t, recv, T):
            if t == W: recv[(0, 5)] = b"DUPLICATE PAYLOAD"
            return recv
        def tamper(t, recs):
            out = []
            for r in recs:
                r = list(r)
                if r[0] == 0 and t == 1: r[3] = list(r[3]) + [5]
                if r[0] == 0 and t == W: r[5] = list(r[5]) + [5]
                out.append(tuple(r))
            return out
        svc.pre_tree, svc.tamper = pre_tree, tamper
    return {"compromise": compromise}, lambda r, tr: ("INVALID", None)

def sc_cis_forge_unreceipted(cfg, W):
    """The link drops the last chunk of sensor 0; it is resent in window W, whose receipt is not
    yet due at audit time. A compromised service forges the resent payload and withholds the
    receipt; the verifier must open the position anyway (review PoC)."""
    def link(rng, msgs, truth):
        idx = [k for k, (tau, m) in enumerate(msgs) if m[0] == "C" and m[1] == 0 and tau < W * cfg.delta - 1]
        return [x for k, x in enumerate(msgs) if k != idx[-1]]
    def compromise(rng, svc, tr):
        def pre(t, recv, T):
            if t == W:
                for key in recv: recv[key] = b"FORGED" + recv[key][6:]
            return recv
        svc.pre_tree = pre
    def expect(r, tr):
        return (None, None) if cfg.decl == "mac" else ("INVALID", None)
    return {"link": link, "repair": (lambda r, q, a, t: q), "compromise": compromise,
            "custody": {"withhold": {W}}}, expect

def sc_genesis_substitution(cfg, W):
    """Compromised service starts the chain from a genesis with adapter keys of its own."""
    def compromise(rng, svc, tr):
        g = svc.H(b"\x06" + b"service-chosen genesis")
        svc.prev = g; svc.genesis = g
    return {"compromise": compromise}, lambda r, tr: ("INVALID", None)

def sc_late_audit(cfg, W):
    """Honest history audited long after the epoch: must not be reported as withheld."""
    return {"audit_at": 1e7}, lambda r, tr: ("COMPLETE", [])

def _drop_one_manifest(cfg, W):
    def link(rng, msgs, tr):
        ks = [k for k, (tau, m) in enumerate(msgs) if m[0] == "M" and not m[5] and cfg.delta <= tau < cfg.delta * (W - 2)]
        k = rng.choice(ks); tr["target"] = (msgs[k][1][1], msgs[k][1][2])
        return [x for j, x in enumerate(msgs) if j != k]
    return link

def sc_manifest_drop_repair(cfg, W):
    """A manifest is lost on the link; the service re-requests it, holds the later ones until it
    arrives, and the honest history verifies."""
    if cfg.decl != "signed":
        return {}, lambda r, tr: ("COMPLETE", [])
    return {"link": _drop_one_manifest(cfg, W), "repair": _honest_repair}, lambda r, tr: ("COMPLETE", [])

def sc_manifest_drop_suppressed(cfg, W):
    """A manifest is lost and every request is suppressed: later manifests stay held, the
    declaration frontier stops, and the chunks beyond it are not source-confirmed."""
    if cfg.decl != "signed":
        return {}, lambda r, tr: ("COMPLETE", [])
    return ({"link": _drop_one_manifest(cfg, W), "repair": lambda rng, reqs, attempt, tr: []},
            lambda r, tr: ("STALE", None))

def sc_late_audit_aligned(cfg, W):
    """Shutdown checkpoint falls on a scheduled checkpoint window (11 windows, k = 6); audited
    long after the epoch, the history must not be reported as withheld."""
    return {"W": 2 * cfg.k - 1, "audit_at": 1e7}, lambda r, tr: ("COMPLETE", [])

def sc_checkpoint_pending(cfg, W):
    """Audit before the last scheduled checkpoint is due, with that checkpoint not yet published:
    the history is complete only as far as it goes."""
    Wa = 2 * cfg.k - 1
    def publish(rng, published, svc, is_key, H, cfg_, tr):
        out = list(published); h, rec, R, cp = out[-1]; out[-1] = (h, rec, R, None); return out
    return ({"W": Wa, "publish": publish, "audit_at": cfg.delta * (Wa + 1) + cfg.gamma + cfg.theta - 0.5},
            lambda r, tr: ("PREFIX", []))

def sc_aligned_ontime(cfg, W):
    """Shutdown on a scheduled checkpoint window, audited just after its deadline."""
    return {"W": 2 * cfg.k - 1}, lambda r, tr: ("COMPLETE", [])

def sc_aligned_end_withheld(cfg, W):
    """Shutdown on a scheduled checkpoint window; the shutdown checkpoint is withheld past its
    deadline."""
    def publish(rng, published, svc, is_key, H, cfg_, tr):
        out = list(published); h, rec, R, cp = out[-1]; out[-1] = (h, rec, R, None); return out
    return {"W": 2 * cfg.k - 1, "publish": publish}, lambda r, tr: ("WITHHELD", None)

def sc_cis_early_end(cfg, W):
    """Compromised service signs an end checkpoint in mid-history and keeps publishing, to stop
    the verifier's schedule early."""
    def publish(rng, published, svc, is_key, H, cfg_, tr):
        out = list(published); j = cfg_.k - 1
        (t, N, T, D), rec, R, cp = out[j]
        out[j] = ((t, N, T, D), rec, R, is_key.sign(H(b"\x07" + na.enc(cfg_.epoch, t, True) + R)))
        return out
    return {"publish": publish}, lambda r, tr: ("INVALID", None)

def sc_receipt_short_bitmap(cfg, W):
    """Store signs a receipt whose bitmap is shorter than ceil(N/8) bytes: the receipt
    acknowledges nothing, so that window's positions are attributed to the handoff; the
    history itself is not invalid."""
    def custody(rng, store, svc, tr):
        cand = [p for p in svc.published if 1 <= p[0][0] < W - 1 and p[0][1] > 8]
        (t, N, T, D) = rng.choice(cand)[0]
        bm = b"\xff" * ((N + 7) // 8 - 1)
        q = store.signer.sign(na.enc("rcpt", cfg.epoch, t, N) + T + bm)
        svc.receipt_archive[t] = (q, bm)
    return {"custody": custody}, lambda r, tr: ("ACCOUNTED", None)

SCENARIOS = [
    ("benign", "none", lambda c, W: sc_benign()),
    ("retransmit", "none", lambda c, W: sc_retransmit()),
    ("drop-chunk", "link", sc_drop_chunk),
    ("drop-burst", "link", sc_drop_burst),
    ("silence-chunks+heartbeats", "link", sc_silence),
    ("modify-payload", "link", sc_modify),
    ("inject-forged-chunks+heartbeats", "link", sc_inject),
    ("replay-old-chunks", "link", sc_replay),
    ("reorder-within-window", "link", sc_reorder),
    ("delay-across-window", "link", sc_late),
    ("delete-window", "publication", sc_pub_delete),
    ("insert-window", "publication", sc_pub_insert),
    ("swap-windows", "publication", sc_pub_swap),
    ("truncate-tail", "publication", sc_pub_truncate),
    ("substitute-record+recompute-chain", "publication", sc_pub_substitute),
    ("forge-checkpoint", "publication", sc_pub_forge_cp),
    ("withhold-receipt", "custody", sc_receipt_withhold),
    ("tamper-handoff", "custody", sc_handoff_tamper),
    ("delete-stored-chunk", "custody", sc_store_delete),
    ("substitute-stored-chunk", "custody", sc_store_substitute),
    ("drop-burst+repair", "link", sc_repair_burst),
    ("modify-payload+repair", "link", sc_repair_modify),
    ("drop-burst+repair-after-retry", "link", sc_repair_retry),
    ("drop-burst+requests-suppressed", "link", sc_repair_suppressed),
    ("forged-resend-requests", "link", sc_repair_forged_requests),
    ("compromised-IS: erase gaps + re-sign", "service", sc_cis_erase),
    ("compromised-IS: fabricate chunks", "service", sc_cis_fabricate),
    ("compromised-IS: omit manifests", "service", sc_cis_omit),
    ("compromised-IS: hide newest blocks", "service", sc_cis_hide_newest),
    ("duplicate-inflation", "link", sc_dup_inflate),
    ("receipt-bound-to-wrong-window", "custody", sc_receipt_wrong_window),
    ("compromised-IS: fake gap then fabricated late leaf", "service", sc_cis_fake_gap_fabricate),
    ("compromised-IS: fake gap then duplicate leaf", "service", sc_cis_fake_gap_duplicate),
    ("compromised-IS: forge unreceipted last window", "service", sc_cis_forge_unreceipted),
    ("compromised-IS: substitute genesis", "service", sc_genesis_substitution),
    ("honest history, late audit", "none", sc_late_audit),
    ("honest history, late audit, shutdown on a scheduled checkpoint", "none", sc_late_audit_aligned),
    ("checkpoint not yet due at audit", "publication", sc_checkpoint_pending),
    ("drop-manifest+repair", "link", sc_manifest_drop_repair),
    ("drop-manifest+requests-suppressed", "link", sc_manifest_drop_suppressed),
    ("honest history, shutdown on a scheduled checkpoint, on-time audit", "none", sc_aligned_ontime),
    ("shutdown checkpoint on a scheduled window withheld", "publication", sc_aligned_end_withheld),
    ("compromised-IS: end checkpoint in mid-history", "service", sc_cis_early_end),
    ("receipt with a short bitmap", "custody", sc_receipt_short_bitmap),
]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=100)
    ap.add_argument("--windows", type=int, default=12, help="telemetry windows per mission")
    ap.add_argument("--leaf", type=int, default=8192)
    ap.add_argument("--hash", default="shake128")
    ap.add_argument("--mac", default="kmac128")
    ap.add_argument("--xmss", default="XMSS-SHAKE256_10_256")
    ap.add_argument("--only", default=None)
    ap.add_argument("--decl", default="signed", choices=["signed", "mac"])
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    cfg = na.Config(hash=a.hash, mac=a.mac, sig=a.xmss, decl=a.decl)
    H = na.hash_backends()[a.hash]; mac = na.mac_backends()[a.mac]
    keys = Keys(a.xmss)
    rows, failures = [], []
    for name, pos, build in SCENARIOS:
        if a.only and a.only not in name:
            continue
        passed, vts, verdicts = 0, [], {}
        for trial in range(a.trials):
            rng = random.Random(f"{a.seed}-{name}-{trial}")
            kw, expect = build(cfg, a.windows)
            Wm = kw.pop("W", a.windows)
            res = mission(rng, cfg, H, mac, keys, Wm, a.leaf, **kw)
            ev, eabs = expect(rng, res["truth"])
            if ev is None:
                ok = res["verdict"] != "COMPLETE"
            else:
                ok = res["verdict"] == ev and (eabs is None or res["absences"] == sorted(eabs))
            if name in ("drop-burst+repair", "modify-payload+repair", "drop-burst+repair-after-retry"):
                tr_target = res["truth"]["target"]
                rep = [(i, s_, c) for (i, s_, c, t_) in res["info"].get("repairs", [])]
                ok = ok and sorted(rep) == sorted(tr_target)
            if name in ("reorder-within-window", "replay-old-chunks", "retransmit",
                        "forged-resend-requests", "duplicate-inflation"):
                base = mission(random.Random(f"{a.seed}-{name}-{trial}"), cfg, H, mac, keys,
                               a.windows, a.leaf)       # same seed, no attack
                ok = ok and telemetry_view(base) == telemetry_view(res)
            passed += ok; vts.append(res["verify_s"])
            verdicts[res["verdict"]] = verdicts.get(res["verdict"], 0) + 1
            if not ok and len(failures) < 50:
                failures.append(dict(scenario=name, trial=trial, got=res["verdict"],
                                     expect=ev, info=res["info"], absences=res["absences"][:10],
                                     expected_abs=(sorted(eabs)[:10] if eabs else None)))
        row = dict(scenario=name, position=pos, trials=a.trials, passed=passed,
                   verdicts=json.dumps(verdicts),
                   verify_ms_median=round(1e3 * statistics.median(vts), 2),
                   verify_ms_p95=round(1e3 * sorted(vts)[int(0.95 * (len(vts) - 1))], 2))
        rows.append(row)
        print(f"{name:36s} {pos:12s} {passed:4d}/{a.trials}  {row['verdicts']}  verify {row['verify_ms_median']} ms", flush=True)
    tag = os.uname().nodename + ("" if a.decl == "signed" else "_macdecl")
    with open(os.path.join(a.out, f"attacks_{tag}.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    with open(os.path.join(a.out, f"attacks_{tag}_failures.json"), "w") as f:
        json.dump(dict(failures=failures, keygen_s=keys.keygen_s, args=vars(a)), f, indent=1, default=str)
    print(f"wrote {a.out}/attacks_{tag}.csv  (failures: {len(failures)})")

if __name__ == "__main__":
    main()
