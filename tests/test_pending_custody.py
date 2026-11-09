"""A committed position whose receipt is not yet due must keep the verdict at PREFIX, even when
the store can already produce the chunk; once the receipt deadline passes without a receipt,
the position is HandoffAbsent. Run from the repository root: python3 tests/test_pending_custody.py"""
import os, sys, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import neith_ace as na, attacks as at

def main():
    for decl in ("signed", "mac"):
        cfg = na.Config(decl=decl); H = na.hash_backends()["shake128"]; mac = na.mac_backends()["kmac128"]
        keys = at.Keys("XMSS-SHAKE256_10_256"); W = 12
        r = at.mission(random.Random("2026-pending-custody"), cfg, H, mac, keys, W, 8192)
        svc, store = r["svc"], r["store"]
        pub = list(svc.published); t_last = W - 1
        rec = {t: v for t, v in svc.receipt_archive.items() if t != t_last}
        v = na.Verifier(cfg, H, keys.is_key.public(), keys.st_key.public(), svc.genesis,
                        adapter_pubs={i: keys.ad_keys[i].public() for i in at.SENSORS} if decl == "signed" else {})
        early = cfg.delta * (t_last + 1) + cfg.theta_st - 1.0      # receipt of t_last not yet due
        late = cfg.delta * (t_last + 1) + cfg.theta_st + 1.0       # now overdue
        a = v.verify(pub, rec, store=store, now=early)[0]
        b, absn, _ = v.verify(pub, rec, store=store, now=late)
        ok = a == "PREFIX" and b == "ACCOUNTED" and all(x[2] == "HandoffAbsent" for x in absn)
        print(f"{decl:6s} before deadline: {a:8s} after: {b:9s} ({len(absn)} HandoffAbsent)  {'PASS' if ok else 'FAIL'}")
        assert ok

if __name__ == "__main__":
    main()
