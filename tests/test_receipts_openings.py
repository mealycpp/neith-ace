"""Receipt canonicalization and store openings.
1. A store-signed receipt whose last bitmap byte has bits set beyond position N-1 acknowledges
   nothing: that window's positions are attributed to the handoff (ACCOUNTED), never INVALID.
2. An opening the store supplies but that fails verification (altered payload) is reported as
   altered and attributed to custody (CustodyLoss), not INVALID, and distinct from a chunk the
   store cannot supply at all (CustodyLoss, not altered).
3. Every committed position is enumerated: deleting one chunk the store never mentions is found.
Run from the repository root: python3 tests/test_receipts_openings.py"""
import os, sys, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import neith_ace as na, attacks as at

def verifier(cfg, keys, svc, decl):
    return na.Verifier(cfg, na.hash_backends()["shake128"], keys.is_key.public(), keys.st_key.public(), svc.genesis,
                       adapter_pubs={i: keys.ad_keys[i].public() for i in at.SENSORS} if decl == "signed" else {})

def main():
    for decl in ("signed", "mac"):
        cfg = na.Config(decl=decl); H = na.hash_backends()["shake128"]; mac = na.mac_backends()["kmac128"]
        keys = at.Keys("XMSS-SHAKE256_10_256"); W = 12
        r = at.mission(random.Random("2026-receipts-openings"), cfg, H, mac, keys, W, 8192)
        svc, store = r["svc"], r["store"]; pub = list(svc.published)
        v = verifier(cfg, keys, svc, decl)
        base = v.verify(pub, dict(svc.receipt_archive), store=store)[0]
        # 1. non-canonical bitmap
        cand = [p[0] for p in pub if 1 <= p[0][0] < W - 1 and p[0][1] % 8 != 0 and p[0][0] in svc.receipt_archive]
        (t, N, T, D) = cand[0]
        bm = bytearray((1 << 8) - 1 for _ in range((N + 7) // 8)); bm[-1] = 0xFF   # padding bits set
        q = store.signer.sign(na.enc("rcpt", cfg.epoch, t, N) + T + bytes(bm))
        rec = dict(svc.receipt_archive); rec[t] = (q, bytes(bm))
        v1, a1, _ = v.verify(pub, rec, store=store)
        ok1 = v1 == "ACCOUNTED" and a1 and all(c == "HandoffAbsent" for _, _, c in a1)
        # 2./3. altered and missing chunks in another receipted window
        (t2, N2, _, _) = [p[0] for p in pub if 1 <= p[0][0] < W - 1 and p[0][1] >= 2 and p[0][0] != t][0]
        e0 = store.data[(t2, 0)]; i0, s0, c0 = e0[0], e0[1], e0[2]
        store.data[(t2, 0)] = (i0, s0, bytes(len(c0))) + tuple(e0[3:])  # altered payload
        miss = store.data.pop((t2, 1))                                   # unavailable chunk
        v2, a2, info2 = v.verify(pub, dict(svc.receipt_archive), store=store)
        cls = {(i, s): c for i, s, c in a2}
        ok2 = (v2 == "ACCOUNTED" and cls.get((i0, s0)) == "CustodyLoss" and cls.get(miss[:2]) == "CustodyLoss"
               and info2.get("altered") == [(i0, s0)])
        print(f"{decl:6s} baseline {base}; padding bits -> {v1} ({len(a1)} HandoffAbsent) {'PASS' if ok1 else 'FAIL'}; "
              f"altered+missing -> {v2}, altered={info2.get('altered')} {'PASS' if ok2 else 'FAIL'}")
        assert ok1 and ok2

if __name__ == "__main__":
    main()
