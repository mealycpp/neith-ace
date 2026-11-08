#!/usr/bin/env python3
"""NEITH-ACE cost microbenchmarks for the overhead model (manuscript Sec. 6, Eq. work/emit/rate).

Measures on the node it runs on:
  c_H(L)      per-leaf hash cost, every backend incl. native vs Python Ascon-XOF128
  throughput  leaf hashing with P parallel processes (P = 1, 2, 4)
  c_MAC(L)    tag verification: KMAC128, keyed Ascon-CXOF128, HMAC-SHA256
  c_n, c_rho, c_root   node, record, and root hashing
  XMSS        keygen / sign / verify / signature size for SHAKE256 heights
"""
import argparse, json, multiprocessing as mp, os, platform, statistics, sys, time
import neith_ace as na

def timeit(fn, reps, warm=2):
    for _ in range(warm):
        fn()
    ts = []
    for _ in range(reps):
        t0 = time.perf_counter(); fn(); ts.append(time.perf_counter() - t0)
    return dict(median_us=round(1e6 * statistics.median(ts), 2),
                p95_us=round(1e6 * sorted(ts)[int(0.95 * (len(ts) - 1))], 2),
                min_us=round(1e6 * min(ts), 2), reps=reps)

def _worker(args):
    name, L, n = args
    H = na.hash_backends()[name]; d = os.urandom(L)
    t0 = time.perf_counter()
    for _ in range(n):
        H(b"\x00" + d)
    return time.perf_counter() - t0

def parallel_tput(name, L, P, n_per):
    with mp.Pool(P) as pool:
        pool.map(_worker, [(name, L, 2)] * P)          # warm
        t0 = time.perf_counter()
        pool.map(_worker, [(name, L, n_per)] * P)
        wall = time.perf_counter() - t0
    return round(P * n_per * L / wall / 1e6, 3)          # MB/s

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--leaf", type=int, nargs="+", default=[8192])
    ap.add_argument("--reps", type=int, default=200)
    ap.add_argument("--py-reps", type=int, default=5, help="reps for pure-Python Ascon (slow)")
    ap.add_argument("--xmss-h", type=int, nargs="+", default=[10, 16])
    ap.add_argument("--xmss-sign-reps", type=int, default=100)
    ap.add_argument("--procs", type=int, nargs="+", default=[1, 2, 4])
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    host = os.uname().nodename
    res = dict(host=host, machine=platform.machine(), python=platform.python_version(),
               cpu_count=os.cpu_count(), uname=" ".join(os.uname()), hash={}, mac={}, xmss={},
               parallel={}, structure={})
    try:
        res["cpu_model"] = [l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo")
                            if l.lower().startswith(("model name", "hardware", "model"))][:2]
    except OSError:
        pass
    hb, mb = na.hash_backends(), na.mac_backends()
    for L in a.leaf:
        d = os.urandom(L)
        for name, H in sorted(hb.items()):
            reps = a.py_reps if name.endswith("python") else a.reps
            r = timeit(lambda: H(b"\x00" + d), reps, warm=1 if name.endswith("python") else 2)
            r["MBps"] = round(L / (r["median_us"] / 1e6) / 1e6, 3)
            res["hash"][f"{name}@{L}"] = r
            print(f"hash  {name:24s} L={L:6d}  {r['median_us']:12.1f} us  {r['MBps']:9.3f} MB/s", flush=True)
        key = os.urandom(16)
        for name, M in sorted(mb.items()):
            r = timeit(lambda: M(key, b"\x01" * 40 + d), a.reps)
            res["mac"][f"{name}@{L}"] = r
            print(f"mac   {name:24s} L={L:6d}  {r['median_us']:12.1f} us", flush=True)
        for name in [n for n in hb if not n.endswith("python")]:
            for P in a.procs:
                if P > (os.cpu_count() or 1):
                    continue
                n_per = max(20, int(2e6 / L))
                res["parallel"][f"{name}@{L}@P{P}"] = parallel_tput(name, L, P, n_per)
                print(f"par   {name:24s} L={L:6d} P={P}  {res['parallel'][f'{name}@{L}@P{P}']} MB/s", flush=True)
    # structure costs with the default instantiation and every native hash
    for name, H in sorted(hb.items()):
        if name.endswith("python"):
            continue
        a32, b32 = os.urandom(32), os.urandom(32)
        rec = (0, 120, 175, [130, 131], [], [118], [(3, s) for s in range(60)], a32, 175, 900, False)
        res["structure"][name] = dict(
            node=timeit(lambda: H(b"\x01" + a32 + b32), a.reps),
            record_m2=timeit(lambda: H(b"\x02" + na.enc(rec, rec)), a.reps),
            root=timeit(lambda: H(b"\x05" + na.enc(1, 42, 70) + a32 + b32 + a32), a.reps),
            tree_N70=timeit(lambda: na.tree(H, [a32] * 70), max(20, a.reps // 10)))
    for h in a.xmss_h:
        param = f"XMSS-SHAKE256_{h}_256"
        print(f"xmss  {param}: keygen ...", flush=True)
        state = os.path.join(a.out, f".xmss_state_h{h}")
        k = na.XMSS(param, state_path=state)   # sign() includes the fsync of the state
        msg = os.urandom(32)
        n = min(a.xmss_sign_reps, 2 ** h - 8)
        sig_t, ver_t, sig = [], [], None
        for _ in range(n):
            t0 = time.perf_counter(); sig = k.sign(msg); sig_t.append(time.perf_counter() - t0)
        for _ in range(min(n, 50)):
            t0 = time.perf_counter(); ok = na.xmss_verify(k.public(), sig, msg); ver_t.append(time.perf_counter() - t0)
            assert ok
        res["xmss"][param] = dict(keygen_s=round(k.keygen_s, 3), sig_bytes=len(sig), pk_bytes=k.pk_len,
                                  sk_bytes=k.sk_len,
                                  sign_ms_median=round(1e3 * statistics.median(sig_t), 3),
                                  sign_ms_p95=round(1e3 * sorted(sig_t)[int(0.95 * (n - 1))], 3),
                                  sign_ms_max=round(1e3 * max(sig_t), 3),
                                  verify_ms_median=round(1e3 * statistics.median(ver_t), 3),
                                  sign_reps=n)
        print(f"xmss  {param}: {res['xmss'][param]}", flush=True)
        for f in (state, state + ".tmp"):
            if os.path.exists(f): os.remove(f)
    out = os.path.join(a.out, f"bench_{host}.json")
    json.dump(res, open(out, "w"), indent=1)
    print("wrote", out)

if __name__ == "__main__":
    main()
