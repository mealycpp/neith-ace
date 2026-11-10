#!/usr/bin/env python3
"""Measured capacity of the NEITH-ACE reference pipeline (no model, no extrapolation).

For each offered chunk rate, runs the real live pipeline on this machine: `live.py serve`
(integrity service + local fsync'd store + verifier) and S `live.py adapter` processes with
constant-rate producers of L-byte chunks, signed manifests, and every window a checkpoint
window (k = 1, the worst case for the signing term). A rate PASSES when, over the whole run,

  1. the verifier returns COMPLETE (nothing lost, nothing unaccounted),
  2. every window meets the no-stutter rule E_t - T_t <= Delta, and
  3. the adapters actually delivered >= 95% of the offered rate (no hidden back-pressure).

The capacity is the highest delivered rate that passes. Rates are swept upward by doubling until
the first failure, then bisected. Everything runs on one node, so adapters, service, and store
share its cores: the result is a measured lower bound on what the service alone sustains.

  python3 capacity.py                    # full sweep (about 20-30 min on a Pi 4)
  python3 capacity.py --rates 500,1000   # specific rates only
Output: results/capacity_<host>_<time>/{capacity.csv, capacity.json, runs/...}
"""
import argparse, csv, glob, json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
LIVE = os.path.join(HERE, "live.py")

def mem_available_mb():
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except OSError:
        pass
    return None

def run_rate(a, rate, port, outroot):
    tag = f"r{int(rate):06d}_{time.strftime('%H%M%S')}"
    out = os.path.join(outroot, "runs", tag); os.makedirs(out, exist_ok=True)
    common = ["--delta-h", str(a.delta_h), "--mac", a.mac, "--hash", a.hash,
              "--decl", "signed", "--delta-m", str(a.delta), "--secret", "capacity"]
    serve = [sys.executable, LIVE, "serve", "--port", str(port), "--windows", str(a.windows),
             "--sensors", str(a.sensors), "--delta", str(a.delta), "--gamma", str(a.gamma),
             "--k", "1", "--theta-st", str(a.theta_st), "--xmss", a.xmss, "--warmup", str(a.warmup),
             "--repair", "1", "--out", out] + common
    logs = []
    f = open(os.path.join(out, "serve.log"), "w"); logs.append(f)
    sp = subprocess.Popen(serve, stdout=f, stderr=subprocess.STDOUT, cwd=HERE)
    per = rate / a.sensors
    aps = []
    for i in range(a.sensors):
        cmd = [sys.executable, LIVE, "adapter", "--connect", f"127.0.0.1:{port}", "--id", str(i),
               "--source", f"paced:{per}:{a.chunk}", "--max-chunk", str(a.chunk), "--xmss", a.xmss,
               "--out", out] + common
        g = open(os.path.join(out, f"adapter{i}.log"), "w"); logs.append(g)
        aps.append(subprocess.Popen(cmd, stdout=g, stderr=subprocess.STDOUT, cwd=HERE))
    timeout = a.warmup + 60 + (a.windows + 3) * a.delta + a.theta_st + 600
    try:
        sp.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        sp.kill()
    for p in aps:
        try: p.wait(timeout=60)
        except subprocess.TimeoutExpired: p.kill()
    for x in logs: x.close()
    res = dict(offered_rate=rate, run=tag)
    runs = glob.glob(os.path.join(out, "live_*", "summary.json"))
    if not runs:
        res.update(passed=False, reason="service did not finish (see serve.log)"); return res
    summ = json.load(open(runs[0]))
    rows = list(csv.DictReader(open(os.path.join(os.path.dirname(runs[0]), "windows.csv"))))
    tele = [r for r in rows if r["phase"] == "telemetry"]
    ads = [json.load(open(p)) for p in glob.glob(os.path.join(out, "adapter*_*.json"))]
    delivered = sum(d["achieved_rate"] or 0 for d in ads)
    emit = [float(r["emit_latency_s"]) for r in rows]
    comp = [float(r["compute_s"]) for r in rows]
    res.update(delivered_rate=round(delivered, 1), adapters_reported=len(ads),
               chunks=sum(d["chunks"] for d in ads),
               committed_telemetry=sum(int(r["N"]) for r in tele),
               max_emit_latency_s=round(max(emit), 4), max_compute_s=round(max(comp), 4),
               median_compute_s=round(sorted(comp)[len(comp) // 2], 4),
               verdict=summ["verdict"], n_absences=summ["n_absences"],
               verify_s=round(summ["verify_s"], 3), mem_available_mb=mem_available_mb())
    fails = []
    if summ["verdict"] != "COMPLETE": fails.append(f"verdict {summ['verdict']}")
    if max(emit) > a.delta: fails.append(f"no-stutter violated (E-T max {max(emit):.2f}s)")
    if len(ads) < a.sensors: fails.append("adapter summary missing")
    if delivered < 0.95 * rate: fails.append(f"delivered {delivered:.0f} < 95% of offered")
    res.update(passed=not fails, reason="; ".join(fails) or "ok")
    return res

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rates", default=None, help="comma-separated offered rates (chunks/s); default: sweep")
    ap.add_argument("--start", type=float, default=100.0); ap.add_argument("--max-rate", type=float, default=20000.0)
    ap.add_argument("--precision", type=float, default=0.05, help="bisection stops at this relative gap")
    ap.add_argument("--sensors", type=int, default=2); ap.add_argument("--chunk", type=int, default=8192)
    ap.add_argument("--windows", type=int, default=4, help="telemetry windows per run")
    ap.add_argument("--delta", type=float, default=10.0); ap.add_argument("--gamma", type=float, default=0.5)
    ap.add_argument("--delta-h", type=float, default=1.0); ap.add_argument("--theta-st", type=float, default=10.0)
    ap.add_argument("--warmup", type=float, default=15.0, help="time for adapters' XMSS keygen")
    ap.add_argument("--hash", default="shake128"); ap.add_argument("--mac", default="kmac128")
    ap.add_argument("--xmss", default="XMSS-SHAKE256_10_256"); ap.add_argument("--port", type=int, default=7800)
    ap.add_argument("--mem-frac", type=float, default=0.6, help="skip a rate whose chunks would exceed this share of free RAM")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    host = os.uname().nodename
    outroot = os.path.join(HERE, a.out, f"capacity_{host}_{time.strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(outroot, exist_ok=True)
    results, port = [], a.port

    def fits(rate):
        need = rate * (a.windows + 2) * a.delta * a.chunk * 3 / 2**20   # store + service + queue copies
        free = mem_available_mb()
        return free is None or need <= a.mem_frac * free, need, free

    def trial(rate):
        nonlocal port
        ok, need, free = fits(rate)
        if not ok:
            r = dict(offered_rate=rate, passed=None, reason=f"skipped: needs ~{need:.0f} MB, {free} MB free")
        else:
            print(f"\n=== offered {rate:.0f} chunks/s ({a.sensors} adapters, {a.chunk} B chunks) ===", flush=True)
            r = run_rate(a, rate, port, outroot); port += 1
        print(json.dumps(r), flush=True); results.append(r); save(); return r

    def save():
        keys = sorted({k for r in results for k in r})
        with open(os.path.join(outroot, "capacity.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(results)
        passed = [r for r in results if r.get("passed")]
        best = max(passed, key=lambda r: r["delivered_rate"]) if passed else None
        json.dump(dict(host=host, machine=os.uname().machine, cpu_count=os.cpu_count(),
                       config=vars(a), capacity_chunks_per_s=best["delivered_rate"] if best else None,
                       capacity_MBps=round(best["delivered_rate"] * a.chunk / 1e6, 2) if best else None,
                       best_run=best, runs=results),
                  open(os.path.join(outroot, "capacity.json"), "w"), indent=1)

    if a.rates:
        for x in a.rates.split(","): trial(float(x))
    else:
        lo, hi, rate = None, None, a.start
        while rate <= a.max_rate:
            r = trial(rate)
            if r["passed"]: lo = rate; rate *= 2
            else: hi = rate; break
        while lo and hi and (hi - lo) / lo > a.precision:
            mid = round((lo + hi) / 2)
            r = trial(mid)
            if r["passed"]: lo = mid
            else: hi = mid
    save()
    best = json.load(open(os.path.join(outroot, "capacity.json")))
    print(f"\nMEASURED CAPACITY on {host}: {best['capacity_chunks_per_s']} chunks/s "
          f"({best['capacity_MBps']} MB/s of {a.chunk}-byte chunks), every window k=1 signed, "
          f"verdict COMPLETE, no-stutter held.\n-> {outroot}")

if __name__ == "__main__":
    main()
