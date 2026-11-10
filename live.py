#!/usr/bin/env python3
"""NEITH-ACE live pipeline over TCP (real time, real sensors or synthetic producers).

  serve    integrity service + chunk store (separate process, fsync'd) + verifier at the end
  adapter  capture adapter: reads a sensor source, tags chunks, sends heartbeats

Sources for `adapter --source`:
  serial:/dev/ttyACM0        one chunk per line (NMEA etc.); configure the port with stty first
  serialblock:/dev/ttyUSB0:N one chunk per N raw bytes (binary LiDAR streams)
  stdin                      one chunk per line from a pipe:  my_reader | live.py adapter --source stdin
  synth:RATE_HZ:BYTES        synthetic producer (bursty, mean rate RATE_HZ)
  paced:RATE_HZ:BYTES        synthetic producer at a constant rate (capacity measurement)

Adapter key K_i = SHAKE256(secret || "adapter" || i)[:16]; pass the same --secret to every process.
Measured per window: E_t - T_t (root emission latency), service compute time, N_t, gaps,
receipt latency (receipt arrival - T_t), checkpoint signing time.
"""
import argparse, csv, hashlib, json, multiprocessing as mp, os, queue, random, select, socket
import struct, sys, threading, time
import neith_ace as na

def adapter_key(secret, i):
    return hashlib.shake_256(secret.encode() + b"adapter" + struct.pack(">I", i)).digest(16)

# ---------------------------------------------------------------- wire format
# frame: >B type, >I len, body.  C: >H i >Q s, 32B tag, payload.   B: >H i >q s_hat >Q u, 32B tag
def send_frame(sock, m):
    if m[0] == "C":
        _, i, s, c, tag = m; body = struct.pack(">HQ", i, s) + tag + c; ty = 1
    elif m[0] == "B":
        _, i, sh, u, tag = m; body = struct.pack(">HqQ", i, sh, u) + tag; ty = 2
    elif m[0] == "M":                       # signed manifest
        body = na.enc(*m[1:]); ty = 3
    elif m[0] in ("R", "RM"):               # resend request (service -> adapter)
        body = na.enc(*m); ty = 4
    elif m[0] == "HELLO":                   # adapter identity + XMSS public key
        body = na.enc(*m[1:]); ty = 5
    else:
        raise ValueError(m[0])
    sock.sendall(struct.pack(">BI", ty, len(body)) + body)

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        x = sock.recv(n - len(buf))
        if not x:
            raise ConnectionError
        buf += x
    return buf

def parse(ty, body):
    if ty == 1:
        i, s = struct.unpack_from(">HQ", body); return ("C", i, s, body[42:], body[10:42])
    if ty == 2:
        i, sh, u = struct.unpack_from(">HqQ", body); return ("B", i, sh, u, body[18:50])
    if ty == 3:
        i, v, s_hat, m_prev, final, items, sig = na._decode_records(body)
        return ("M", i, v, s_hat, bytes(m_prev), bool(final), [(x[0], bytes(x[1])) for x in items], bytes(sig))
    if ty == 4:
        return tuple(na._decode_records(body))
    if ty == 5:
        i, param, pk = na._decode_records(body); return ("HELLO", i, param, bytes(pk))
    raise ValueError(ty)

# ---------------------------------------------------------------- store process
def store_proc(cfg_d, hash_name, xmss_param, inq, outq, store_dir):
    cfg = na.Config(**cfg_d); H = na.hash_backends()[hash_name]
    st_key = na.XMSS(xmss_param, state_path=os.path.join(store_dir, "store_xmss.state"))
    outq.put(("pub", st_key.public()))
    store = na.Store(cfg, H, st_key)
    while True:
        msg = inq.get()
        if msg is None:
            break
        if msg == "dump":
            outq.put(("dump", store.data)); continue
        pkg = msg
        t = pkg[0][0]
        t0 = time.time()
        q = store.accept(pkg)
        with open(os.path.join(store_dir, f"w{t:05d}.bin"), "wb") as f:   # durable persistence
            for (pos, i, s, c, sib) in pkg[1]:
                f.write(struct.pack(">IHQI", pos, i, s, len(c)) + c)
            f.flush(); os.fsync(f.fileno())
        outq.put(("rcpt", q, time.time() - t0))


# ---------------------------------------------------------------- remote store / verifier (SOBEK)
# frames: >B type, >I len, enc(...) payload
PKG, RCPT, PUB_REQ, PUB, EVID, VERDICT = 10, 11, 12, 13, 14, 15

def send_obj(sock, ty, *fields):
    body = na.enc(*fields); sock.sendall(struct.pack(">BI", ty, len(body)) + body)

def recv_obj(sock):
    ty, n = struct.unpack(">BI", recv_exact(sock, 5))
    return ty, na._decode_records(recv_exact(sock, n))

def store_server(a):
    """Untrusted chunk store with its own XMSS receipt key, plus the external verifier."""
    os.makedirs(a.out, exist_ok=True)
    run_dir = os.path.join(a.out, f"store_{os.uname().nodename}_{time.strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(os.path.join(run_dir, "chunks"), exist_ok=True)
    print(f"[store] XMSS keygen ({a.xmss}) ...", flush=True)
    key = na.XMSS(a.xmss, state_path=os.path.join(run_dir, "store_xmss.state"))
    print(f"[store] keygen {key.keygen_s:.1f}s; listening on :{a.port}", flush=True)
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.port)); srv.listen(4)
    conn, peer = srv.accept(); print(f"[store] service connected from {peer}", flush=True)
    store = None; H = None; rows = []; tampered = []; tampered_keys = set()
    while True:
        try:
            ty, f = recv_obj(conn)
        except ConnectionError:
            break
        if ty == PUB_REQ:
            cfg = na.Config(**json.loads(f[0])); H = na.hash_backends()[cfg.hash]
            store = DiskStore(cfg, H, key)
            send_obj(conn, PUB, key.public()[0], key.public()[1])
        elif ty == PKG:
            (t, N, T, D), items = f[0], f[1]
            t0 = time.time()
            q = store.accept(((t, N, T, D), items))
            t1 = time.time()
            fn = os.path.join(run_dir, "chunks", f"w{t:05d}.bin")
            with open(fn, "wb") as fh:
                for (pos, i, s_, c, sib) in items:
                    hdr = struct.pack(">IHQI", pos, i, s_, len(c)); off = fh.tell() + len(hdr)
                    fh.write(hdr + c)
                    if (t, pos) in store.data:            # accepted: replace bytes with a disk pointer
                        store.data[(t, pos)] = (i, s_, (fn, off, len(c)), sib)
                fh.flush(); os.fsync(fh.fileno())
            send_obj(conn, RCPT, q[0], q[1], q[2], repr(time.time() - t0))
            rows.append(dict(t=t, N=N, verify_sign_s=round(t1 - t0, 6), total_s=round(time.time() - t0, 6)))
            if getattr(a, "malicious", 0) and N > 0 and t % 3 == 1:
                # Byzantine custodian: signs a correct receipt, then alters a stored chunk it
                # acknowledged. The regulator must flag CustodyLoss against that signed receipt.
                untampered = [kk for kk in sorted(store.data) if (kk, ) not in tampered_keys]
                if not untampered:
                    continue
                k = untampered[0]; tampered_keys.add((k, ))
                e = store.data[k]
                store.data[k] = (e[0], e[1], os.urandom(len(e[2]) if isinstance(e[2], bytes) else 64), e[3])
                tampered.append((t, e[0], e[1]))
        elif ty == EVID:
            cfg_d, is_param, is_pk, genesis, published, receipts, extra, apk = f
            cfg = na.Config(**json.loads(cfg_d))
            pub = [((h[0], h[1], h[2], h[3]), rec, R, cp) for (h, rec, R, cp) in published]
            rc = {t: (q, bm) for (t, q, bm) in receipts}
            ad_pubs = {i: (prm, bytes(pk)) for (i, prm, pk) in apk}
            # NOTE: in this live harness the verifier receives cfg and keys with the evidence.
            # That is sound only for an honest service (as in the published live run); a
            # deployment must provision cfg, pk, adapter keys, and pk_st out of band (Theorem 4).
            v = na.Verifier(cfg, H, (is_param, is_pk), key.public(), genesis, adapter_pubs=ad_pubs)
            t0 = time.perf_counter()
            verdict, absences, info = v.verify(pub, rc, store=store)
            vt = time.perf_counter() - t0
            cl = sorted((i, s) for (i, s, b) in absences if b == "CustodyLoss")
            res = dict(verdict=verdict, absences=[list(x) for x in absences], info=info, verify_s=vt,
                       verifier_host=os.uname().nodename, windows=len(pub),
                       tampered=tampered,
                       custodyloss_matches=(cl == sorted(set((i, s) for (t, i, s) in tampered))))
            json.dump(dict(res, store_rows=rows, extra=json.loads(extra)), open(os.path.join(run_dir, "verdict.json"), "w"),
                      indent=1, default=str)
            send_obj(conn, VERDICT, json.dumps(res, default=str))
            print(f"[store] verifier: {verdict}, {len(absences)} absences, {vt*1e3:.1f} ms -> {run_dir}", flush=True)
            break
    conn.close()

class DiskStore(na.Store):
    """Store whose accepted chunks live on disk; get() reads them back for the audit."""
    def get(self, t, pos):
        e = self.data.get((t, pos))
        if e is None or not isinstance(e[2], tuple):
            return e
        fn, off, n = e[2]
        with open(fn, "rb") as fh:
            fh.seek(off); c = fh.read(n)
        return (e[0], e[1], c, e[3])

class RemoteStore:
    """Service-side client: sends packages, receives receipts asynchronously."""
    def __init__(self, addr, cfg, outq):
        host, port = addr.rsplit(":", 1)
        while True:
            try:
                self.sock = socket.create_connection((host, int(port)), timeout=10); break
            except OSError:
                print("[serve] waiting for store ...", flush=True); time.sleep(1)
        self.sock.settimeout(None)
        send_obj(self.sock, PUB_REQ, json.dumps(cfg.__dict__))
        ty, f = recv_obj(self.sock); assert ty == PUB
        self.pub = (f[0], f[1]); self.outq = outq; self.verdict = queue.Queue()
        threading.Thread(target=self._rx, daemon=True).start()
    def _rx(self):
        while True:
            try:
                ty, f = recv_obj(self.sock)
            except (ConnectionError, OSError):
                return
            if ty == RCPT:
                self.outq.put(("rcpt", (f[0], f[1], f[2]), float(f[3])))
            elif ty == VERDICT:
                self.verdict.put(json.loads(f[0]))
    def put(self, pkg):
        (t, N, T, D), items = pkg
        send_obj(self.sock, PKG, (t, N, T, D), [list(x) for x in items])
    def verify(self, cfg, is_key, svc, extra):
        pubs = [(list(h), rec, R, cp) for (h, rec, R, cp) in svc.published]
        rc = [(t, q, bm) for t, (q, bm) in sorted(svc.receipt_archive.items())]
        apk = [(i, p[0], p[1]) for i, p in sorted(svc.adapter_pubs.items())]
        send_obj(self.sock, EVID, json.dumps(cfg.__dict__), is_key.public()[0], is_key.public()[1],
                 svc.genesis, pubs, rc, json.dumps(extra), apk)
        return self.verdict.get(timeout=600)

# ---------------------------------------------------------------- serve
def serve(a):
    cfg = na.Config(delta=a.delta, gamma=a.gamma, delta_h=a.delta_h, kappa=a.kappa, k=a.k,
                    theta_st=a.theta_st, hash=a.hash, mac=a.mac, sig=a.xmss, decl=a.decl,
                    delta_m=a.delta_m)
    H = na.hash_backends()[a.hash]; mac = na.mac_backends()[a.mac]
    os.makedirs(a.out, exist_ok=True)
    run_dir = os.path.join(a.out, f"live_{os.uname().nodename}_{time.strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(os.path.join(run_dir, "store"), exist_ok=True)
    print(f"[serve] XMSS keygen ({a.xmss}) for service and store ...", flush=True)
    is_key = na.XMSS(a.xmss, state_path=os.path.join(run_dir, "is_xmss.state"))
    outq = mp.Queue()
    if a.store:
        remote = RemoteStore(a.store, cfg, outq); st_pub = remote.pub
        print(f"[serve] remote store/verifier at {a.store}", flush=True)
    else:
        remote = None; inq = mp.Queue()
        sp = mp.Process(target=store_proc, args=(cfg.__dict__, a.hash, a.xmss, inq, outq,
                                                 os.path.join(run_dir, "store")), daemon=True)
        sp.start()
        kind, st_pub = outq.get()
    keys = {i: adapter_key(a.secret, i) for i in range(a.sensors)}
    lock = threading.Lock()
    tau0 = [None]
    # ingest is aligned to tau0 = time the service starts its schedule
    svc = None
    stats = {"frames": 0, "authfail": 0, "dup": 0}; dropped = []

    go = threading.Event(); conns = {}; adapter_pubs = {}
    stats.update({"manifests": 0, "resend_req": 0, "resent": 0})
    def handle(conn):
        ty, n = struct.unpack(">BI", recv_exact(conn, 5)); hello = parse(ty, recv_exact(conn, n))
        assert hello[0] == "HELLO"
        adapter_pubs[hello[1]] = (hello[2], hello[3])
        go.wait()
        conns[hello[1]] = conn
        conn.sendall(b"G")                                 # epoch start: adapters begin at s = 0
        while True:
            try:
                ty, n = struct.unpack(">BI", recv_exact(conn, 5)); body = recv_exact(conn, n)
            except (ConnectionError, OSError):
                return
            m = parse(ty, body)
            if a.drop > 0 and m[0] == "C" and svc is not None and random.random() < a.drop:
                if (m[1], m[2]) not in dropped:
                    dropped.append((m[1], m[2]))           # injected link loss (evaluation only)
                    continue                               # a resend of a dropped chunk passes
            with lock:
                if svc is None:
                    continue
                tau = time.time() - tau0[0]
                r = {"C": svc.on_chunk, "B": svc.on_heartbeat, "M": svc.on_manifest}[m[0]](m, tau)
                stats["frames"] += 1
                stats["manifests"] += m[0] == "M"
                stats["authfail"] += r == "authfail"; stats["dup"] += r == "duplicate"
                if m[0] == "C" and r == "ok" and (m[1], m[2]) in dropped:
                    stats["resent"] += 1

    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.port)); srv.listen(16)
    def accept_loop():
        while True:
            c, _ = srv.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=accept_loop, daemon=True).start()
    print(f"[serve] listening on :{a.port}; waiting {a.warmup}s for adapters ...", flush=True)
    time.sleep(a.warmup)
    with lock:
        if cfg.decl == "signed" and len(adapter_pubs) < a.sensors:
            print(f"[serve] WARNING: {len(adapter_pubs)}/{a.sensors} adapters announced keys", flush=True)
        svc = na.IntegrityService(cfg, keys, is_key, H, mac,
                                  adapter_pubs=adapter_pubs if cfg.decl == "signed" else {},
                                  store_pub=st_pub)
        tau0[0] = time.time()
    go.set()
    rows, rcpt_lat = [], {}
    close_s_hist = []
    W = a.windows            # telemetry windows 0..W-1, drain window W, settlement window W+1
    for t in range(W + 2):
        settle = t == W + 1
        if t == W:           # orderly shutdown: tell adapters to stop at the end of telemetry
            for c in list(conns.values()):
                try: c.sendall(b"S")
                except OSError: pass
        T_t = tau0[0] + cfg.delta * (t + 1)
        close_at = T_t + cfg.gamma
        deadline = close_at if not settle else close_at + cfg.theta_st
        while time.time() < deadline:   # fold receipts as they arrive (asynchronous to roots)
            done = settle and len(rcpt_lat) >= W + 1
            if done and time.time() >= close_at:
                break
            wait_until = close_at if done else deadline
            try:
                kind, q, store_s = outq.get(timeout=max(0.001, wait_until - time.time()))
            except queue.Empty:
                continue
            tq = q[0]; rcpt_lat[tq] = (time.time() - (tau0[0] + cfg.delta * (tq + 1)), store_s)
            with lock:
                svc.on_receipt(*q)
        with lock:
            t_c0 = time.time()
            R, recs, pkg = svc.close(t, time.time() - tau0[0], force_checkpoint=settle, settlement=settle)
            E = time.time()
        cp = svc.published[-1][3] is not None
        (remote.put if remote else inq.put)(pkg)
        if a.repair and not settle:          # evidence-guided repair: ask for what is missing
            with lock:
                reqs = svc.resend_requests()
            for q in reqs:
                c = conns.get(q[1])
                if c is not None:
                    try: send_frame(c, q); stats["resend_req"] += 1
                    except OSError: pass
        row = dict(t=t, N=pkg[0][1], phase="settle" if settle else ("drain" if t == W else "telemetry"), emit_latency_s=round(E - T_t, 6), compute_s=round(E - t_c0, 6),
                   checkpoint=int(cp), miss=sum(len(r[3]) for r in recs), auth=sum(len(r[4]) for r in recs),
                   late=sum(len(r[5]) for r in recs), stale=int(any(r[10] for r in recs)))
        rows.append(row)
        print(f"[serve] t={t:3d} N={row['N']:4d} E-T={row['emit_latency_s']:.4f}s compute={row['compute_s']*1e3:.2f}ms "
              f"cp={cp} miss={row['miss']} late={row['late']} stale={row['stale']}", flush=True)
    # settlement window may carry late repairs: wait for its receipt before auditing
    t_end = time.time() + cfg.theta_st
    while (W + 1) not in rcpt_lat and time.time() < t_end:
        try:
            kind, q, store_s = outq.get(timeout=max(0.001, t_end - time.time()))
        except queue.Empty:
            break
        rcpt_lat[q[0]] = (time.time() - (tau0[0] + cfg.delta * (q[0] + 1)), store_s)
        with lock:
            svc.on_receipt(*q)
    for r in rows:
        if r["t"] in rcpt_lat:
            r["receipt_latency_s"] = round(rcpt_lat[r["t"]][0], 6); r["store_s"] = round(rcpt_lat[r["t"]][1], 6)
    if remote:
        res = remote.verify(cfg, is_key, svc, dict(dropped=len(dropped), drop=a.drop, repair=a.repair))
        verdict, info, vt = res["verdict"], res["info"], res["verify_s"]
        absences = [tuple(x) for x in res["absences"]]
    else:
        inq.put("dump")
        while True:
            kind, *rest = outq.get()
            if kind == "dump":
                data = rest[0]; break
        class Snap:  # verifier audits the store snapshot
            def get(self, t, pos): return data.get((t, pos))
        v = na.Verifier(cfg, H, is_key.public(), st_pub, svc.genesis, adapter_pubs=svc.adapter_pubs)
        t0 = time.perf_counter()
        verdict, absences, info = v.verify(svc.published, svc.receipt_archive, store=Snap())
        vt = time.perf_counter() - t0
        inq.put(None)
    with open(os.path.join(run_dir, "windows.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=sorted({k for r in rows for k in r})); w.writeheader(); w.writerows(rows)
    repaired = {(r[0], r[1]) for r in info.get("repairs", [])} if isinstance(info, dict) else set()
    truth = sorted((i, s, "IngestAbsent") for i, s in dropped if (i, s) not in repaired)
    summary = dict(topology=dict(service=os.uname().nodename, store=a.store or "local"),
                   dropped=len(dropped), repaired=len(repaired), repair=a.repair, decl=cfg.decl,
                   absences_match_injected=(sorted(map(tuple, absences)) == truth),
                   repairs_match_injected=(repaired <= set(dropped)),
                   verdict=verdict, info=info, absences=absences[:200], n_absences=len(absences),
                   verify_s=vt, stats=stats, cfg=cfg.__dict__, drop=a.drop, sensors=a.sensors,
                   xmss_keygen_s=is_key.keygen_s, record_bytes=sum(len(p[1]) for p in svc.published))
    json.dump(summary, open(os.path.join(run_dir, "summary.json"), "w"), indent=1, default=str)
    print(f"[serve] verdict={verdict} absences={len(absences)} verify={vt*1e3:.1f} ms repaired={len(repaired)} -> {run_dir}")
    for c in list(conns.values()):
        try: c.close()
        except OSError: pass

# ---------------------------------------------------------------- adapter
def source_iter(spec):
    kind = spec.split(":")[0]
    if kind == "synth":
        _, rate, size = spec.split(":"); rate, size = float(rate), int(size)
        while True:
            time.sleep(random.expovariate(rate) * 0.5 + 0.5 / rate)
            yield os.urandom(size)
    if kind == "paced":                      # constant-rate producer on an absolute schedule
        _, rate, size = spec.split(":"); rate, size = float(rate), int(size)
        nxt = time.time()
        while True:
            nxt += 1.0 / rate
            d = nxt - time.time()
            if d > 0:
                time.sleep(d)                    # behind schedule: no sleep, catch up
            yield os.urandom(size)
    if kind == "stdin":
        for line in sys.stdin.buffer:
            yield line.rstrip(b"\r\n")
    if kind == "serial":
        with open(spec.split(":", 1)[1], "rb", buffering=0) as f:
            buf = b""
            while True:
                x = f.read(4096)
                if not x:
                    time.sleep(0.005); continue
                buf += x
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        yield line.rstrip(b"\r")
    if kind == "serialblock":
        _, dev, n = spec.split(":"); n = int(n)
        with open(dev, "rb", buffering=0) as f:
            buf = b""
            while True:
                x = f.read(4096)
                if not x:
                    time.sleep(0.005); continue
                buf += x
                while len(buf) >= n:
                    yield buf[:n]; buf = buf[n:]
    raise SystemExit(f"unknown source {spec}")

def adapter(a):
    cfg = na.Config(delta_h=a.delta_h, mac=a.mac, hash=a.hash, decl=a.decl, delta_m=a.delta_m)
    mac = na.mac_backends()[a.mac]; H = na.hash_backends()[a.hash]
    os.makedirs(a.out, exist_ok=True)
    signer = None
    if cfg.decl == "signed":
        print(f"[adapter {a.id}] XMSS keygen ({a.xmss}) ...", flush=True)
        signer = na.XMSS(a.xmss, state_path=os.path.join(a.out, f"adapter{a.id}_xmss.state"))
        print(f"[adapter {a.id}] keygen {signer.keygen_s:.1f}s", flush=True)
    ad = na.Adapter(cfg, a.id, adapter_key(a.secret, a.id), mac, H=H, signer=signer)
    host, port = a.connect.rsplit(":", 1)
    while True:
        try:
            sock = socket.create_connection((host, int(port)), timeout=5); break
        except OSError:
            print("[adapter] waiting for service ...", flush=True); time.sleep(1)
    sock.settimeout(None)
    pub = signer.public() if signer else ("none", b"")
    send_frame(sock, ("HELLO", a.id, pub[0], pub[1]))
    assert recv_exact(sock, 1) == b"G"                  # wait for the service to open the epoch
    print(f"[adapter {a.id}] epoch open", flush=True)
    t_open = time.time(); t_stop = [None]
    lock = threading.Lock(); stop = threading.Event(); closed = threading.Event()
    stats = {"manifests": 0, "resends": 0, "sign_s": []}
    def hb_loop():
        # heartbeats continue after the stop signal, with the declaration frozen at the final
        # sequence number, until the service closes the connection (drain + settlement windows)
        next_m = time.time() + cfg.delta_m
        while not closed.is_set():
            time.sleep(cfg.delta_h)
            with lock:
                if closed.is_set():
                    break
                try:
                    send_frame(sock, ad.heartbeat())
                    if signer and not stop.is_set() and time.time() >= next_m:
                        t0 = time.perf_counter(); m = ad.manifest(); stats["sign_s"].append(time.perf_counter() - t0)
                        send_frame(sock, m); stats["manifests"] += 1; next_m += cfg.delta_m
                except OSError:
                    closed.set()
    def ctl_loop():
        try:
            while True:
                b = recv_exact(sock, 1)
                if b == b"S":
                    with lock:
                        stop.set()
                        if signer:                                   # FINAL manifest covers the tail
                            m = ad.manifest(final=True); send_frame(sock, m); stats["manifests"] += 1
                        send_frame(sock, ad.heartbeat())             # final declaration
                    print(f"[adapter {a.id}] stop: final declaration s={ad.s}", flush=True)
                elif b == b"\x04":                                   # resend request frame
                    n = struct.unpack(">I", recv_exact(sock, 4))[0]
                    req = parse(4, recv_exact(sock, n))
                    with lock:
                        m = ad.resend_manifest(req[2]) if req[0] == "RM" else ad.resend(req[2])
                        if m is not None:
                            send_frame(sock, m); stats["resends"] += 1
        except (ConnectionError, OSError):
            closed.set(); stop.set()
    threading.Thread(target=hb_loop, daemon=True).start()
    threading.Thread(target=ctl_loop, daemon=True).start()
    n = 0
    for c in source_iter(a.source):
        if stop.is_set():
            t_stop[0] = time.time(); break
        with lock:
            if stop.is_set():
                t_stop[0] = time.time(); break
            send_frame(sock, ad.chunk(c[: a.max_chunk]))
        n += 1
        if n % 100 == 0:
            print(f"[adapter {a.id}] sent {n} chunks", flush=True)
    closed.wait(timeout=600)
    import statistics
    run_s = (t_stop[0] or time.time()) - t_open
    summ = dict(id=a.id, chunks=n, run_s=round(run_s, 3), achieved_rate=round(n / run_s, 2) if run_s > 0 else None, manifests=stats["manifests"], resends=stats["resends"],
                sign_ms_median=round(1e3 * statistics.median(stats["sign_s"]), 2) if stats["sign_s"] else None,
                xmss_keygen_s=signer.keygen_s if signer else None, host=os.uname().nodename)
    json.dump(summ, open(os.path.join(a.out, f"adapter{a.id}_{os.uname().nodename}.json"), "w"), indent=1)
    print(f"[adapter {a.id}] done: {summ}", flush=True)
    os._exit(0)

def main():
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=7700); s.add_argument("--windows", type=int, default=32)
    s.add_argument("--sensors", type=int, default=2); s.add_argument("--secret", default="neith-ace-demo")
    s.add_argument("--delta", type=float, default=10.0); s.add_argument("--gamma", type=float, default=0.5)
    s.add_argument("--delta-h", type=float, default=1.0); s.add_argument("--kappa", type=int, default=3)
    s.add_argument("--k", type=int, default=6); s.add_argument("--theta-st", type=float, default=10.0)
    s.add_argument("--hash", default="shake128"); s.add_argument("--mac", default="kmac128")
    s.add_argument("--xmss", default="XMSS-SHAKE256_10_256")
    s.add_argument("--drop", type=float, default=0.0, help="injected chunk loss probability")
    s.add_argument("--warmup", type=float, default=5.0); s.add_argument("--out", default="results")
    s.add_argument("--store", default=None, help="host:port of a remote store/verifier (live.py store)")
    s.add_argument("--decl", default="signed", choices=["signed", "mac"])
    s.add_argument("--delta-m", type=float, default=10.0, help="manifest period (s)")
    s.add_argument("--repair", type=int, default=1, help="1: request resends for recorded gaps")
    st = sub.add_parser("store")
    st.add_argument("--port", type=int, default=7701)
    st.add_argument("--xmss", default="XMSS-SHAKE256_16_256", help="h=16: 65536 receipts (one per window)")
    st.add_argument("--out", default="results")
    st.add_argument("--malicious", type=int, default=0, help="Byzantine custodian: alter stored chunks after receipting")
    d = sub.add_parser("adapter")
    d.add_argument("--connect", default="127.0.0.1:7700"); d.add_argument("--id", type=int, required=True)
    d.add_argument("--source", required=True); d.add_argument("--secret", default="neith-ace-demo")
    d.add_argument("--delta-h", type=float, default=1.0); d.add_argument("--mac", default="kmac128")
    d.add_argument("--max-chunk", type=int, default=8192)
    d.add_argument("--hash", default="shake128"); d.add_argument("--decl", default="signed", choices=["signed", "mac"])
    d.add_argument("--delta-m", type=float, default=10.0); d.add_argument("--xmss", default="XMSS-SHAKE256_10_256")
    d.add_argument("--out", default="results")
    a = ap.parse_args()
    {"serve": serve, "adapter": adapter, "store": store_server}[a.cmd](a)

if __name__ == "__main__":
    main()
