"""NEITH-ACE reference implementation (matches the manuscript, Sec. 4).

Parties: Adapter (per sensor), IntegrityService, Store, Verifier.
Every value the verifier checks is recomputed from public data; nothing is trusted
from the store or the publication path.
"""
import ctypes, os, struct, hashlib, hmac, sys, time
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(HERE, "build")
sys.path.insert(0, os.path.join(HERE, "vendor", "pyascon"))

# ---------------------------------------------------------------- encoding
def enc(*fields):
    """Injective, length-prefixed encoding of tuples."""
    out = [struct.pack(">I", len(fields))]
    for f in fields:
        if isinstance(f, bool):
            out.append(b"b" + (b"\x01" if f else b"\x00"))
        elif isinstance(f, int):
            out.append(b"i" + struct.pack(">q", f))
        elif isinstance(f, (bytes, bytearray)):
            out.append(b"y" + struct.pack(">I", len(f)) + bytes(f))
        elif isinstance(f, str):
            b = f.encode()
            out.append(b"s" + struct.pack(">I", len(b)) + b)
        elif isinstance(f, (list, tuple)):
            out.append(b"l" + enc(*f))
        elif f is None:
            out.append(b"n")
        else:
            raise TypeError(type(f))
    return b"".join(out)

# ---------------------------------------------------------------- hash backends (32-byte output)
def _load(name):
    p = os.path.join(BUILD, name)
    return ctypes.CDLL(p) if os.path.exists(p) else None

_xof_opt = _load("libasconxof_opt64.so")
_xof_ref = _load("libasconxof_ref.so")
_cxof_ref = _load("libasconcxof_ref.so")

def _ascon_native(lib):
    fn = lib.crypto_hash  # 64-byte XOF output; SP 800-232 XOF has the prefix property
    def h(d, _b=ctypes.create_string_buffer(64)):
        fn(_b, d, ctypes.c_ulonglong(len(d)))
        return _b.raw[:32]
    return h

def hash_backends():
    hb = {"shake128": lambda d: hashlib.shake_128(d).digest(32),
          "sha3-256": lambda d: hashlib.sha3_256(d).digest()}
    try:
        import blake3
        hb["blake3"] = lambda d: blake3.blake3(d).digest()
    except ImportError:
        pass
    try:
        from Crypto.Hash import KangarooTwelve, cSHAKE128
        hb["k12"] = lambda d: KangarooTwelve.new(data=d).read(32)
        hb["cshake128"] = lambda d: cSHAKE128.new(data=d, custom=b"NEITH").read(32)
    except ImportError:
        pass
    if _xof_opt: hb["ascon-xof128-c-opt64"] = _ascon_native(_xof_opt)
    if _xof_ref: hb["ascon-xof128-c-ref"] = _ascon_native(_xof_ref)
    try:
        import ascon as _pya
        hb["ascon-xof128-python"] = lambda d: _pya.ascon_hash(d, "Ascon-XOF128", 32)
    except ImportError:
        pass
    return hb

# ---------------------------------------------------------------- MAC backends
def mac_backends():
    mb = {"hmac-sha256": lambda k, m: hmac.new(k, m, hashlib.sha256).digest()}
    try:
        from Crypto.Hash import KMAC128
        mb["kmac128"] = lambda k, m: KMAC128.new(key=k, mac_len=32, custom=b"NEITH-ACE").update(m).digest()
    except ImportError:
        pass
    if _cxof_ref:
        fn = _cxof_ref.crypto_cxof
        cs = b"NEITH-ACE-MAC"
        def m(k, msg, _b=ctypes.create_string_buffer(32)):
            d = k + msg  # keyed CXOF: fixed 16-byte key prefix, fixed customization
            fn(_b, ctypes.c_ulonglong(32), d, ctypes.c_ulonglong(len(d)), cs, ctypes.c_ulonglong(len(cs)))
            return _b.raw
        mb["ascon-cxof128-keyed"] = m
    return mb

# ---------------------------------------------------------------- XMSS
class XMSS:
    """Stateful XMSS via xmss-reference. The secret key buffer is the state; callers must
    persist it before releasing a signature (persist() writes it atomically)."""
    _lib = _load("libxmss.so")

    def __init__(self, param="XMSS-SHAKE256_10_256", state_path=None):
        if not self._lib:
            raise RuntimeError("build/libxmss.so missing: run ./build.sh")
        L = self._lib
        pkb, skb, sigb = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
        if L.xw_init(param.encode(), ctypes.byref(pkb), ctypes.byref(skb), ctypes.byref(sigb)):
            raise ValueError(param)
        self.param, self.pk_len, self.sk_len, self.sig_len = param, pkb.value, skb.value, sigb.value
        self.pk = ctypes.create_string_buffer(self.pk_len)
        self.sk = ctypes.create_string_buffer(self.sk_len)
        self.state_path = state_path
        t0 = time.perf_counter()
        L.xw_keypair(self.pk, self.sk)
        self.keygen_s = time.perf_counter() - t0
        self.persist()

    def _select(self):
        pkb, skb, sigb = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
        self._lib.xw_init(self.param.encode(), ctypes.byref(pkb), ctypes.byref(skb), ctypes.byref(sigb))

    def persist(self):
        if self.state_path:
            tmp = self.state_path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(self.sk.raw); f.flush(); os.fsync(f.fileno())
            os.replace(tmp, self.state_path)

    def sign(self, msg):
        self._select()
        sig = ctypes.create_string_buffer(self.sig_len)
        r = self._lib.xw_sign(self.sk, sig, msg, ctypes.c_ulonglong(len(msg)))
        if r:
            raise RuntimeError(f"xmss_sign failed ({r}); key exhausted?")
        self.persist()  # state reaches storage before the signature is released
        return sig.raw

    def public(self):
        return (self.param, self.pk.raw)

def xmss_verify(pub, sig, msg):
    param, pk = pub
    L = XMSS._lib
    pkb, skb, sigb = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
    L.xw_init(param.encode(), ctypes.byref(pkb), ctypes.byref(skb), ctypes.byref(sigb))
    return L.xw_verify(pk, sig, msg, ctypes.c_ulonglong(len(msg))) == 0

# ---------------------------------------------------------------- Merkle tree (Eq. 2-3)
def tree(H, leaves):
    """Returns (root, levels). Padded binary tree; shape depends on len(leaves) only."""
    if not leaves:
        return H(b"\x04"), []
    pad = H(b"\x03")
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        if len(cur) % 2:
            cur = cur + [pad]
        levels.append([H(b"\x01" + cur[j] + cur[j + 1]) for j in range(0, len(cur), 2)])
    return levels[-1][0], levels

def path(H, levels, pos):
    pad = H(b"\x03"); out = []
    for lvl in levels[:-1]:
        sib = pos ^ 1
        out.append(lvl[sib] if sib < len(lvl) else pad)
        pos >>= 1
    return out

def root_from_path(H, leaf, pos, sibs):
    v = leaf
    for s in sibs:
        v = H(b"\x01" + (v + s if pos % 2 == 0 else s + v)); pos >>= 1
    return v

def leaf_value(H, e, t, i, s, c):
    return H(b"\x00" + enc(e, t, i, s) + c)

# ---------------------------------------------------------------- configuration
@dataclass
class Config:
    epoch: int = 1
    delta: float = 10.0       # window length (s)
    gamma: float = 0.5        # grace period (s)
    delta_h: float = 1.0      # heartbeat period (s)
    kappa: int = 3            # staleness multiplier
    k: int = 6                # checkpoint period (windows)
    theta: float = 2.0        # publication skew allowance (s)
    theta_st: float = 10.0    # receipt-completion deadline after window close (s)
    hash: str = "shake128"
    mac: str = "kmac128"
    sig: str = "XMSS-SHAKE256_10_256"
    decl: str = "signed"      # "mac": heartbeats only (IS trusted); "signed": adapter-signed manifests
    delta_m: float = 10.0     # manifest period (s); one adapter signature per delta_m per sensor
    def enc(self):
        return enc(self.epoch, repr(self.delta), repr(self.gamma), repr(self.delta_h), self.kappa,
                   self.k, repr(self.theta), repr(self.theta_st), self.hash, self.mac, self.sig,
                   self.decl, repr(self.delta_m))

# ---------------------------------------------------------------- adapter (Eq. 5-6)
class Adapter:
    """Capture adapter. Keeps the last `buf_size` authenticated chunks so an integrity
    service can ask for a gap to be filled; a resend is the identical message, so the
    service treats it like any arrival (authenticate, then resolve or ignore)."""
    def __init__(self, cfg, i, key, mac, buf_size=4096, H=None, signer=None):
        self.cfg, self.i, self.key, self.mac = cfg, i, key, mac
        self.s = -1; self.u = 0
        self.buf, self.buf_size = {}, buf_size
        self.resends = 0
        # signed declarations (cfg.decl == "signed"): the adapter signs, once per delta_m, a
        # manifest listing the digests of every chunk since the previous manifest, chained to it.
        self.H, self.signer = H, signer
        self.digests = {}                      # s -> H(c) since last manifest
        self.v = 0                             # manifest counter
        self.m_prev = H(b"\x09" + enc(cfg.epoch, i)) if H else None   # manifest-chain genesis
        self.manifests = {}                    # v -> message (resend buffer for manifests)
    def chunk(self, c):
        self.s += 1
        tag = self.mac(self.key, enc("chunk", self.cfg.epoch, self.i, self.s) + c)
        m = ("C", self.i, self.s, c, tag)
        self.buf[self.s] = m
        if len(self.buf) > self.buf_size:
            del self.buf[min(self.buf)]
        if self.H is not None:
            self.digests[self.s] = self.H(c)
        return m
    def manifest(self, final=False):
        """Signed declaration M_v = Sign_A(enc("mf", e, i, v, s_hat, m_{v-1}, final, [(s, H(c_s))...])).
        Binding every chunk digest to the adapter's own key is what a compromised integrity
        service cannot reproduce; chaining m_{v-1} is what it cannot skip; the final flag is
        what lets a verifier distinguish a closed epoch from a prefix of one."""
        if getattr(self, "final_sent", False):
            raise RuntimeError("capture after FINAL")
        self.v += 1
        items = [(s, self.digests[s]) for s in sorted(self.digests)]
        body = enc("mf", self.cfg.epoch, self.i, self.v, self.s, self.m_prev, bool(final), items)
        sig = self.signer.sign(self.H(b"\x0a" + body))
        m = ("M", self.i, self.v, self.s, self.m_prev, bool(final), items, sig)
        if final:
            self.final_sent = True
        self.m_prev = self.H(b"\x0a" + body)
        self.digests = {}
        self.manifests[self.v] = m
        return m
    def resend_manifest(self, v):
        return self.manifests.get(v)
    def resend(self, s):
        """Answer a resend request. Requests need no authentication: a forged request
        can only make the adapter repeat an authentic chunk, which the service discards."""
        m = self.buf.get(s)
        if m is not None:
            self.resends += 1
        return m
    def heartbeat(self):
        self.u += 1
        tag = self.mac(self.key, enc("hb", self.cfg.epoch, self.i, self.s, self.u))
        return ("B", self.i, self.s, self.u, tag)

# ---------------------------------------------------------------- integrity service
@dataclass
class SensorState:
    b: int = -1                                    # last accounted sequence number
    unresolved: set = field(default_factory=set)   # missing/auth-failed in earlier windows
    unres_miss: set = field(default_factory=set)   # subset still classified as missing
    pending_auth: set = field(default_factory=set) # invalid arrivals beyond the declared range
    hbs: list = field(default_factory=list)        # (tau, s_hat, u) authenticated heartbeats
    u_max: int = 0
    mfs: list = field(default_factory=list)        # manifests received, not yet committed
    v_seen: set = field(default_factory=set)
    mf_hold: dict = field(default_factory=dict)    # manifests waiting for an earlier one
    mf_next: int = 1                               # next manifest index to commit

class IntegrityService:
    """Windows are assigned by ingestion time t(tau) = floor((tau - tau0)/Delta), tau0 = 0."""
    def __init__(self, cfg, keys, signer, H, mac, adapter_pubs=None, store_pub=None):
        self.cfg, self.keys, self.signer, self.H, self.mac = cfg, keys, signer, H, mac
        self.adapter_pubs = adapter_pubs or {}
        self.sensors = {i: SensorState() for i in keys}
        self.prev = genesis_root(H, cfg, signer.public(), self.adapter_pubs, store_pub)
        self.genesis = self.prev
        self.recv, self.authfail = {}, {}          # t -> {(i,s): chunk}, t -> set((i,s))
        self.pending_receipts = []                 # (t_committed, q, bitmap)
        self.committed = {}                        # t -> leaf ids in order
        self.published = []                        # (header, rec_enc, root, checkpoint|None)
        self.receipt_archive = {}                  # t -> (q, bitmap)

    def win(self, tau):
        return int(tau // self.cfg.delta)

    def _seen(self, i, s):
        st = self.sensors[i]
        if s <= st.b and s not in st.unresolved:
            return True
        return any((i, s) in bucket for bucket in self.recv.values())

    def on_chunk(self, msg, tau):
        _, i, s, c, tag = msg
        if i not in self.keys:
            return "unknown"
        t = self.win(tau)
        exp = self.mac(self.keys[i], enc("chunk", self.cfg.epoch, i, s) + c)
        if not hmac.compare_digest(exp, tag):
            if not self._seen(i, s):
                self.authfail.setdefault(t, set()).add((i, s))
            return "authfail"
        if self._seen(i, s):
            return "duplicate"                     # idempotent retransmission / replay
        self.recv.setdefault(t, {})[(i, s)] = c
        for bucket in self.authfail.values():
            bucket.discard((i, s))
        self.sensors[i].pending_auth.discard(s)
        return "ok"

    def on_heartbeat(self, msg, tau):
        _, i, s_hat, u, tag = msg
        if i not in self.keys:
            return "unknown"
        st = self.sensors[i]
        exp = self.mac(self.keys[i], enc("hb", self.cfg.epoch, i, s_hat, u))
        if not hmac.compare_digest(exp, tag) or u <= st.u_max:
            return "reject"
        st.u_max = u
        st.hbs.append((tau, s_hat, u))
        return "ok"

    def resend_requests(self, limit=256):
        """Gaps recorded in closed windows that a resend could still close: missing and
        auth-failed sequence numbers, oldest first, bounded per sensor."""
        out = []
        for i in sorted(self.sensors):
            st = self.sensors[i]
            out += [("R", i, s) for s in sorted(st.unresolved)[:limit]]
            if st.v_seen:          # manifests missing below the highest one seen
                out += [("RM", i, v) for v in range(1, max(st.v_seen)) if v not in st.v_seen][:limit]
        return out

    def on_manifest(self, msg, tau):
        """The service stores manifests verbatim; it does not need to verify them (the verifier
        does), but an honest service checks the signature so it can request a resend early."""
        _, i, v, s_hat, m_prev, final, items, sig = msg
        if i not in self.keys or v in self.sensors[i].v_seen:
            return "duplicate"
        body = enc("mf", self.cfg.epoch, i, v, s_hat, m_prev, bool(final), items)
        if i in self.adapter_pubs and not xmss_verify(self.adapter_pubs[i], sig, self.H(b"\x0a" + body)):
            return "reject"
        st = self.sensors[i]
        st.v_seen.add(v)
        # manifests are committed in chain order: a later one waits until every earlier one
        # has arrived (a lost manifest is re-requested), so an honest record never skips one
        st.mf_hold[v] = (v, s_hat, m_prev, bool(final), [tuple(x) for x in items], sig)
        while st.mf_next in st.mf_hold:
            st.mfs.append(st.mf_hold.pop(st.mf_next)); st.mf_next += 1
        return "ok"

    def on_receipt(self, t, q, bitmap):
        self.pending_receipts.append((t, q, bitmap))
        self.receipt_archive[t] = (q, bitmap)

    def close(self, t, now, force_checkpoint=False, settlement=False):
        cfg, H = self.cfg, self.H
        T_close = cfg.delta * (t + 1)
        recv = self.recv.pop(t, {}); authf = self.authfail.pop(t, set())
        if getattr(self, "pre_tree", None):          # compromised-service hook (evaluation)
            recv = self.pre_tree(t, recv, T_close)
        ids = sorted(recv)
        leaves = [leaf_value(H, cfg.epoch, t, i, s, recv[(i, s)]) for i, s in ids]
        T, levels = tree(H, leaves)
        acked = {i: [] for i in self.keys}; rc = []
        for (tc, q, bm) in self.pending_receipts:
            for pos, (i, s) in enumerate(self.committed.get(tc, [])):
                if (bm[pos // 8] >> (pos % 8)) & 1:
                    acked[i].append((tc, s))
            rc.append(enc(tc, q, bm))
        self.pending_receipts = []
        r = H(b"\x08" + enc(*rc))
        records = []
        for i in sorted(self.keys):
            st = self.sensors[i]
            hb = [h for h in st.hbs if h[0] < T_close]
            s_hat, u, hb_tau = (hb[-1][1], hb[-1][2], hb[-1][0]) if hb else (-1, 0, None)
            got = {s for (j, s) in recv if j == i}
            a = st.b + 1
            b = max([st.b, s_hat] + [s for s in got if s >= a])
            late = sorted(s for s in got if s < a)          # only unresolved can reach recv
            st.unresolved -= set(late); st.unres_miss -= set(late)
            # an invalid arrival for an earlier *missing* gap reclassifies it (never the reverse)
            af = {s for (j, s) in authf if j == i} | st.pending_auth
            recl = sorted(s for s in af if s < a and s in st.unres_miss)
            st.unres_miss -= set(recl)
            miss, auth = [], []
            for s in range(a, b + 1):
                if s not in got:
                    (auth if s in af else miss).append(s)
            auth = recl + auth
            # invalid arrivals for not-yet-declared numbers wait for a declaration (bounded)
            st.pending_auth = set(sorted(x for x in af if x > b)[:1024])
            st.unresolved |= set(miss) | set(auth); st.unres_miss |= set(miss)
            stale = (not settlement) and (hb_tau is None or (T_close - hb_tau) > cfg.kappa * cfg.delta_h)
            mfs = sorted(st.mfs); st.mfs = []
            records.append((i, a, b, miss, auth, late, sorted(acked[i]), r, s_hat, u, stale, mfs))
            st.b = b
        if getattr(self, "tamper", None):            # compromised-service hook (evaluation)
            records = self.tamper(t, records)
        rec_enc = enc(*records)
        D = H(b"\x02" + rec_enc)
        N = len(leaves)
        R = H(b"\x05" + enc(cfg.epoch, t, N) + T + D + self.prev)
        cp = None
        if force_checkpoint or t % cfg.k == cfg.k - 1:
            # the shutdown checkpoint carries end=1, so a verifier knows the schedule has ended
            cp = self.signer.sign(H(b"\x07" + enc(cfg.epoch, t, bool(settlement)) + R))
        self.published.append(((t, N, T, D), rec_enc, R, cp))
        self.prev = R
        self.committed[t] = ids
        package = ((t, N, T, D), [(pos, i, s, recv[(i, s)], path(H, levels, pos))
                                  for pos, (i, s) in enumerate(ids)])
        return R, records, package

# ---------------------------------------------------------------- store
class Store:
    def __init__(self, cfg, H, signer):
        self.cfg, self.H, self.signer = cfg, H, signer
        self.data = {}              # (t, pos) -> (i, s, chunk)
    def accept(self, package, refuse=()):
        (t, N, T, D), items = package
        bm = bytearray((N + 7) // 8)
        for pos, i, s, c, sib in items:
            if (t, pos) in refuse:
                continue
            leaf = leaf_value(self.H, self.cfg.epoch, t, i, s, c)
            if root_from_path(self.H, leaf, pos, sib) != T:
                continue           # never acknowledge content that does not match T_t
            self.data[(t, pos)] = (i, s, c, sib)   # path kept so any audit is self-contained
            bm[pos // 8] |= 1 << (pos % 8)
        bm = bytes(bm)
        q = self.signer.sign(enc("rcpt", self.cfg.epoch, t, N) + T + bm)
        return t, q, bm
    def get(self, t, pos):
        return self.data.get((t, pos))

# ---------------------------------------------------------------- genesis
def genesis_root(H, cfg, pub, adapter_pubs, store_pub):
    """R_{-1}: fixes the configuration (incl. declaration mode), the checkpoint key, every
    adapter manifest key, and the store receipt key."""
    apk = enc(*[(i, adapter_pubs[i][0], adapter_pubs[i][1]) for i in sorted(adapter_pubs)])
    spk = enc(store_pub[0], store_pub[1]) if store_pub is not None else b""
    return H(b"\x06" + enc(cfg.epoch, cfg.enc(), pub[1], apk, spk))

# ---------------------------------------------------------------- verifier
class Verifier:
    """The verifier's inputs (cfg, checkpoint key, adapter keys, store key) are its own,
    provisioned out of band; the genesis root it is handed must match them."""
    def __init__(self, cfg, H, pub, store_pub, genesis, adapter_pubs=None):
        self.cfg, self.H, self.pub, self.store_pub, self.genesis = cfg, H, pub, store_pub, genesis
        self.adapter_pubs = adapter_pubs or {}

    @staticmethod
    def _due(deadline, now, contacts):
        if now is None:
            return True
        if contacts is None:
            return deadline <= now
        return any(e >= deadline and st_ <= now for (st_, e) in contacts)

    def verify(self, published, receipts, store=None, now=None, contacts=None):
        try:
            return self._verify(published, receipts, store, now, contacts)
        except (ValueError, IndexError, KeyError, TypeError) as e:
            return "INVALID", [], {"reason": f"malformed history: {e}"}

    def _verify(self, published, receipts, store=None, now=None, contacts=None):
        """published: list of (header, rec_enc, root_claimed, checkpoint).
        receipts: dict t -> (q, bm). now: audit time. contacts: optional list of (start, end)
        intervals during which the service could publish; a checkpoint counts as overdue only
        if a contact ended after its deadline (planned outages are not withholding).
        Returns (verdict, absences, info)."""
        cfg, H = self.cfg, self.H
        if self.genesis != genesis_root(H, cfg, self.pub, self.adapter_pubs, self.store_pub):
            return "INVALID", [], {"reason": "genesis does not match the verifier's trusted inputs"}
        if cfg.decl == "signed" and not self.adapter_pubs:
            return "INVALID", [], {"reason": "signed declarations configured but no adapter keys"}
        prev, absences = self.genesis, []
        verified_through, last_cp_t, end_cp = -1, -1, None
        decoded = []
        for idx, (header, rec_enc, R_claim, cp) in enumerate(published):
            t, N, T, D = header
            if t != idx:
                return "INVALID", [], {"reason": f"window index gap/reorder at position {idx} (t={t})"}
            if H(b"\x02" + rec_enc) != D:
                return "INVALID", [], {"reason": f"record digest mismatch t={t}"}
            R = H(b"\x05" + enc(cfg.epoch, t, N) + T + D + prev)
            if R != R_claim:
                return "INVALID", [], {"reason": f"root mismatch t={t}"}
            if cp is None and t % cfg.k == cfg.k - 1:
                # a scheduled checkpoint not yet present is pending until T_t + gamma + theta
                if self._due(cfg.delta * (t + 1) + cfg.gamma + cfg.theta, now, contacts):
                    return "WITHHELD", [], {"reason": f"checkpoint missing t={t}"}
            if cp is not None:
                if xmss_verify(self.pub, cp, H(b"\x07" + enc(cfg.epoch, t, False) + R)):
                    pass
                elif xmss_verify(self.pub, cp, H(b"\x07" + enc(cfg.epoch, t, True) + R)):
                    if idx != len(published) - 1:
                        return "INVALID", [], {"reason": f"windows published after the end checkpoint t={t}"}
                    end_cp = t
                else:
                    return "INVALID", [], {"reason": f"checkpoint signature t={t}"}
                last_cp_t = t
            decoded.append((t, N, T, rec_enc))
            prev = R
        # Windows after the last checkpoint are unauthenticated. They are *pending* while the
        # checkpoint that will cover them is not yet due, and are then excluded from the audit
        # scope (the result can be at most PREFIX); once that checkpoint's deadline has passed
        # at a contact, the tail is WITHHELD.
        n = len(published)
        # the shutdown checkpoint (signed with end=1) closes the epoch; no later checkpoint is expected
        epoch_end = end_cp
        pending_tail = None
        if n and last_cp_t < n - 1:
            next_cp = last_cp_t + cfg.k if last_cp_t >= 0 else cfg.k - 1
            deadline = cfg.delta * (next_cp + 1) + cfg.gamma + cfg.theta
            due_now = now is None or (deadline <= now if contacts is None else
                                      any(e >= deadline and st_ <= now for (st_, e) in contacts))
            if due_now:
                return "WITHHELD", [], {"reason": f"windows {last_cp_t+1}..{n-1} lack a checkpoint"}
            pending_tail = (last_cp_t + 1, n - 1)
            decoded = decoded[:last_cp_t + 1]
        if now is not None:     # every checkpoint whose deadline has passed must be present
            def publishable(d):   # was there a contact after deadline d?
                if contacts is None:
                    return d <= now
                return any(e >= d and st_ <= now for (st_, e) in contacts)
            horizon = int(now // cfg.delta) if epoch_end is None else min(int(now // cfg.delta), epoch_end)
            due = [t for t in range(horizon + 1)
                   if t % cfg.k == cfg.k - 1 and publishable(cfg.delta * (t + 1) + cfg.gamma + cfg.theta)]
            if due and due[-1] > last_cp_t:
                return "WITHHELD", [], {"reason": f"checkpoint for t={due[-1]} overdue"}
        # completeness: rebuild accounts from records (records verified via D)
        acct, stale, stale_decl = {}, False, False
        recs_by_t = {}; repairs = []     # (i, s, class of the recorded gap, window that closed it)
        for t, N, T, rec_enc in decoded:
            recs = _decode_records(rec_enc)
            recs_by_t[t] = recs
            for rec in recs:
                (i, a, b, miss, auth, late, K, r, sh, u, st) = rec[:11]
                A = acct.setdefault(i, {"next": 0, "miss": set(), "auth": set()})
                if a != A["next"]:
                    return "INVALID", [], {"reason": f"interval tiling broken sensor {i} t={t}"}
                for s in late:
                    if s not in A["miss"] and s not in A["auth"]:
                        return "INVALID", [], {"reason": f"late arrival {s} without earlier gap"}
                    cls = "IngestAbsent" if s in A["miss"] else "IngestAuthFail"
                    repairs.append((i, s, cls, t))
                    A["miss"].discard(s); A["auth"].discard(s)
                for s in auth:
                    if s < a:     # reclassification of an earlier missing gap
                        if s not in A["miss"]:
                            return "INVALID", [], {"reason": f"reclassified {s} was not a gap"}
                        A["miss"].discard(s)
                    elif not (a <= s <= b):
                        return "INVALID", [], {"reason": f"auth gap {s} outside interval"}
                for s in miss:
                    if not (a <= s <= b) or s in auth or s in A["miss"]:
                        return "INVALID", [], {"reason": f"missing gap {s} outside interval or repeated sensor {i} t={t}"}
                A["miss"] |= set(miss); A["auth"] |= set(auth)
                A["next"] = b + 1
                stale = stale or st
        for i, A in acct.items():
            absences += [(i, s, "IngestAbsent") for s in sorted(A["miss"])]
            absences += [(i, s, "IngestAuthFail") for s in sorted(A["auth"])]
        # ---- signed declarations: the adapter's manifests, not the service's records, define
        # what was captured. Checked only when the configuration says so.
        declared = {}                       # i -> {s: digest}
        decl_frontier = {}                  # i -> s_hat of the last manifest
        undeclared_tail = {}                # i -> (first, last) committed beyond the declaration
        finals = {}                         # i -> True once the adapter's FINAL manifest is seen
        if cfg.decl == "signed":
            chain = {i: (0, H(b"\x09" + enc(cfg.epoch, i))) for i in self.adapter_pubs}
            for t, N, T, rec_enc in decoded:
                for rec in recs_by_t[t]:
                    i = rec[0]; mfs = rec[11] if len(rec) > 11 else []
                    for (v, s_hat, m_prev, final, items, sig) in mfs:
                        v_exp, m_exp = chain[i]
                        if v != v_exp + 1:
                            return "WITHHELD", absences, {"reason": f"manifest {v_exp + 1} of sensor {i} skipped"}
                        if m_prev != m_exp:
                            return "INVALID", absences, {"reason": f"manifest chain link wrong sensor {i} at v={v}"}
                        if finals.get(i):
                            return "INVALID", absences, {"reason": f"capture after FINAL sensor {i} v={v}"}
                        body = enc("mf", cfg.epoch, i, v, s_hat, m_prev, bool(final), [tuple(x) for x in items])
                        if not xmss_verify(self.adapter_pubs[i], sig, H(b"\x0a" + body)):
                            return "INVALID", absences, {"reason": f"manifest signature sensor {i} v={v}"}
                        if final:
                            finals[i] = True
                        D_i = declared.setdefault(i, {})
                        for (s_, d_) in items:
                            if s_ in D_i:
                                return "INVALID", absences, {"reason": f"duplicate declaration {i},{s_}"}
                            D_i[s_] = bytes(d_)
                        decl_frontier[i] = s_hat
                        chain[i] = (v, H(b"\x0a" + body))
            for i in self.adapter_pubs:
                D_i = declared.get(i, {})
                fr = decl_frontier.get(i, -1)
                # every declared number up to the frontier is declared exactly once
                if fr >= 0 and sorted(D_i) != list(range(fr + 1)):
                    return "INVALID", absences, {"reason": f"declaration list not contiguous sensor {i}"}
                A = acct.get(i, {"next": 0})
                if A["next"] - 1 > fr:
                    # committed chunks beyond the last declaration are source-unconfirmed:
                    # the history cannot be COMPLETE until a manifest covers them.
                    stale_decl = True
                    undeclared_tail[i] = (fr + 1, A["next"] - 1)
                if A["next"] - 1 < fr:
                    # adapter declared more than the service accounted: the tail is missing
                    for s_ in range(A["next"], fr + 1):
                        absences.append((i, s_, "IngestAbsent"))
        # every committed identity appears once in the whole history
        seen_ids, ids_by_t = set(), {}
        for t, N, T, rec_enc in decoded:
            ids = _leaf_ids(recs_by_t, t, N, decoded); ids_by_t[t] = ids
            for x in ids:
                if x in seen_ids:
                    return "INVALID", absences, {"reason": f"identity {x} committed twice"}
                seen_ids.add(x)
        if cfg.decl == "signed":
            for (i, s) in seen_ids:
                if i in self.adapter_pubs and s not in declared.get(i, {}):
                    if s <= decl_frontier.get(i, -1) or finals.get(i):
                        return "INVALID", absences, {"reason": f"undeclared committed chunk {i},{s}"}
                    stale_decl = True
                    undeclared_tail.setdefault(i, (s, s))
        # custody: every committed position is opened when a store is available; receipts
        # (signed by the store) decide only where an absence is attributed
        unaudited = store is None
        pending_custody = False
        for t, N, T, rec_enc in decoded:
            ids = ids_by_t[t]
            depth = (N - 1).bit_length() if N > 1 else 0
            q_bm = receipts.get(t)
            ok_bits = set()
            if q_bm is not None:
                q, bm = q_bm
                # a receipt whose bitmap has the wrong length acknowledges nothing (never INVALID:
                # a malformed receipt is the store's fault, not the history's)
                if len(bm) == (N + 7) // 8 and xmss_verify(self.store_pub, q, enc("rcpt", cfg.epoch, t, N) + T + bm):
                    ok_bits = {p for p in range(N) if (bm[p // 8] >> (p % 8)) & 1}
            deadline_passed = now is None or now >= cfg.delta * (t + 1) + cfg.theta_st
            for pos in range(N):
                i, s = ids[pos]
                opened = False
                if store is not None:
                    got = store.get(t, pos)
                    opened = (got is not None and got[0] == i and got[1] == s and len(got[3]) == depth and
                              root_from_path(H, leaf_value(H, cfg.epoch, t, i, s, got[2]), pos, got[3]) == T)
                    if opened and cfg.decl == "signed" and i in self.adapter_pubs:
                        d = declared.get(i, {}).get(s)
                        if d is not None and H(got[2]) != d:
                            return "INVALID", absences, {"reason": f"committed chunk {i},{s} differs from declaration"}
                if pos in ok_bits:
                    if store is not None and not opened:
                        absences.append((i, s, "CustodyLoss"))
                elif deadline_passed:
                    absences.append((i, s, "HandoffAbsent"))
                else:
                    # receipt not yet due: whether custody was accepted is still open, so the
                    # history cannot be COMPLETE or REPAIRED yet, even if the store produced it
                    pending_custody = True
        info = {"repairs": sorted(repairs)}
        if unaudited or pending_custody:
            info["unaudited"] = True
        if pending_tail:
            info["pending"] = pending_tail          # excluded from scope until its checkpoint is due
        if undeclared_tail:
            info["undeclared_tail"] = undeclared_tail
        # chunks past the last manifest in scope are unconfirmed; when the scope was cut short only
        # by a checkpoint not yet due, their manifests lie in the pending tail, so this is a prefix
        stale = stale or (stale_decl and pending_tail is None)
        if cfg.decl == "signed":
            closed = all(finals.get(i) for i in self.adapter_pubs) and pending_tail is None
            info["scope"] = "epoch" if closed else "prefix"
            info["declared_through"] = dict(decl_frontier)
            if not closed and not absences and not stale:
                # a complete *prefix* is not a complete epoch (the newest blocks may be hidden)
                return "PREFIX", absences, info
        if stale:
            return "STALE", absences, info
        if absences:
            return "ACCOUNTED", absences, info
        # REPAIRED: every recorded gap was closed by an authenticated late arrival, and the
        # closing window lies under a valid checkpoint (enforced above: no unsigned tail).
        if pending_tail or unaudited or pending_custody:
            return "PREFIX", absences, info          # complete only as far as audited
        return ("REPAIRED" if repairs else "COMPLETE"), absences, info

def _decode_records(rec_enc):
    """Inverse of enc(*records) for the record tuple shape used above."""
    return _Dec(rec_enc).tuple()

class _Dec:
    def __init__(self, b): self.b, self.p = b, 0
    def tuple(self):
        n = struct.unpack_from(">I", self.b, self.p)[0]; self.p += 4
        return [self.field() for _ in range(n)]
    def field(self):
        k = self.b[self.p:self.p + 1]; self.p += 1
        if k == b"i":
            v = struct.unpack_from(">q", self.b, self.p)[0]; self.p += 8; return v
        if k == b"b":
            v = self.b[self.p] == 1; self.p += 1; return v
        if k in (b"y", b"s"):
            n = struct.unpack_from(">I", self.b, self.p)[0]; self.p += 4
            v = self.b[self.p:self.p + n]; self.p += n
            return v if k == b"y" else v.decode()
        if k == b"l":
            return self.tuple()
        if k == b"n":
            return None
        raise ValueError(k)

def _leaf_ids(recs_by_t, t, N, decoded):
    """Leaf identities of window t, reconstructed from records alone: committed seqs are the
    interval members that are not gaps, plus late arrivals; order is lexicographic (i, s)."""
    ids = []
    for rec in recs_by_t[t]:
        (i, a, b, miss, auth, late, K, r, sh, u, st) = rec[:11]
        gaps = set(miss) | set(auth)
        ids += [(i, s) for s in late] + [(i, s) for s in range(a, b + 1) if s not in gaps]
    ids.sort()
    if len(ids) != N:
        raise ValueError(f"record/leaf-count mismatch at t={t}: {len(ids)} vs {N}")
    return ids

