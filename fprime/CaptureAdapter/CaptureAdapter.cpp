// NEITH-ACE capture adapter — implementation. Mirrors Adapter in neith_ace.py:
// sequence tag + MAC per chunk, chained signed manifest per period, bounded resend buffer.
#include "Components/CaptureAdapter/CaptureAdapter.hpp"
#include "neith_shim.h"
#include <Fw/Types/Assert.hpp>
#include <cstring>
#include <array>
#include <vector>

namespace Components {

CaptureAdapter::CaptureAdapter(const char* name) : CaptureAdapterComponentBase(name) {
    std::memset(m_prevManifest, 0, sizeof(m_prevManifest));
}
void CaptureAdapter::init(FwSizeType q, FwEnumStoreType inst) {
    CaptureAdapterComponentBase::init(q, inst);
}
CaptureAdapter::~CaptureAdapter() { neith_xmss_close(m_xmss); if (m_replay) std::fclose(m_replay); }

void CaptureAdapter::setReplay(const char* path, U32 blockBytes, U32 chunksPerTick, U32 epoch) {
    if (m_replay) std::fclose(m_replay);
    m_replay = std::fopen(path, "rb"); m_replayBlock = blockBytes; m_replayPerTick = chunksPerTick;
    if (m_replay) openEpoch(epoch);
}
U32 CaptureAdapter::nowUs() const { Fw::Time t = this->getTime(); return t.getSeconds() * 1000000u + t.getUSeconds(); }
void CaptureAdapter::openEpoch(U32 epoch) {
    m_epoch = epoch; m_seq = -1; m_v = 0; m_tick = 0; m_stopped = false; m_epochOpen = true;
    m_buffer.clear(); m_pending.clear();
    neith_manifest_genesis(m_epoch, m_sensor, m_prevManifest);        // chain genesis H(0x09||enc(e,i))
    this->log_ACTIVITY_HI_EpochOpened(epoch);
}

void CaptureAdapter::configure(U16 sensorId, const U8 key[16], const char* param,
                               const char* statePath, U32 periodTicks, U32 bufSize) {
    m_sensor = sensorId; std::memcpy(m_key, key, 16);
    m_manifestPeriod = periodTicks ? periodTicks : 1; m_bufSize = bufSize ? bufSize : 4096;
    neith_xmss_close(m_xmss);
    m_xmss = neith_xmss_open(param, statePath);
    if (m_xmss == nullptr) { this->log_FATAL_KeyExhausted(); }
}

// One captured sensor payload this tick.
void CaptureAdapter::dataIn_handler(FwIndexType, Fw::Buffer& buf) {
    if (!m_stopped && m_epochOpen) capture(buf.getData(), buf.getSize());
    if (this->isConnected_bufferReturn_OutputPort(0)) this->bufferReturn_out(0, buf);
}
void CaptureAdapter::capture(const U8* p, U32 n) {
    const U32 s = static_cast<U32>(++m_seq);

    U8 tag[32]; neith_mac_chunk(m_key, m_epoch, m_sensor, s, p, n, tag);

    // bounded resend buffer
    m_buffer[s] = std::vector<U8>(p, p + n);
    if (m_buffer.size() > m_bufSize) m_buffer.erase(m_buffer.begin());
    if (m_buffer.size() > m_highWater) { m_highWater = m_buffer.size(); this->tlmWrite_BufferHighWater(m_highWater); }

    // manifest entry: (seq, digest)
    std::array<U8,32> d; neith_digest(p, n, d.data());
    m_pending.emplace_back(s, d);

    shipChunk(s, p, n, tag);
    m_chunks++; this->tlmWrite_ChunksCaptured(m_chunks); this->tlmWrite_LastSeq(s);
}

// Heartbeat / manifest tick.
void CaptureAdapter::schedIn_handler(FwIndexType, U32) {
    if (m_stopped || !m_epochOpen) return;
    if (m_replay) {                                   // measurement mode: feed recorded chunks
        static U8 line[8192];
        for (U32 k = 0; k < m_replayPerTick; k++) {
            size_t n = 0;
            if (m_replayBlock) { n = std::fread(line, 1, m_replayBlock, m_replay); if (n < m_replayBlock) n = 0; }
            else if (std::fgets(reinterpret_cast<char*>(line), sizeof(line), m_replay)) {
                n = std::strlen(reinterpret_cast<char*>(line));
                while (n && (line[n-1] == '\n' || line[n-1] == '\r')) n--;
            }
            if (n == 0) {                             // EOF: declare FINAL and stop
                sealManifest(true); m_stopped = true;
                this->log_ACTIVITY_HI_Stopped(static_cast<U32>(m_seq));
                std::fclose(m_replay); m_replay = nullptr; return;
            }
            capture(line, static_cast<U32>(n));
        }
    }
    if (++m_tick >= m_manifestPeriod) { m_tick = 0; sealManifest(false); }
}

void CaptureAdapter::sealManifest(bool final) {
    m_v++;
    // build parallel (seq, digest) arrays from the pending entries since the last manifest
    const size_t n = m_pending.size();
    std::vector<U32> seqs(n);
    std::vector<std::array<U8,32>> digs(n);
    for (size_t j = 0; j < n; j++) { seqs[j] = m_pending[j].first; digs[j] = m_pending[j].second; }

    U8 signmsg[32], nextPrev[32];
    neith_manifest_signmsg(m_epoch, m_sensor, m_v, m_seq, m_prevManifest, final ? 1 : 0,
                           seqs.data(), reinterpret_cast<const U8(*)[32]>(digs.data()), n,
                           signmsg, nextPrev);

    U8 sig[3072]; size_t siglen = sizeof(sig);
    const U32 t0 = nowUs();
    const int r = neith_xmss_sign(m_xmss, signmsg, 32, sig, &siglen);   // persists state (fsync) before return
    const U32 dtUs = nowUs() - t0;
    if (r != 0) { this->log_FATAL_KeyExhausted(); return; }
    this->tlmWrite_SignLatencyUs(dtUs);
    std::fprintf(stderr, "NEITH-ACE sensor=%u epoch=%u v=%u s_hat=%lld items=%zu final=%d sign_us=%u highwater=%u\n",
                 (unsigned)m_sensor, (unsigned)m_epoch, (unsigned)m_v, (long long)m_seq, n, final ? 1 : 0,
                 (unsigned)dtUs, (unsigned)m_highWater);

    std::memcpy(m_prevManifest, nextPrev, 32);                  // advance the manifest chain
    m_pending.clear();
    m_manifests++; this->tlmWrite_ManifestsSigned(m_manifests);
    this->log_ACTIVITY_LO_ManifestSigned(m_v, static_cast<U32>(m_seq), final);
    // frame = (MANIFEST, sensor, v, s_hat, prev, final, items, sig); ship via frameOut (same path as chunks)
}

void CaptureAdapter::shipChunk(U32, const U8*, U32, const U8[32]) {
    // acquire a buffer via bufferGet_out, frame (type,sensor,seq,tag,payload), frameOut_out
}

void CaptureAdapter::OPEN_EPOCH_cmdHandler(FwOpcodeType op, U32 seq, U32 epoch) {
    openEpoch(epoch);
    this->cmdResponse_out(op, seq, Fw::CmdResponse::OK);
}
void CaptureAdapter::STOP_cmdHandler(FwOpcodeType op, U32 seq) {
    sealManifest(true); m_stopped = true;
    this->log_ACTIVITY_HI_Stopped(static_cast<U32>(m_seq));
    this->cmdResponse_out(op, seq, Fw::CmdResponse::OK);
}
void CaptureAdapter::RESEND_cmdHandler(FwOpcodeType op, U32 cmdSeq, U32 dataSeq) {
    auto it = m_buffer.find(dataSeq);
    if (it != m_buffer.end()) {
        U8 tag[32]; neith_mac_chunk(m_key, m_epoch, m_sensor, dataSeq, it->second.data(), it->second.size(), tag);
        shipChunk(dataSeq, it->second.data(), it->second.size(), tag);
        m_resends++; this->tlmWrite_Resends(m_resends);
    }
    this->cmdResponse_out(op, cmdSeq, Fw::CmdResponse::OK);
}

}
