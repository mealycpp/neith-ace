// NEITH-ACE custodian — implementation. Mirrors Store in neith_ace.py: persist chunks,
// sign one receipt per window over the accepted-position bitmap. Malicious mode alters a
// stored, already-receipted chunk, which the independent regulator attributes as CustodyLoss.
#include "Components/Custodian/Custodian.hpp"
#include "neith_shim.h"
#include <Fw/Types/Assert.hpp>
#include <cstdio>
#include <cstring>

namespace Components {

Custodian::Custodian(const char* name) : CustodianComponentBase(name) {
    std::memset(m_treeRoot, 0, sizeof(m_treeRoot));
}
void Custodian::init(FwSizeType q, FwEnumStoreType inst) { CustodianComponentBase::init(q, inst); }
Custodian::~Custodian() { neith_xmss_close(m_xmss); }

void Custodian::configure(const char* storeDir, const char* param, const char* statePath, U32 period) {
    std::snprintf(m_storeDir, sizeof(m_storeDir), "%s", storeDir);
    m_period = period ? period : 1;
    neith_xmss_close(m_xmss); m_xmss = neith_xmss_open(param, statePath);
    if (m_xmss == nullptr) this->log_FATAL_KeyExhausted();
}

// A frame arrived: in a full deployment this is deframed into (type, window, sensor, seq,
// payload, path, T). The scaffold persists the chunk and records it for the window's receipt.
void Custodian::frameIn_handler(FwIndexType, Fw::Buffer& buf) {
    // ... deframe buf -> {window w, sensor i, seq s, payload, T_t} ...
    // Honest custodian verifies the chunk's path against T_t before accepting; omitted here.
    // persist to disk:
    //   char fn[600]; snprintf(fn,sizeof fn,"%s/w%05u_p%05u.bin", m_storeDir, w, pos);
    //   write payload, fflush, fsync.
    m_frames++; this->tlmWrite_FramesStored(m_frames);
    this->bufferReturn_out(0, buf);
}

void Custodian::schedIn_handler(FwIndexType, U32) {
    if (++m_tick >= m_period) { m_tick = 0; signReceipt(false); }
}

void Custodian::signReceipt(bool final) {
    auto it = m_window_chunks.find(m_window);
    const U32 n = (it == m_window_chunks.end()) ? 0 : static_cast<U32>(it->second.size());

    // accepted-position bitmap, ceil(n/8) bytes, unused high bits zero
    std::vector<U8> bm((n + 7) / 8, 0);
    if (it != m_window_chunks.end())
        for (const auto& c : it->second) bm[c.pos / 8] |= (1u << (c.pos % 8));

    U8 msg[512]; size_t mlen = neith_receipt_msg(m_epoch, m_window, n, m_treeRoot,
                                                 bm.data(), bm.size(), msg, sizeof(msg));
    U8 sig[3072]; size_t sl = sizeof(sig);
    const U32 t0 = this->getTime().getUSeconds();
    const int r = neith_xmss_sign(m_xmss, msg, mlen, sig, &sl);          // persists state before return
    const U32 dtUs = this->getTime().getUSeconds() - t0;
    if (r != 0) { this->log_FATAL_KeyExhausted(); return; }
    this->tlmWrite_SignLatencyUs(dtUs);

    m_receipts++; this->tlmWrite_ReceiptsSigned(m_receipts);
    this->log_ACTIVITY_LO_ReceiptSigned(m_window, n);
    // ship (RECEIPT, epoch, window, n, T, bitmap, sig) via receiptOut to service AND regulator ...

    if (m_malicious && (m_window % 3 == 1)) tamperOne();         // Byzantine: alter after signing
    m_window++;
}

void Custodian::tamperOne() {
    auto it = m_window_chunks.find(m_window);
    if (it == m_window_chunks.end() || it->second.empty()) return;
    Chunk& c = it->second.front();
    // overwrite the stored bytes on disk (and in memory) with garbage; the receipt already
    // committed to the real content, so the regulator's audit flags this as CustodyLoss.
    if (!c.payload.empty()) c.payload[0] ^= 0xFF;
    // ... rewrite c's on-disk file with the altered bytes ...
    m_tampered++; this->tlmWrite_Tampered(m_tampered);
    this->log_WARNING_HI_Tampered(m_window, c.sensor, c.seq);
}

void Custodian::OPEN_EPOCH_cmdHandler(FwOpcodeType op, U32 seq, U32 epoch) {
    m_epoch = epoch; m_window = 0; m_tick = 0; m_window_chunks.clear();
    this->log_ACTIVITY_HI_EpochOpened(epoch);
    this->cmdResponse_out(op, seq, Fw::CmdResponse::OK);
}
void Custodian::SET_MALICIOUS_cmdHandler(FwOpcodeType op, U32 seq, bool enable) {
    m_malicious = enable; this->log_ACTIVITY_HI_MaliciousMode(enable);
    this->cmdResponse_out(op, seq, Fw::CmdResponse::OK);
}
void Custodian::STOP_cmdHandler(FwOpcodeType op, U32 seq) {
    signReceipt(true);
    this->cmdResponse_out(op, seq, Fw::CmdResponse::OK);
}

}
