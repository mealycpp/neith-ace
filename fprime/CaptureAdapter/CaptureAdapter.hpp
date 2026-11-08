// NEITH-ACE capture-adapter F' component (flight segment). Autocoded base is generated
// by fprime-util from CaptureAdapter.fpp; this is the hand-written implementation class.
#ifndef Components_CaptureAdapter_HPP
#define Components_CaptureAdapter_HPP
#include "neith_shim.h"
#include "Components/CaptureAdapter/CaptureAdapterComponentAc.hpp"
#include <cstdio>
#include <map>
#include <vector>

namespace Components {

class CaptureAdapter : public CaptureAdapterComponentBase {
  public:
    CaptureAdapter(const char* compName);
    void init(FwSizeType queueDepth, FwEnumStoreType instance = 0);
    ~CaptureAdapter();

    // Provisioned at init: this adapter's sensor id, MAC key, XMSS state path, params.
    void configure(U16 sensorId, const U8 key[16], const char* xmssParam,
                   const char* xmssStatePath, U32 manifestPeriodTicks, U32 bufSize);
    // Measurement mode: replay a recorded sensor log through the capture path on each
    // schedIn tick (no UART driver needed). blockBytes==0 -> one chunk per line.
    // Opens epoch `epoch` immediately so no ground command is required.
    void setReplay(const char* path, U32 blockBytes, U32 chunksPerTick, U32 epoch);

  private:
    // port handlers (names match the .fpp)
    void dataIn_handler(FwIndexType portNum, Fw::Buffer& buf) override;
    void schedIn_handler(FwIndexType portNum, U32 context) override;
    void OPEN_EPOCH_cmdHandler(FwOpcodeType op, U32 seq, U32 epoch) override;
    void STOP_cmdHandler(FwOpcodeType op, U32 seq) override;
    void RESEND_cmdHandler(FwOpcodeType op, U32 cmdSeq, U32 dataSeq) override;

    // internal
    void sealManifest(bool final);
    void capture(const U8* payload, U32 len);
    void openEpoch(U32 epoch);
    U32  nowUs() const;
    void shipChunk(U32 s, const U8* payload, U32 len, const U8 tag[32]);

    U16 m_sensor = 0;
    U8  m_key[16] = {0};
    ::neith_xmss_ctx* m_xmss = nullptr;
    FILE* m_replay = nullptr; U32 m_replayBlock = 0, m_replayPerTick = 0;
    bool m_epochOpen = false;
    U32 m_epoch = 0;
    I64 m_seq = -1;              // highest sequence captured
    U32 m_v = 0;                 // manifest counter
    U32 m_manifestPeriod = 1;    // ticks between manifests
    U32 m_tick = 0;
    U32 m_bufSize = 4096;
    bool m_stopped = false;

    U8  m_prevManifest[32];                         // manifest-chain predecessor digest
    std::map<U32, std::vector<U8>> m_buffer;        // seq -> payload, bounded resend buffer
    std::vector<std::pair<U32, std::array<U8,32>>> m_pending;  // (seq, digest) since last manifest

    U32 m_chunks = 0, m_manifests = 0, m_resends = 0, m_highWater = 0;
};

}
#endif
