#ifndef Components_Custodian_HPP
#define Components_Custodian_HPP
#include "Components/Custodian/CustodianComponentAc.hpp"
#include "neith_shim.h"
#include <map>
#include <vector>

namespace Components {

class Custodian : public CustodianComponentBase {
  public:
    Custodian(const char* compName);
    void init(FwSizeType queueDepth, FwEnumStoreType instance = 0);
    ~Custodian();
    // storeDir: where chunks are persisted; xmssStatePath/param: the custodian's receipt key
    void configure(const char* storeDir, const char* xmssParam, const char* xmssStatePath,
                   U32 receiptPeriodTicks);

  private:
    void frameIn_handler(FwIndexType portNum, Fw::Buffer& buf) override;
    void schedIn_handler(FwIndexType portNum, U32 context) override;
    void OPEN_EPOCH_cmdHandler(FwOpcodeType op, U32 seq, U32 epoch) override;
    void SET_MALICIOUS_cmdHandler(FwOpcodeType op, U32 seq, bool enable) override;
    void STOP_cmdHandler(FwOpcodeType op, U32 seq) override;

    void signReceipt(bool final);
    void tamperOne();

    struct Chunk { U16 sensor; U32 seq; std::vector<U8> payload; U32 pos; };

    U32  m_epoch = 0;
    U32  m_window = 0;             // current receipt window
    U32  m_period = 1, m_tick = 0;
    bool m_malicious = false;
    char m_storeDir[512] = {0};
    ::neith_xmss_ctx* m_xmss = nullptr;

    std::map<U32, std::vector<Chunk>> m_window_chunks;   // window -> chunks accepted this window
    U8   m_treeRoot[32];                                 // T_t for the current window (from headers)
    U32  m_frames = 0, m_receipts = 0, m_tampered = 0, m_bytes = 0;
};

}
#endif
