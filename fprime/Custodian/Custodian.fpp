module Components {

  @ Custodian: the ground-segment node of NEITH-ACE running on SOBEK. It receives the chunk
  @ and manifest frames, persists them, and signs one custody receipt per window with its own
  @ XMSS key (distinct from the adapter and the integrity service). In malicious mode it is a
  @ Byzantine custodian: it signs an honest receipt and then alters the stored bytes of a chunk
  @ it acknowledged. The independent regulator, auditing the store against the published roots
  @ and these signed receipts, is what catches the tampering --- the custodian's signature over
  @ the leaf content it promised to retain is non-repudiable.
  active component Custodian {

    @ Incoming authenticated frames (chunks, manifests) from the uplink
    async input port frameIn: Fw.BufferSend

    @ Signed custody receipts out to the integrity service and the regulator
    output port receiptOut: Fw.BufferSend
    output port bufferGet: Fw.BufferGet
    output port bufferReturn: Fw.BufferSend

    @ Receipt-period tick (wire to a rate group)
    async input port schedIn: Svc.Sched

    @ Open an epoch; bind a fresh receipt key
    async command OPEN_EPOCH(epoch: U32)
    @ Byzantine switch: when enabled, alter one acknowledged chunk per receipt (evaluation only)
    async command SET_MALICIOUS(enable: bool)
    @ Orderly stop: sign the final receipt
    async command STOP()

    telemetry FramesStored: U32
    telemetry ReceiptsSigned: U32
    telemetry Tampered: U32
    telemetry SignLatencyUs: U32
    telemetry BytesOnDisk: U32

    event EpochOpened(epoch: U32) severity activity high format "custodian epoch {} opened"
    event MaliciousMode(enabled: bool) severity activity high format "malicious custody = {}"
    event ReceiptSigned(window: U32, accepted: U32) severity activity low \
      format "receipt for window {} over {} accepted chunks"
    event Tampered(window: U32, sensor: U16, seq: U32) severity warning high \
      format "altered stored chunk after receipting: window {} sensor {} seq {}"
    event KeyExhausted() severity fatal format "custodian XMSS key exhausted"

    command recv port cmdIn
    command reg port cmdRegOut
    command resp port cmdResponseOut
    event port eventOut
    text event port textEventOut
    telemetry port tlmOut
    time get port timeGetOut
  }
}
