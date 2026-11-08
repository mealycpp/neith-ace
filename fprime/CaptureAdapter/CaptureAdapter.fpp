module Components {

  @ Capture adapter: the flight-segment node of NEITH-ACE. It reads sensor chunks,
  @ assigns a per-sensor sequence number, tags each chunk with a MAC, signs a chained
  @ manifest once per manifest period under the adapter's own key, keeps a bounded resend
  @ buffer, and ships authenticated chunks and manifests downstream. The MAC and XMSS
  @ operations are the same native code the reference implementation uses; F Prime provides
  @ the task, scheduling, buffering, and telemetry around them.
  active component CaptureAdapter {

    # ----------------------------------------------------------------- data path
    @ One sensor payload captured this tick (e.g. a UART frame from GNSS or LiDAR)
    async input port dataIn: Fw.BufferSend

    @ Authenticated chunk/manifest frames out to the integrity-service uplink component
    output port frameOut: Fw.BufferSend

    @ Buffer manager for outgoing frames
    output port bufferGet: Fw.BufferGet
    output port bufferReturn: Fw.BufferSend

    # ----------------------------------------------------------------- scheduling
    @ Heartbeat / manifest tick (wire to a rate group, e.g. 1 Hz = Delta_h)
    async input port schedIn: Svc.Sched

    # ----------------------------------------------------------------- commands
    @ Open a new epoch: sequence numbers restart at zero, a fresh XMSS adapter key is bound
    async command OPEN_EPOCH(epoch: U32)

    @ Orderly stop: seal the final manifest, declare the last sequence, stop capturing
    async command STOP()

    @ Answer a resend request for one sequence number from the bounded buffer
    async command RESEND(seq: U32)

    # ----------------------------------------------------------------- telemetry
    telemetry ChunksCaptured: U32
    telemetry ManifestsSigned: U32
    telemetry Resends: U32
    telemetry LastSeq: U32
    telemetry SignLatencyUs: U32
    telemetry BufferHighWater: U32

    # ----------------------------------------------------------------- events
    event EpochOpened(epoch: U32) severity activity high format "NEITH-ACE epoch {} opened"
    event ManifestSigned(v: U32, through: U32, final: bool) severity activity low \
      format "manifest v={} through seq={} final={}"
    event Stopped(lastSeq: U32) severity activity high format "stopped; final declaration seq={}"
    event SignOverrun(latencyUs: U32, budgetUs: U32) severity warning high \
      format "manifest sign {} us exceeded budget {} us"
    event KeyExhausted() severity fatal format "XMSS one-time key index exhausted"

    # ----------------------------------------------------------------- standard ports
    command recv port cmdIn
    command reg port cmdRegOut
    command resp port cmdResponseOut
    event port eventOut
    text event port textEventOut
    telemetry port tlmOut
    time get port timeGetOut
  }
}
