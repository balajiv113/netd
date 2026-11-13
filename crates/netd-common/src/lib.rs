//! Shared pieces of the netd socket-offload path: the wire protocol spoken
//! between the guest agent and netd, a splice-based bidirectional relay and
//! small socket helpers (AF_VSOCK is not covered by std).

pub mod proto;
pub mod relay;
pub mod shm;
pub mod sock;
