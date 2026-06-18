//! The orchestration layer: gather host state, gate mutations, audit, detect drift and
//! apply firewall changes safely.

pub mod audit;
pub mod drift;
pub mod firewall_ops;
pub mod inventory;
pub mod safety;
