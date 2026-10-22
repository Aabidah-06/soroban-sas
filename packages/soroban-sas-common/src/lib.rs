#![allow(unexpected_cfgs)]
#![no_std]
pub mod errors;
pub mod events;
pub mod macros;
pub mod merkle;
pub mod signature;
pub mod typed_data;
pub mod validation;

pub use errors::*;
pub use events::*;
pub use merkle::*;
pub use signature::*;
pub use typed_data::*;
pub use validation::*;

use soroban_sdk::{contracttype, Address, Bytes, String};

/// Approximate number of ledgers in one year at five seconds per ledger.
pub const LEDGERS_IN_ONE_YEAR: u32 = 6_307_200;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UID(pub soroban_sdk::BytesN<32>);

/// Tri-state on-chain schema revocation policy (#448).
///
/// A schema creator uses this to constrain the `revocable` flag of every
/// attestation issued under the schema:
///
/// * `RevocableOnly` — every attestation MUST be revocable; issuing an
///   irrevocable attestation fails with [`SASError::InvalidRevocability`].
/// * `IrrevocableOnly` — every attestation MUST be irrevocable; issuing a
///   revocable attestation fails with [`SASError::NotRevocable`]. This is the
///   policy that the legacy boolean `revocable: false` maps to.
/// * `Permissive` — the attester chooses either flag freely. This is the
///   policy that the legacy boolean `revocable: true` maps to.
///
/// Existing boolean `revocable` schemas map cleanly via [`From<bool>`], so the
/// policy model is backwards compatible with records registered before #448.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RevocationPolicy {
    /// All attestations under this schema must be revocable.
    RevocableOnly = 1,
    /// All attestations under this schema must be irrevocable.
    IrrevocableOnly = 2,
    /// The attester may choose whether each attestation is revocable.
    Permissive = 3,
}

impl From<bool> for RevocationPolicy {
    fn from(revocable: bool) -> Self {
        if revocable {
            RevocationPolicy::Permissive
        } else {
            RevocationPolicy::IrrevocableOnly
        }
    }
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaRecord {
    pub uid: UID,
    pub resolver: Address,
    pub revocable: bool,
    pub schema: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)] // Optimize storage serialization
pub struct Attestation {
    pub uid: UID,
    pub schema_uid: UID,
    pub time: u64,
    pub expiration_time: u64,
    pub revocation_time: u64,
    pub ref_uid: UID,
    pub recipient: Address,
    pub attester: Address,
    pub revocable: bool,
    pub data: Bytes,
}

#[cfg(test)]
mod test;
