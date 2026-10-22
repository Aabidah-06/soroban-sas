//! Standardized event topics and payloads emitted by the SAS contracts.
//!
//! Off-chain indexing services (e.g. The Graph, Soroban Zephyr) subscribe to
//! these topics to build fast, queryable materialized views of the
//! attestation graph without reading contract storage.

use crate::UID;
use soroban_sdk::{contracttype, symbol_short, Address, Symbol};

/// First topic of every `AttestationIssued` event.
pub const ATTESTED: Symbol = symbol_short!("ATTESTED");
/// First topic of every `AttestationRevoked` event.
pub const REVOKED: Symbol = symbol_short!("REVOKED");
/// First topic of every `SchemaRegistered` event.
pub const REGISTERED: Symbol = symbol_short!("REGISTER");
/// First topic of every `SchemaOwnershipProposed` event (#446).
pub const SCHEMA_OWNERSHIP_PROPOSED: Symbol = symbol_short!("SCHPROP");
/// First topic of every `SchemaOwnershipTransferred` event (#446).
pub const SCHEMA_OWNERSHIP_TRANSFERRED: Symbol = symbol_short!("SCHOWN");
/// First topic of every `SchemaOwnershipTransferCancelled` event (#446).
pub const SCHEMA_OWNERSHIP_CANCELLED: Symbol = symbol_short!("SCHCANC");
/// First topic of every `NoncesInvalidated` event (#437).
pub const NONCES_INVALIDATED: Symbol = symbol_short!("NONCEINV");

/// Payload of the `SchemaRegistered` event.
///
/// Published with topics `(REGISTERED, schema_uid)`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaRegisteredEvent {
    pub schema_uid: UID,
    pub owner: Address,
}

/// Payload of the `AttestationIssued` event.
///
/// Published with topics `(ATTESTED, schema_uid, attester)` so indexers can
/// filter by schema or attester without decoding the payload.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationIssuedEvent {
    pub uid: UID,
    pub schema_uid: UID,
    pub attester: Address,
    pub recipient: Address,
}

/// Payload of the `SchemaOwnershipProposed` event (#446).
///
/// Published with topics `(SCHEMA_OWNERSHIP_PROPOSED, schema_uid)` when the
/// current owner proposes a new owner in the two-step transfer.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaOwnershipProposedEvent {
    pub schema_uid: UID,
    pub current_owner: Address,
    pub proposed_owner: Address,
}

/// Payload of the `SchemaOwnershipTransferred` event (#446).
///
/// Published with topics `(SCHEMA_OWNERSHIP_TRANSFERRED, schema_uid)` when the
/// proposed owner claims ownership.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaOwnershipTransferredEvent {
    pub schema_uid: UID,
    pub old_owner: Address,
    pub new_owner: Address,
}

/// Payload of the `NoncesInvalidated` event (#437).
///
/// Published with topics `(NONCES_INVALIDATED, attester)`. `min_nonce` and
/// `max_nonce` describe the inclusive range of delegation nonces cancelled by
/// advancing the attester's high-water mark.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoncesInvalidatedEvent {
    pub attester: Address,
    pub min_nonce: u64,
    pub max_nonce: u64,
}

/// Payload of the `AttestationRevoked` event.
///
/// Published with topics `(REVOKED, uid)`. `timestamp` is the ledger
/// timestamp recorded as the attestation's revocation time.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationRevokedEvent {
    pub uid: UID,
    pub timestamp: u64,
}
