use soroban_sas_common::{
    events::{ATTESTED, NONCES_INVALIDATED, REVOKED},
    Attestation, AttestationIssuedEvent, AttestationRevokedEvent, NoncesInvalidatedEvent, UID,
};
use soroban_sdk::{Address, Env};

/// Publishes the `AttestationIssued` event.
///
/// Topics: `(ATTESTED, schema_uid, attester)`.
pub fn publish_attested(env: &Env, attestation: &Attestation) {
    let event = AttestationIssuedEvent {
        uid: attestation.uid.clone(),
        schema_uid: attestation.schema_uid.clone(),
        attester: attestation.attester.clone(),
        recipient: attestation.recipient.clone(),
    };
    env.events().publish(
        (
            ATTESTED,
            attestation.schema_uid.clone(),
            attestation.attester.clone(),
        ),
        event,
    );
}

/// Publishes the `AttestationRevoked` event.
///
/// Topics: `(REVOKED, uid)`. `timestamp` must match the revocation time
/// written to storage so off-chain indexers never diverge from state.
pub fn publish_revoked(env: &Env, uid: &UID, timestamp: u64) {
    env.events().publish(
        (REVOKED, uid.clone()),
        AttestationRevokedEvent {
            uid: uid.clone(),
            timestamp,
        },
    );
}

/// Publishes the `NoncesInvalidated` event (#437).
///
/// Topics: `(NONCES_INVALIDATED, attester)`. `min_nonce`/`max_nonce` describe
/// the inclusive range of delegation nonces cancelled by the watermark advance.
pub fn publish_nonces_invalidated(env: &Env, attester: &Address, min_nonce: u64, max_nonce: u64) {
    env.events().publish(
        (NONCES_INVALIDATED, attester.clone()),
        NoncesInvalidatedEvent {
            attester: attester.clone(),
            min_nonce,
            max_nonce,
        },
    );
}
