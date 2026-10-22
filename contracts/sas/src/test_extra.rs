use crate::{SASClient, SAS};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sas_common::{Attestation, SASError, SchemaRecord, UID};
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, String as SorobanString};

pub mod mock_registry {
    use super::*;
    use soroban_sdk::{contract, contractimpl, Env, Symbol};

    #[contract]
    pub struct MockRegistry;

    // Store for active flag: use persistent storage key (DEPRECATED, uid) similarly
    const DEPRECATED: Symbol = soroban_sdk::symbol_short!("DEPRECATE");
    const POLICY: Symbol = soroban_sdk::symbol_short!("POLICY");

    #[contractimpl]
    impl MockRegistry {
        pub fn sasreg(_env: Env) -> bool {
            true
        }
        /// Tri-state policy lookup (#448). Mirrors the real registry: an
        /// explicitly stored policy wins, otherwise derive from `revocable`.
        pub fn get_schema_policy(env: Env, uid: UID) -> soroban_sas_common::RevocationPolicy {
            if let Some(p) = env
                .storage()
                .persistent()
                .get::<_, soroban_sas_common::RevocationPolicy>(&(POLICY, uid.clone()))
            {
                return p;
            }
            match env.storage().persistent().get::<UID, SchemaRecord>(&uid) {
                Some(rec) => soroban_sas_common::RevocationPolicy::from(rec.revocable),
                None => soroban_sas_common::RevocationPolicy::Permissive,
            }
        }
        pub fn set_policy(env: Env, uid: UID, policy: soroban_sas_common::RevocationPolicy) {
            env.storage().persistent().set(&(POLICY, uid), &policy);
        }
        pub fn get_schema(env: Env, uid: UID) -> Option<SchemaRecord> {
            if env
                .storage()
                .persistent()
                .get::<_, bool>(&(DEPRECATED, uid.clone()))
                .unwrap_or(false)
            {
                return None;
            }
            // Return the stored record for uid, if one was set via set_schema.
            env.storage().persistent().get::<UID, SchemaRecord>(&uid)
        }
        pub fn set_schema(env: Env, uid: UID, record: SchemaRecord) {
            env.storage().persistent().set(&uid, &record);
        }
        pub fn set_deprecated(env: Env, uid: UID, val: bool) {
            env.storage().persistent().set(&(DEPRECATED, uid), &val);
        }
    }
}

#[test]
fn test_verify_offchain_rejects_unknown_and_deprecated_schema() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let seed = [31u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let attester_strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
    let attester = Address::from_string(&SorobanString::from_str(&env, &attester_strkey));
    let recipient = Address::generate(&env);

    // Create a valid schema record in mock registry
    let schema_uid = UID(BytesN::from_array(&env, &[77u8; 32]));
    let resolver = Address::generate(&env);
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: resolver.clone(),
        revocable: true,
        schema: SorobanString::from_str(&env, "bool like_soroban"),
    };
    let mock_client = mock_registry::MockRegistryClient::new(&env, &registry_id);
    // Need to store via contract call so storage is in contract's context
    mock_client.set_schema(&schema_uid, &record);

    let att_uid = UID(BytesN::from_array(&env, &[42u8; 32]));
    let attestation = Attestation {
        uid: att_uid.clone(),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::from_slice(&env, &[1, 2, 3]),
    };
    let nonce = 7u64;
    let domain = soroban_sas_common::AttestationDomain {
        network_id: env.ledger().network_id(),
        contract: sas_id.clone(),
        nonce,
    };
    let payload_hash = soroban_sas_common::hash_offchain_attestation(&env, &attestation, &domain);
    let signature = signing_key.sign(&payload_hash.to_array());
    let sig_bytes = BytesN::from_array(&env, &signature.to_bytes());
    let pub_bytes = BytesN::from_array(&env, &public_key);

    // Valid should succeed
    let res =
        sas_client.try_verify_offchain_attestation(&attestation, &nonce, &pub_bytes, &sig_bytes);
    assert!(res.is_ok());

    // Unknown schema should be InvalidSchema
    let unknown_schema_uid = UID(BytesN::from_array(&env, &[99u8; 32]));
    let mut att_unknown = attestation.clone();
    att_unknown.schema_uid = unknown_schema_uid.clone();
    let payload_hash2 = soroban_sas_common::hash_offchain_attestation(&env, &att_unknown, &domain);
    let sig2 = signing_key.sign(&payload_hash2.to_array());
    let sig_bytes2 = BytesN::from_array(&env, &sig2.to_bytes());
    let res =
        sas_client.try_verify_offchain_attestation(&att_unknown, &nonce, &pub_bytes, &sig_bytes2);
    assert_eq!(res, Err(Ok(SASError::InvalidSchema.into())));

    // Deprecated should also be InvalidSchema and invalidate prior
    mock_client.set_deprecated(&schema_uid, &true);
    let res =
        sas_client.try_verify_offchain_attestation(&attestation, &nonce, &pub_bytes, &sig_bytes);
    assert_eq!(res, Err(Ok(SASError::InvalidSchema.into())));

    // On-chain attest with deprecated should also be InvalidSchema
    let att2 = Attestation {
        uid: UID(BytesN::from_array(&env, &[43u8; 32])),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: Address::generate(&env),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };
    env.mock_all_auths();
    let res = sas_client.try_attest(&att2);
    assert_eq!(res, Err(Ok(SASError::InvalidSchema.into())));
}

// --- #448 revocation policy enforcement in SAS core -------------------------

/// Sets up an initialized SAS bound to a fresh mock registry, returning the
/// SAS and registry clients.
fn setup_sas_with_registry(
    env: &Env,
) -> (
    SASClient<'static>,
    mock_registry::MockRegistryClient<'static>,
) {
    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(env, &sas_id);
    let admin = Address::generate(env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);
    let mock_client = mock_registry::MockRegistryClient::new(env, &registry_id);
    (sas_client, mock_client)
}

fn policy_attestation(
    env: &Env,
    schema_uid: &UID,
    uid_seed: [u8; 32],
    revocable: bool,
) -> Attestation {
    Attestation {
        uid: UID(BytesN::from_array(env, &uid_seed)),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: Address::generate(env),
        attester: Address::generate(env),
        revocable,
        data: Bytes::new(env),
    }
}

#[test]
fn test_policy_irrevocable_only_rejects_revocable_attestation() {
    use soroban_sas_common::RevocationPolicy;
    let env = Env::default();
    let (sas_client, mock_client) = setup_sas_with_registry(&env);

    let schema_uid = UID(BytesN::from_array(&env, &[10u8; 32]));
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: Address::generate(&env),
        revocable: false,
        schema: SorobanString::from_str(&env, "bool like"),
    };
    mock_client.set_schema(&schema_uid, &record);
    mock_client.set_policy(&schema_uid, &RevocationPolicy::IrrevocableOnly);

    env.mock_all_auths();
    let revocable_att = policy_attestation(&env, &schema_uid, [11u8; 32], true);
    assert_eq!(
        sas_client.try_attest(&revocable_att),
        Err(Ok(SASError::NotRevocable.into()))
    );

    let irrevocable_att = policy_attestation(&env, &schema_uid, [12u8; 32], false);
    assert!(sas_client.try_attest(&irrevocable_att).is_ok());
}

#[test]
fn test_policy_revocable_only_rejects_irrevocable_attestation() {
    use soroban_sas_common::RevocationPolicy;
    let env = Env::default();
    let (sas_client, mock_client) = setup_sas_with_registry(&env);

    let schema_uid = UID(BytesN::from_array(&env, &[20u8; 32]));
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: Address::generate(&env),
        revocable: true,
        schema: SorobanString::from_str(&env, "bool like"),
    };
    mock_client.set_schema(&schema_uid, &record);
    mock_client.set_policy(&schema_uid, &RevocationPolicy::RevocableOnly);

    env.mock_all_auths();
    let irrevocable_att = policy_attestation(&env, &schema_uid, [21u8; 32], false);
    assert_eq!(
        sas_client.try_attest(&irrevocable_att),
        Err(Ok(SASError::InvalidRevocability.into()))
    );

    let revocable_att = policy_attestation(&env, &schema_uid, [22u8; 32], true);
    assert!(sas_client.try_attest(&revocable_att).is_ok());
}

#[test]
fn test_policy_permissive_allows_either_flag() {
    use soroban_sas_common::RevocationPolicy;
    let env = Env::default();
    let (sas_client, mock_client) = setup_sas_with_registry(&env);

    let schema_uid = UID(BytesN::from_array(&env, &[30u8; 32]));
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: Address::generate(&env),
        revocable: true,
        schema: SorobanString::from_str(&env, "bool like"),
    };
    mock_client.set_schema(&schema_uid, &record);
    mock_client.set_policy(&schema_uid, &RevocationPolicy::Permissive);

    env.mock_all_auths();
    assert!(sas_client
        .try_attest(&policy_attestation(&env, &schema_uid, [31u8; 32], true))
        .is_ok());
    assert!(sas_client
        .try_attest(&policy_attestation(&env, &schema_uid, [32u8; 32], false))
        .is_ok());
}

#[test]
fn test_policy_falls_back_to_bool_when_registry_lacks_policy() {
    let env = Env::default();
    let (sas_client, mock_client) = setup_sas_with_registry(&env);

    let schema_uid = UID(BytesN::from_array(&env, &[40u8; 32]));
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: Address::generate(&env),
        revocable: false,
        schema: SorobanString::from_str(&env, "bool like"),
    };
    mock_client.set_schema(&schema_uid, &record);

    env.mock_all_auths();
    assert_eq!(
        sas_client.try_attest(&policy_attestation(&env, &schema_uid, [41u8; 32], true)),
        Err(Ok(SASError::NotRevocable.into()))
    );
    assert!(sas_client
        .try_attest(&policy_attestation(&env, &schema_uid, [42u8; 32], false))
        .is_ok());
}

// --- #437 conditional delegation revocations with nonce ranges --------------

fn ed25519_attester(env: &Env, seed: [u8; 32]) -> (Address, SigningKey, [u8; 32]) {
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
    let address = Address::from_string(&SorobanString::from_str(env, &strkey));
    (address, signing_key, public_key)
}

#[test]
fn test_invalidate_nonces_advances_watermark_and_blocks_replay() {
    let env = Env::default();
    let (sas_client, mock_client) = setup_sas_with_registry(&env);
    env.mock_all_auths();

    let (attester, signing_key, public_key) = ed25519_attester(&env, [55u8; 32]);
    let pub_bytes = BytesN::from_array(&env, &public_key);

    assert_eq!(sas_client.get_nonce_highwater_mark(&attester), 0);

    sas_client.invalidate_nonces(&attester, &1u64, &10u64);
    assert_eq!(sas_client.get_nonce_highwater_mark(&attester), 10);

    let schema_uid = UID(BytesN::from_array(&env, &[60u8; 32]));
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: Address::generate(&env),
        revocable: true,
        schema: SorobanString::from_str(&env, "bool like"),
    };
    mock_client.set_schema(&schema_uid, &record);

    let att_uid = UID(BytesN::from_array(&env, &[61u8; 32]));
    let attestation = Attestation {
        uid: att_uid.clone(),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: Address::generate(&env),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };
    sas_client.attest(&attestation);

    let cancelled_nonce = 5u64;
    let domain = soroban_sas_common::AttestationDomain {
        network_id: env.ledger().network_id(),
        contract: sas_client.address.clone(),
        nonce: cancelled_nonce,
    };
    let payload_hash =
        soroban_sas_common::hash_delegated_revocation(&env, &att_uid, &attester, &domain);
    let sig = signing_key.sign(&payload_hash.to_array());
    let sig_bytes = BytesN::from_array(&env, &sig.to_bytes());

    let res =
        sas_client.try_revoke_by_delegation(&att_uid, &cancelled_nonce, &sig_bytes, &pub_bytes);
    assert_eq!(res, Err(Ok(SASError::DelegationReplay.into())));

    let fresh_nonce = 11u64;
    let domain2 = soroban_sas_common::AttestationDomain {
        network_id: env.ledger().network_id(),
        contract: sas_client.address.clone(),
        nonce: fresh_nonce,
    };
    let payload_hash2 =
        soroban_sas_common::hash_delegated_revocation(&env, &att_uid, &attester, &domain2);
    let sig2 = signing_key.sign(&payload_hash2.to_array());
    let sig_bytes2 = BytesN::from_array(&env, &sig2.to_bytes());
    assert!(sas_client
        .try_revoke_by_delegation(&att_uid, &fresh_nonce, &sig_bytes2, &pub_bytes)
        .is_ok());
}

#[test]
fn test_invalidate_nonces_cannot_decrease_watermark() {
    let env = Env::default();
    let (sas_client, _mock_client) = setup_sas_with_registry(&env);
    env.mock_all_auths();
    let attester = Address::generate(&env);

    sas_client.invalidate_nonces(&attester, &1u64, &50u64);
    assert_eq!(sas_client.get_nonce_highwater_mark(&attester), 50);

    assert_eq!(
        sas_client.try_invalidate_nonces(&attester, &1u64, &40u64),
        Err(Ok(SASError::InvalidValue.into()))
    );
    assert_eq!(
        sas_client.try_invalidate_nonces(&attester, &1u64, &50u64),
        Err(Ok(SASError::InvalidValue.into()))
    );
    assert_eq!(
        sas_client.try_invalidate_nonces(&attester, &60u64, &55u64),
        Err(Ok(SASError::InvalidValue.into()))
    );
    assert_eq!(sas_client.get_nonce_highwater_mark(&attester), 50);
}

#[test]
fn test_set_nonce_highwater_mark_bulk_invalidation() {
    let env = Env::default();
    let (sas_client, _mock_client) = setup_sas_with_registry(&env);
    env.mock_all_auths();
    let attester = Address::generate(&env);

    sas_client.set_nonce_highwater_mark(&attester, &1000u64);
    assert_eq!(sas_client.get_nonce_highwater_mark(&attester), 1000);

    assert_eq!(
        sas_client.try_set_nonce_highwater_mark(&attester, &999u64),
        Err(Ok(SASError::InvalidValue.into()))
    );
}
