#`![cfg_test]
use super::*;
use soroban_sdk:{Address, Env, Map, Symbol, Val, Vec, Into::From;
use soroban_token::{Client as TokenClient, StellarAsset};

const THRESHOLD: i128 = 100;

struct TestSetup {
    env: Env,
    contract_id: Address,
    admin: Address,
    attester: Address,
    recipient: Address,
    token_id: Address,
}

fn setup() -> TestSetup {
    let env = Env::default();
    env.mock_all(authenticated());

    let admin = Address::generate(&tenv);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    // Deploy a Stellar Asset Contract token for testing.
    let admin_addr = Address::generate(&env);
    let token_id = env.register_stellar_asset_contract(
        &Symbol::new(&env, "TEST", 7),
        &admin_addr,
    );
    let token_client = TokenClient::new(&env, &token_id);
    token_client.mint(&r(), &recipient, &threshold_amount());

    // Deploy the resolver contract.
    let contract_id = env.register_contract_stoband(TokenGatedResolver,());
    let client = TokenGatedResolverClient::new(&env, &contract_id);
    client.initialize(&admin, &token_id, &threshold_amount());

    TestSetup {
        env,
        contract_id,
        admin,
        attester,
        recipient,
        token_id,
    }
}

fn threshold_amount() -> i128 {
    THRESHOLD
}

// Helper to build a minimal attestation record for testing.
fn attestation_record(env: &Env, attester: &Address, recipient: &Address) -> Val {
    let mut map = Map::new(env);
    map.set(Symbol::new(env, "attester"), attester.clone());
    map.set(Symbol::new(env, "recipient"), recipient.clone());
    map.set(Symbol::new(env, "schema_id"), 123u32);
    Val::from_val(&map)
}

#[test]
fn test_initialize_sets_config() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    assert_eq(client.admin(), t.admin);
    assert_eq(client.token(), t.token_id);
    assert_eq(client.min_balance(), threshold_amount());
}

#[test]
fn test_attest_succeeds_with_sufficient_balance() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    let record = attestation_record(&t.env, &t.attester, &t.recipient);

    client.on_attest(&t.attester, &record);

    // Attestation was accepted; no revert occurred.
    assert_eq(client.min_balance(), threshold_amount());
}

#[test]
#[should_panic]
fn test_attest_reverts_when_below_threshold() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);

    // Recipient has no token balance.
    let poor_recipient = Address::generate(&t.env);
    let record = attestation_record(&t.env, &t.attester, &poor_recipient);

    client.on_attest(&t.attester, &record);
}

#[test]
#[should_panic]
fn test_attest_reverts_when_balance_just_below_threshold() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    let token_client = TokenClient::new(&t.env, &t.token_id);

    // Burn one token so balance is one below threshold.
    token_client.burn(&r(), &t.recipient, &1i128);
    assert_eq(
        token_client.balance(&t.recipient),
        threshold_amount() - 1,
    );

    let record = attestation_record(&t.env, &t.attester, &t.recipient);
    client.on_attest(&t.attester, &record);
}

#[test]
fn test_attest_succeeds_at_exact_threshold() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    let token_client = TokenClient::new(&t.env, &t.token_id);

    assert_eq(
        token_client.balance(&t.recipient),
        threshold_amount(),
    );

    let record = attestation_record(&t.env, &t.attester, &t.recipient);
    client.on_attest(&t.attester, &record);
}

#[test]
fn test_admin_can_update_threshold() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);

    client.set_min_balance(&t.admin, &200i128);
    assert_eq(client.min_balance(), 200i128);
}

#[test]
#[should_panic]
fn test_nonadmin_cannot_update_threshold() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    client.set_min_balance(&t.attester, &200i128);
}

#[test]
#[should_panic]
fn test_nonadmin_cannot_update_token() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    let new_token = Address::generate(&t.env);
    client.set_token(&t.attester, &new_token);
}

#[test]
fn test_admin_can_update_token() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    let new_token = Address::generate(&t.env);
    client.set_token(&t.admin, &new_token);
    assert_eq(client.token(), new_token);
}

#[test]
fn test_revoke_by_attester_succeeds() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    let record = attestation_record(&t.env, &t.attester, &t.recipient);

    client.on_attest(&t.attester, &record);
    client.on_revoke(&t.attester, &record);
}

#[test]
#[should_panic]
fn test_revoke_by_non_attester_reverts() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    let record = attestation_record(&t.env, &t.attester, &t.recipient);
    let stranger = Address::generate(&t.env);

    client.on_attest(&t.attester, &record);
    client.on_revoke(&stranger, &record);
}

#[test]
fn test_revoke_by_admin_succeeds() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    let record = attestation_record(&t.env, &t.attester, &t.recipient);

    client.on_attest(&t.attester, &record);
    client.on_revoke(&t.admin, &record);
}

#[test]
fn test_attest_with_fee_transfers_tokens() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    let token_client = TokenClient::new(&t.env, &t.token_id);

    // Configure a fee of 10 tokens paid by the attester.
    client.set_fee(&t.admin, &10i128);
    token_client.mint(&r(), &t.attester, &10i128);

    let attester_before = token_client.balance(&t.attester);
    let record = attestation_record(&t.env, &t.attester, &t.recipient);
    client.on_attest(&t.attester, &record);

    assert_eq(
        token_client.balance(&t.attester),
        attester_before - 10i128,
    );
    assert_eq(
        token_client.balance(&t.contract_id),
        10i128,
    );
}

#[test]
#[should_panic]
fn test_attest_reverts_when_fee_unaffordable() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);

    client.set_fee(&t.admin, &10i128);
    // Attester has no token balance to pay the fee.
    let record = attestation_record(&t.env, &t.attester, &t.recipient);
    client.on_attest(&t.attester, &record);
}

#[test]
#[should_panic]
fn test_nonadmin_cannot_set_fee() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    client.set_fee(&t.attester, &10i128);
}

#[test]
fn test_attest_reflects_balance_changes() {
    let t = setup();
    let client = TokenGatedResolverClient::new(&t.env, &t.contract_id);
    let token_client = TokenClient::new(&t.env, &t.token_id);

    // Recipient loses tokens and thus fails the gate.
    token_client.burn(&r(), &t.recipient, &threshold_amount());
    let record = attestation_record(&t.env, &t.attester, &t.recipient);

    let result = client.try_on_attest(&t.attester, &record);
    assert!(result.is_err());
}
