# soroban-sas-sdk-mock
In-memory mock client for the Soroban SAS SDK, designed for contract integration unit tests.

This crate lets services that depend on SAS unit test their code without running a local
standalone Stellar node or mocking low-level HTTP requests. It implements both core client
traits -- `SASClientTrait` and `IndexerClientTrait` -- and simulates schema creation,
attestation issuance, revocation, and indexer queries entirely in memory.

## Features

- In-memory schema registry and attestation storage.
- Revocation records and expiration aware status reporting.
- Indexer queries with subject, attester, schema, and status filters.
- Error injection for network timeouts and contract reverts.
- Call recording with assertion helpers.
- Fast, deterministic, and dependency-free at runtime.

## Usage

Add the crate as a dev-dependency and enable the `testutils` feature:

```toml
[dev-dependencies]
soroban-sas-sdk-mock = { path = "../sdk", features = ["testutils"] }
```

Then write your tests:

```rust
use soroban_sas_sdk_mock::client:{IndexerClientTrait, SASClientTrait, SASClientError};
use soroban_sas_sdk_mock::testutils:{mock_with_schema, sample_attestation_query};

test issues_and_queries() {
    let (mut client, schema_id) = mock_with_schema();

    let attestation = client
        .issue_attestation(
            schema_id,
            "subject-1".to_string(),
            "attester-1".to_string(),
            b"data".to_vec(),
            None,
        )
        .unwrap();

    let results = client
        .query_attestations(sample_attestation_query("subject-1"))
        .unwrap();
    assert_eq!(results[0].id, attestation.id);
}
```

## Error injection

You can simulate failures from the next call:

```rust
use soroban_sas_sdk_mock::client:{SASClientTrait, SASClientError};

test handles_timeout() {
    let (mut client, schema_id) = mock_with_schema();
    client.inject_timeout("boom");
    let err = client
        .issue_attestation(schema_id, "s".to_string(), "a".to_string(), Vec::new(), None)
        .unwrap_err();
    assert_matches!(err, SASClientError::NetworkTimeout(_));
}
```

## Call assertions

Every call is recorded as a `MockCall`. Use `assert_called` and `assert_last_call` to
check dispatched calls and arguments:

```rust
use soroban_sas_sdk_mock::mock::MockCall;

client.assert_called(|call| {
    matches!(
        call,
        MockCall::IssueAttestation { subject, attester, .. }
            if subject == "subject-1" && attester == "attester-1"
    )
});
```

## License

Apache-2.0
