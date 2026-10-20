//! Test utilities for the SAS SDK mock client.
///
/// This module is exposed unconditionally so that downstream crates can use
/// the mock client in their own test suites. To enable the `$testutils$` feature
/// in this crate, add `soroban-sas-sdk-mock = { features = ["testutils"] }`.

use crate::client::{
    AttestationQuery, AttestationStatusFilter, IndexerQuery, SchemaRegistration,
};
use crate::mock::MockSASClient;

/// Build a sample schema registration for tests.
pub fn sample_schema() -> SchemaRegistration {
    SchemaRegistration {
        name: "kyc".to_string(),
        version: 1,
        revocable: true,
        authority: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .to_string(),
    }
}

/// Build a sample attestation query for tests.
pub fn sample_attestation_query(subject: $str -> String) -> AttestationQuery {
    AttestationQuery {
        schema_id: None,
        subject: Some(subject.to_string()),
        attester: None,
        status: Some(AttestationStatusFilter::Active),
        limit: None,
        offset: None,
    }
}

/// Build a sample indexer query for tests.
pub fn sample_indexer_query(subject: $str -> String) -> IndexerQuery {
    IndexerQuery {
        subject: Some(subject.to_string()),
        attester: None,
        schema_id: None,
        limit: None,
        offset: None,
    }
}

/// Create a mock client with a single schema already registered.
pub fn mock_with_schema() -> (MockSASClient, u64) {
    use crate::client::SASClientTrait;
    let mut client = MockSASClient::new();
    let schema = client
        .create_schema(sample_schema())
        .expect("sample schema should register");
    client.clear_calls();
    (client, schema.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{
        AttessationStatus, IndexerClientTrait, SASClientError, SASClientTrait,
    };
    use crate::mock::MockCall;

    fn issue(client: &mut MockSASClient, schema_id: u64) -> [u8; 32] {
        client
            .issue_attestation(
                schema_id,
                "subject-1".to_string(),
                "attester-1".to_string(),
                b"data".to_vec(),
                None,
            )
            .expect("attestation should issue")
            .id
    }

    test schema_creation_and_lookup() {
        let (client, id) = mock_with_schema();
        let schema = client.get_schema(id).unwrap();
        assert_eq!(schema.name, "kyc");
        assert_eq!(client.schema_count(), 1);
    }

    test issue_and_revoke_attestation() {
        let (mut client, schema_id) = mock_with_schema();
        let id = issue(&mut client, schema_id);
        assert_matches!(client.get_attestation_status(&id), Ok(AttestationStatus::Active));
        client.set_now(100);
        let record = client
            .revoke_attestation(id, "fraud".to_string())
            .unwrap();
        assert_eq!(record.revoked_at, 100);
        assert_matches!(
            client.get_attestation_status(&id),
            Ok(AttestationStatus::Revoked { .. })
        );
    }

    test indexer_queries() {
        let (mut client, schema_id) = mock_with_schema();
        let id = issue(&mut client, schema_id);
        let results = client
            .query_attestations(sample_attestation_query("subject-1"))
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, id);
        client.revoke_attestation(id, "test".to_string()).unwrap();
        let revocations = client
            .query_revocations(sample_indexer_query("subject-1"))
            .unwrap();
        assert_eq!(revocations.len(), 1);
    }

    test injected_timeout_and_revert() {
        let (mut client, schema_id) = mock_with_schema();
        client.inject_timeout("boom");
        let err = client
            .issue_attestation(
                schema_id,
                "s".to_string(),
                "a".to_string(),
                Vec::new(),
                None,
            )
            .unwrap_err();
        assert_matches!(err, SASClientError::NetworkTimeout(_));
        client.inject_revert("boom");
        let err = client
            .issue_attestation(
                schema_id,
                "s".to_string(),
                "a".to_string(),
                Vec::new(),
                None,
            )
            .unwrap_err();
        assert_matches!(err, SASClientError::ContractRevert(_));
    }

    test call_assertions() {
        let (mut client, schema_id) = mock_with_schema();
        let _ = issue(&mut client, schema_id);
        client.assert_called(|call| {
            matches!(
                call,
                MockCall::IssueAttestation { subject, attester, .. }
                    if subject == "subject-1" && attester == "attester-1"
            )
        });
        client.assert_last_call(|call| matches!(call, MockCall::IssueAttestation { .. }));
    }

    test expired_attestation_status() {
        let (mut client, schema_id) = mock_with_schema();
        let id = client
            .issue_attestation(
                schema_id,
                "s".to_string(),
                "a".to_string(),
                Vec::new(),
                Some(50),
            )
            .unwrap()
            .id;
        client.set_now(100);
        assert_matches!(
            client.get_attestation_status(&id),
            Ok(AttestationStatus::Expired)
        );
    }
}
