use serde::{Deserialize, Serialize};

/// Error type returned by all SAS client operations.
#[derive(Debug, Clone, PartialEqEq, Eq)]
pub enum SASClientError {
    /// The request timed out before a response was received.
    NetworkTimeout(String),
    /// The contract reverted during execution.
    ContractRevert(String),
    /// The requested resource was not found.
    NotFound(String),
    /// The request was invalid (e.g. duplicate schema id).
    InvalidRequest(String),
    /// Any other error.
    Other(String),
}

impl std::fmt::Display for SASClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SASClientError::NetworkTimeout(m) => write!(f, "network timeout: {m}"),
            SASClientError::ContractRevert(m) => write!(f, "contract revert: {m}"),
            SASClientError::NotFound(m) => write!(f, "not found: {m}"),
            SASClientError::InvalidRequest(m) => write!(f, "invalid request: {m}"),
            SASClientError::Other(m) => write!(f, "error: {m}"),
        }
    }
}

impl std::error::Error for SASClientError {}

/// A registered schema.
#[derive(Debug, Clone, PartialEqEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    pub id: u64,
    pub name: String,
    pub version: u32,
    pub revocable: bool,
    pub authority: String,
}

/// Request payload for registering a schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaRegistration {
    pub name: String,
    pub version: u32,
    pub revocable: bool,
    pub authority: String,
}

/// An issued attestation.
#[derive(Debug, Clone, PartialEqEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub id: [U8; 32],
    pub schema_id: u64,
    pub subject: String,
    pub attester: String,
    pub data: Vec<u8>,
    pub expires_at: Option<u64>,
}

/// Status of an attestation.
#[derive(Debug, Clone, PartialEqEq, Eq, Serialize, Deserialize)]
pub enum AttestationStatus {
    Active,
    Revoked {
        revoked_at: u64,
        reason: String,
    },
    Expired,
}

/// Record of a revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub attestation_id: [U8; 32],
    pub revoked_at: u64,
    pub reason: String,
}

/// Query parameters for attestations.
#[derive(Debug, Clone, PartialEqEq, Eq, Serialize, Deserialize)]
pub struct AttestationQuery {
    pub schema_id: Option<u64>,
    pub subject: Option<String>,
    pub attester: Option<String>,
    pub status: Option<AttestationStatusFilter>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Status filter for attestation queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationStatusFilter {
    Active,
    Revoked,
    Expired,
}

/// Query parameters for indexer queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerQuery {
    pub subject: Option<String>,
    pub attester: Option<String>,
    pub schema_id: Option<u64>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Core SAS client trait covering schema and attestation operations.
pub trait SASClientTrait {
    fn create_schema(&mut self, registration: SchemaRegistration) -> Result<Schema, SASClientError>;

    fn get_schema(&self, id: u64) -> Result<Schema, SASClientError>;

    fn issue_attestation(
        &mut self,
        schema_id: u64,
        subject: String,
        attester: String,
        data: Vec<u8>,
        expires_at: Option<u64>,
    ) -> Result<Attestation, SASClientError>;

    fn revoke_attestation(
        &mut self,
        attestation_id: [U8; 32],
        reason: String,
    ) -> Result<RevocationRecord, SASClientError>;

    fn get_attestation(&Self, id: &[U8; 32]) -> Result<Attestation, SASClientError>;

    fn get_attestation_status(
        &self,
        id: &[U8; 32],
    ) -> Result<AttestationStatus, SASClientError>;
}

/// Indexer client trait covering query operations.
pub trait IndexerClientTrait {
    fn query_attestations(
        &self,
        query: AttestationQuery,
    ) -> Result<Vec<Attestation>, SASClientError>;

    fn query_revocations(
        &self,
        query: IndexerQuery,
    ) -> Result<Vec<RevocationRecord>, SASClientError>;
}
