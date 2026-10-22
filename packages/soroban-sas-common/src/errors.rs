use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SASError {
    /// Lifecycle errors
    /// A contract's `init` was called on an already-initialized instance.
    AlreadyInitialized = 1,
    /// A privileged operation was called before `init` stored an admin.
    NotInitialized = 2,

    /// Schema validation errors
    InvalidSchema = 101,
    SchemaAlreadyExists = 102,
    SchemaNotFound = 103,
    /// A schema definition string violated strict lexical rules: it contained
    /// control characters, invalid/invisible unicode whitespace, or malformed
    /// separators (trailing/leading delimiters, non-canonical spacing). See
    /// `validate_schema_lexical`.
    InvalidSchemaDefinition = 104,

    /// Attestation lifecycle errors
    AttestationNotFound = 201,
    AlreadyRevoked = 202,
    NotRevocable = 203,
    AlreadyExpired = 204,
    DuplicateAttestation = 205,
    /// An attestation's revocability flag violated the schema's revocation
    /// policy: an irrevocable attestation was issued under a `RevocableOnly`
    /// schema. (The inverse violation — a revocable attestation under an
    /// `IrrevocableOnly` schema — reuses `NotRevocable`.)
    InvalidRevocability = 206,

    /// Authorization errors
    Unauthorized = 301,
    InvalidSignature = 302,
    DelegationReplay = 303,

    /// Input validation errors
    InvalidTTL = 401,
    InvalidRecipient = 402,
    /// A fee/value amount was negative.
    InvalidValue = 403,
    /// The configured dependency does not implement the required interface.
    IncompatibleDependency = 404,
    /// The requested attestation batch exceeds the protocol limit.
    BatchTooLarge = 405,
}
