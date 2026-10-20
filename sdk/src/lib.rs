//! Soroban SAS SDK mock client for contract integration unit tests.
///
/// This crate provides an in-memory implementation of the SAS client
/// traits that services can use to unit test their code without running a
/// local standalone Stellar node or mocking low-level HTTP requests.

pub mod testutils;

pub mod client;
pub mod mock;

pub use client::{
    Attestation, AttestationQuery, AttestationStatus, IndexerClientTrait,
    IndexerQuery, RevocationRecord, SASClientError, SASClientTrait, Schema,
    SchemaRegistration,
};
pub use mock::MockSASClient;
