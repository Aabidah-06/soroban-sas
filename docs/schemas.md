# Schema Definitions and Payloads

Schemas are the core mechanism for defining the structure and validation rules for attestations in the Soroban Attestation Service (SAS). 

## Schema Registry
The Schema Registry smart contract acts as the source of truth for all valid schema types. When an issuer creates an attestation, the SAS contract verifies the schema against the registry.

## Schema Structure
A schema is stored as a comma-separated list of `name Type` field definitions.
Each field must name the attribute and its Soroban type, for example:

```text
first_name String, last_name String, document_id Bytes
```

This keeps the on-chain representation compact while still giving the
contracts and CLI enough structure to reject malformed inputs.

### Creating a Schema
When registering a schema, the caller provides a deterministic UID and the
schema string above. The validator rejects whitespace-only values, entries
without at least one `name Type` pair, and strings that do not resemble a
field declaration.

## Schema Definition Hygiene

Schema definition strings are validated with strict lexical rules before the
structural `name Type` parser runs. A registration is rejected with
`SASError::InvalidSchemaDefinition` when the string contains:

- ASCII control characters (`< 0x20`, including tabs, newlines, carriage
  returns, and the null byte) or `DEL` (`0x7F`);
- invalid UTF-8, or invisible / non-ASCII unicode whitespace such as a
  non-breaking space (`U+00A0`), zero-width space (`U+200B`), byte-order mark
  (`U+FEFF`), or ideographic space (`U+3000`);
- malformed separators: a leading or trailing comma, two consecutive spaces,
  a space immediately before a comma, or more than one space after a comma.

These rules enforce a single canonical spelling for any given schema. Without
them, two visually identical schema strings that differ only by an invisible
code point or redundant whitespace would hash to different UIDs, producing
phantom duplicate schemas and divergence between on-chain and off-chain
parsers.

## Revocation Policy

Each schema carries a tri-state `RevocationPolicy` that constrains the
`revocable` flag of every attestation issued under it:

| Policy            | Allowed attestation `revocable` | Rejection error        |
| ----------------- | ------------------------------- | ---------------------- |
| `RevocableOnly`   | `true` only                     | `InvalidRevocability`  |
| `IrrevocableOnly` | `false` only                    | `NotRevocable`         |
| `Permissive`      | `true` or `false`               | (none)                 |

Register a schema with an explicit policy via `register_with_policy`. The
legacy boolean `register` entrypoint maps cleanly onto the policy model:
`revocable: true` becomes `Permissive` and `revocable: false` becomes
`IrrevocableOnly`, preserving the behaviour of schemas registered before the
policy model existed. The SAS core contract reads the policy back through the
registry's `get_schema_policy` view and validates it during attestation
creation, so the policy is enforced regardless of which entrypoint issued the
attestation.

**Developer implications:** choose `RevocableOnly` when downstream consumers
must be able to rely on an attestation being withdrawable (e.g. revocable
credentials, memberships); choose `IrrevocableOnly` for permanent records
(e.g. audit logs, immutable proofs). `Permissive` defers the decision to the
attester per attestation. A schema's policy is fixed at registration and is
part of neither the UID preimage nor mutable afterwards.

## Verification
When verifying an attestation off-chain or on-chain, the client decodes the raw `data` field using the associated schema definition. The schema enforces that every issued attestation strictly conforms to the expected layout.

## Resolver Callbacks
Schemas can optionally specify a `resolver` contract address. If specified, the SAS contract will invoke callbacks on the resolver to enforce schema-specific rules or synchronize dependent state.

### `on_attest`
Invoked exactly once when a new attestation is issued using the schema.
- **Payload:** The full `Attestation` record (including the assigned UID).

### `on_revoke`
Invoked exactly once when an existing attestation using the schema is revoked.
- **Payload:** The updated `Attestation` record, carrying the revocation timestamp.

In both cases, failure of the resolver callback will silently be ignored if it traps, matching the resolver policy where optional resolvers cannot permanently brick issuances or revocations if they fail unexpectedly, though they can enforce requirements if successful. (Note: `try_invoke_contract` is used).
