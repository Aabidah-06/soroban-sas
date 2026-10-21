# @soroban-sas/sdk

TypeScript SDK for the Soroban Solidity Attestation Service (SAS). This is a
companion to the Rust SDK at `packages/soroban-sas-sdk` for JS/TS
applications (wallets, indexers, relayers, frontends) that need to compute
the same content-addressed UIDs and typed-data signatures the Rust contracts
and Rust SDK use, and to submit transactions against a deployed SAS /
Schema Registry contract.

## Install

```bash
npm install @soroban-sas/sdk
```

The SDK requires Node.js 20.19.0 or newer for Node/CommonJS consumers. This
is required by the published Noble 2.4.0 packages used for SHA-256 and Ed25519;
browser consumers are unaffected. Node 18 is not supported because the Noble
2.x packages are ESM-only and the CJS entry cannot load them there.

## Hashing (byte-identical with the Rust contracts)

`computeSchemaUid`, `computeAttestationUid`, and `hashTypedData` are ports of
`soroban_sas_common::schema_uid`, `soroban_sas_common::attestation_uid`, and
`soroban_sas_common::typed_data::hash_offchain_attestation` respectively.
Every field the Rust side hashes via `.to_xdr(env)` — a `String`, `Address`,
`Bytes`, or the `UID` newtype — is encoded here as the identical canonical
`ScVal` XDR shape by the lightweight browser core; fields Rust hashes as raw bytes (`u64`
big-endian, `BytesN<32>` arrays) are encoded the same way here, never
XDR-wrapped. See `src/hashing.ts`'s doc comments for the exact preimage
layout of each function, and `test/hashing.test.ts` for golden vectors
copied verbatim from passing Rust tests in
`packages/soroban-sas-common/src/typed_data.rs` and
`packages/soroban-sas-common/src/test.rs`.

```ts
import { computeSchemaUid, computeAttestationUid, hashTypedData } from "@soroban-sas/sdk";

const schemaUid = computeSchemaUid("bool verified", resolverAddress, true);

const attestationUid = computeAttestationUid(
  schemaUid,
  recipientAddress,
  attesterAddress,
  new TextEncoder().encode("payload"),
);

const digest = hashTypedData(attestation, domain);
```

## Delegated attestations

`signDelegatedAttestation` signs `hashTypedData(attestation, domain)` with
the attester's ed25519 secret key (mirroring
`packages/soroban-sas-cli/src/offchain.rs::sign_offchain_attestation`);
`verifyDelegatedAttestation` recomputes the digest and checks the signature
without needing network access.

```ts
import { signDelegatedAttestation, verifyDelegatedAttestation } from "@soroban-sas/sdk";

const delegated = signDelegatedAttestation(attestation, domain, nonce, attesterSecret);
verifyDelegatedAttestation(delegated, domain); // true

// Any funded relayer account can now submit it without holding attesterSecret:
await client.attestByDelegation(delegated);
```

## Client

`SASClient` wraps `@stellar/stellar-sdk/contract`'s `Client`, which fetches
the deployed contract's on-chain XDR spec and uses it to build the
`InvokeHostFunction` operation for each call, rather than this package
hand-encoding argument layouts.

```ts
import { SASClient } from "@soroban-sas/sdk/client";

const client = new SASClient({
  contractId: "C...", // SAS contract id
  registryContractId: "C...", // Schema Registry contract id
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
  publicKey: walletAddress,
  signTransaction: (xdr, options) => wallet.signTransaction(xdr, options),
});

const schemaUid = await client.registerSchema("bool verified", resolverAddress, true);
const { hash } = await client.attest(attestation);
const stored = await client.getAttestation(attestation.uid);
await client.revoke(attestation.uid);
```

## Scope and limitations

### Browser and wallet integration

The default package entry is a lightweight browser core and can be imported directly from Vite or a Next.js client component. It contains the canonical-compatible hashing, StrKey, and delegated-signature APIs. Transaction submission is available from the separate `/client` entry and uses the wallet callback shape exposed by `@stellar/stellar-sdk`:

```ts
import { SASClient } from "@soroban-sas/sdk/client";

const sas = new SASClient({
  contractId: "C...",
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
  publicKey: walletAddress,
  signTransaction: (xdr, options) => wallet.signTransaction(xdr, options),
});
```

The browser entry does not accept secret seeds. Keep private keys out of browser bundles and provide a wallet signing callback instead. The callback receives the unsigned transaction XDR and returns the wallet's signed transaction XDR. This replaces the earlier `SASClientConfig.secret` path; callers that previously supplied a seed should adapt it to a signer callback or sign outside the browser.

The browser and ESM conditions for the default entry resolve to a self-contained
browser core. The full contract client is retained at
`@soroban-sas/sdk/client`, and the explicit `@soroban-sas/sdk/node` entry remains
available for Node secret-seed signing. The optional contract-client dependency
cost is measured separately from the default core.

For server-side Node applications that need the previous secret-seed signing
convenience, use the explicit Node-only entry. It is intentionally not part of
the browser graph:

```ts
import { createNodeSASClient } from "@soroban-sas/sdk/node";

const client = createNodeSASClient({
  contractId: "C...",
  rpcUrl: "http://localhost:8000",
  networkPassphrase: "Test SDF Network ; September 2015",
  secret: process.env.SAS_SECRET!,
});
```

The Node helper is the supported replacement for the removed
`SASClientConfig.secret` constructor option. Never import it in client-side
code or expose its secret value to a browser.

This release intentionally makes the default root entry browser-core-only:
`SASClient` is no longer exported from `@soroban-sas/sdk`. Migrate imports to
`@soroban-sas/sdk/client`; migrate secret-seed signing to
`@soroban-sas/sdk/node` and `createNodeSASClient`.

- `hashing.ts` and `delegation.ts` are cross-checked byte-for-byte against
  Rust golden vectors (see `test/hashing.test.ts` and
  `test/delegation.test.ts`) and can be relied on for offline UID
  computation and delegated-attestation signing without a network call.
- `client.ts`'s contract-call argument encoding — in particular, the `UID`
  newtype's one-element-array representation — was derived from reading the
  Rust XDR codegen (see `packages/soroban-sas-sdk/src/events.rs`'s
  `decode_uid` comment) and has not been exercised against a live Soroban RPC
  node in this environment. Before relying on `attest`/`attestByDelegation`/
  `revoke`/`registerSchema` for a real submission, run one end-to-end call
  against a local or test network and adjust the argument shape if the
  simulated transaction reports a type mismatch.
