# @gitaalekhyapaul/raziel-sdk-ts

Version 0.1.0 provides Node.js ESM and TypeScript declarations for Raziel signing
and authenticated identity and access-request calls. Node.js 24.18.0 or newer is required.

## Current Scope

`createRazielClient(...).me()` signs `GET /api/agent/v1/me` under ADR-0020.
It checks the returned identity and audience against the caller's configured key.
The response is identity metadata, not permission to access data.

Access-request create/list/get/cancel/resume, exact proposal signing, and issuance
submission are implemented. Polling and protected-query transport remain pending. The existing
capability and protected-request signing helpers remain available. They do not
contact a server or verify a proof.

The only runtime dependency is `@bufbuild/protobuf` pinned to `2.12.1` under ADR-0020.
The client uses Node's native fetch and WebCrypto. Browser support is not claimed.

## Caller-Owned Signing

Supply an existing raw 32-byte Ed25519 public key and a signing function:

```ts
import {
  createRazielClient,
  type AgentSigner,
} from "@gitaalekhyapaul/raziel-sdk-ts";

export async function lookupIdentity(
  signer: AgentSigner,
  tokenProvider: () => Promise<string>,
) {
  const client = createRazielClient({
    baseUrl: "https://raziel.example.com",
    audience: "your-installation-trust-domain",
    tokenProvider,
    signer,
    timeoutMs: 10_000,
  });
  return client.me();
}
```

The signer contract is `{ publicKey: Uint8Array, sign(message): Promise<Uint8Array> }`.
`sign` signs the supplied framed bytes directly. Do not hash them first.
The client copies the public key and derives its SHA-256 thumbprint. It rejects
signatures that are not 64-byte byte arrays. The backend owns strict Ed25519
key and signature verification, token validity, and replay admission.

`createWebCryptoSigner({ publicKey, privateKey })` adapts an existing Ed25519
WebCrypto private key with sign usage. It does not generate, store, export,
recover, or rotate keys. The application owns key storage and token retrieval.
The legacy `createAgentIdentity()` helper still generates an in-memory key on
explicit invocation. The client never calls it or creates a replacement identity.

## Transport Contract

- `baseUrl` is an origin, with an optional trailing slash. Credentials, path
  prefixes, query strings, and fragments are rejected.
- HTTPS is required outside loopback. HTTP accepts `localhost`, IPv4 loopback,
  and IPv6 `::1` for local development or an SSH tunnel.
- `audience` is the configured installation trust domain, not the origin.
  It must contain 1-128 printable ASCII bytes.
- `tokenProvider` returns the canonical `rz1.<tokenId>.<secret>` token on each call.
  The token ID is 32 lowercase hexadecimal characters. The secret is canonical
  unpadded base64url encoding of 32 bytes. The client has no token cache.
- Every call uses a fresh 32-byte random nonce and current whole-second timestamp.
  The GET request has no body. Its signature covers the empty-body SHA-256 hash.
- No redirects, cookies, caching, or automatic retries are used. An injected
  `fetch` must honor the supplied RequestInit, including `redirect: "error"`.
- `timeoutMs` defaults to 10,000 and covers token retrieval, signing, transport,
  and body reading. A timeout aborts fetch and blocks a later send. Caller-owned
  token or signer promises cannot be canceled by this interface.
- The identity method accepts only HTTP 200 JSON with the exact six response fields.
  The public key and thumbprint must be canonical padded base64 for its own key.
  The expiry must be a canonical nonnegative decimal string within the Protobuf
  timestamp range. Responses are capped at 4,096 bytes.

## Access Requests

The client exposes four one-shot methods:

| Method | Input | Generated result | HTTP success |
| --- | --- | --- | --- |
| `createAccessRequest(intent, options?)` | `AccessIntent` | `AccessRequest` | 201 new, 200 retained |
| `listAccessRequests(options?)` | `limit` 1-50, optional `cursor` and `signal` | `ListAccessRequestsResponse` | 200 |
| `getAccessRequest(requestId, options?)` | Lowercase UUIDv4 | `AccessRequest` | 200 |
| `cancelAccessRequest(requestId, mutation, options?)` | `AccessRequestMutation` | `AccessRequest` | 200 or 202 |

Use Buf's `create` with the exported schemas. In-memory integers are `bigint` and
bytes are `Uint8Array`. HTTP uses decimal strings and canonical padded base64.
`AccessRequestList` is a type alias for `ListAccessRequestsResponse`.
The create method returns the request directly, not the owner RPC wrapper.

The application must create and durably persist its intent UUID and context before
the first send. The SDK performs no filesystem writes and generates no request UUID.
Pass the same persisted intent for an explicit retry. Do not replace its UUID after
a timeout or transport error. Local caller storage owns the private request context.

```ts
import { create, fromJsonString, toJsonString } from "@bufbuild/protobuf";
import { AccessIntentSchema, AccessRequestMutationSchema } from "@gitaalekhyapaul/raziel-sdk-ts";

// callerRequestId is a UUIDv4 allocated by the application for this intent.
const intent = create(AccessIntentSchema, {
  formatVersion: 1,
  requestId: callerRequestId,
  taskId: "reconcile-september",
  purpose: "payment reconciliation",
  action: "query",
  datasetId: "bank-ledger",
  datasetRevision: 1n,
  requestContext: [{ name: "approved", value: { case: "boolValue", value: true } }],
});
await intentStore.save(intent.requestId, toJsonString(AccessIntentSchema, intent));
const request = await client.createAccessRequest(intent, { signal });
const page = await client.listAccessRequests({ limit: 25, signal });
const current = await client.getAccessRequest(request.requestId, { signal });

// A separate, explicit application decision requests cancellation.
const cancellation = await client.cancelAccessRequest(current.requestId,
  create(AccessRequestMutationSchema, {
    formatVersion: 1,
    expectedGeneration: current.generation,
  }), { signal });

// Recovery reads the saved intent. Resubmission remains an explicit decision.
const retainedIntent = fromJsonString(AccessIntentSchema,
  await intentStore.load(request.requestId));
```

Dataset revisions are positive and at most `9007199254740991`. Generations are
positive uint64 values. Versioned inputs require `formatVersion: 1`. Claim strings
must contain non-whitespace text, fit 256 UTF-8 bytes, and contain no control characters.
Context accepts at most 16 distinct names matching `[a-z][a-z0-9_]{0,255}`.
Context string values fit 256 UTF-8 bytes. The full serialized input fits 16 KiB.

Every call signs its exact body and canonical target with a fresh transport nonce.
List calls default to 25 rows and accept an opaque cursor of at most 512 characters.
Lists reject embedded capability bytes and more rows than the requested limit.
HTTP detail bodies are capped at 3 MiB, lists at 1 MiB, and errors at 4 KiB.
Decoded capability artifacts have a separate 2 MiB limit.
Unknown fields, unknown enums, noncanonical byte/integer fields, and bad versions fail closed.

All methods, including `me`, accept an optional `AbortSignal`. Aborting returns the
coarse `ABORTED` code, cancels the local fetch/body wait, and blocks a late send.
It does not send a server cancellation. A 202 cancellation response means accepted,
not confirmed termination. A completion race can return `READY`.
No method resumes dispatch, submits issuance, or starts a proof implicitly.
`resumeAccessRequest` and `submitIssuance` are explicit commands.

### Final Issuance Signature

`client.signIssuance(intent, request)` validates an `AWAITING_SIGNATURE` proposal
against the caller's retained intent and public key. It returns the generated
`AccessIssuanceSubmission` message without making an HTTP request. It uses the
existing canonical capability commitment, not a hash of Protobuf bytes.

Persist the returned message in the agent's private state before calling
`client.submitIssuance(requestId, submission)`. Retrying that call preserves the exact
issuance body and refreshes only the outer API signature. Do not call `signIssuance`
again to recover an uncertain submission. The default signing timeout is 10 seconds,
or the client's `timeoutMs`. An abort stops the local wait, not the external signer
or server job. No private signing key enters Raziel.

`client.resumeAccessRequest(requestId, mutation)` explicitly returns an offline
signer to the serial workflow. It needs the latest request generation. A new proposal
then requires a new explicit signature. There is no automatic replacement proof.

### Wait And Reuse

`client.waitForAccessRequest(requestId, { signal, deadlineUnixMilliseconds })`
reads immediately, then polls at 5, 10, 20, and 30-second intervals. Subsequent
intervals remain 30 seconds. It returns on `AWAITING_SIGNATURE`, `WAITING_FOR_AGENT`,
or any terminal state. Callers explicitly sign or resume, then start another wait.
The default overall deadline is 24 hours. A supplied deadline is an absolute Unix
timestamp in milliseconds. The wait retries transient reads, never commands.
Retry-After is bounded to 30 seconds. Abort stops only the local wait.

After `READY`, the returned `capability` bytes can be retained and reused:

```ts
const current = await client.waitForAccessRequest(request.requestId, { signal });
if (current.state === AccessRequestState.READY) {
  const query = {
    fromOccurredAt: "2026-09-01T00:00:00Z",
    toOccurredAt: "2026-09-02T00:00:00Z",
    limit: 20,
  };
  const first = await client.queryDataset(current.datasetId, current.capability, query, { signal });
  const repeated = await client.queryDataset(current.datasetId, current.capability, query, { signal });
}
```

Each query signs the existing protected-request envelope, then separately signs the
API request containing it. Both nonces are fresh on every call. A query is one read
attempt with no automatic retry. Repeating it can produce another receipt, never a
new proof. Query windows are at most 31 days and 100 rows, with whole-second UTC
timestamps. The returned synthetic rows and audit receipt are bounded and typed.
`verification_path` reports `VERIFIER` or `CACHE` from the gateway.

Local key/scope checks and response validation do not verify a Plonk proof. Only
the independent gateway/verifier authorizes a read. Authentication or inbox approval
alone cannot release data. Callers must retain the original intent and exact signed
issuance attempt for recovery. The SDK never persists private keys or tokens itself.

Generated public DTOs are available from the root and `./public` entry points.
The legacy signing-context type retains its name. The generated context type is
exported as `AccessRequestContextEntry`. No owner RPC client, owner create wrapper,
private policy type, or internal proof-job diagnostics are exported.

`me()` returns this strict ProtoJSON shape, without decoding byte fields:

```ts
interface AgentMe {
  formatVersion: 1;
  agentId: string;
  publicKey: string;
  keyThumbprint: string;
  audience: string;
  tokenExpiresAtUnixSeconds: string;
}
```

`RazielClientError` exposes `code`, optional HTTP `status`, `retryable`, and optional
bounded `retryAfterMs`.
It accepts the public API error envelope `{ error: { code, retryable } }`.
401 maps to `NOT_AUTHORIZED`, 409 replay to `REQUEST_REPLAYED`, and 503 to
`SERVICE_UNAVAILABLE`. Protected queries retain the existing coarse
`AUTHORIZATION_REJECTED` and `PROTECTED_QUERY_UNAVAILABLE` codes. Low-level methods
never retry automatically. Only the explicit read-only wait helper retries reads.
Unrecognized server bodies and provider, signer, or transport diagnostics are
not copied into errors. A timeout is an unknown outcome, not proof of rejection.

## Compatibility

`compatibility.json` records base backend protocol revision `abff0c8`, the staged
B-0066 generated schema hashes, ADR-0020, and
the public canonical vector references. The Rust agent-auth fixture is copied
into the test tree and checks exact message, key hash, body hash, and signature.
Public test fixtures are excluded from the npm tarball.

The full previous SDK surface is retained: `createAgentIdentity`,
`signCapabilityRequest`, `signProtectedRequest`, `verifyProtectedRequestSignature`,
canonical helpers, constants, and types. The legacy `RAZIEL_SDK_PACKAGE` value
remains `@raziel/sdk-ts`. `getSdkPackageInfo()` retains its M5 fields and values.
Use `RAZIEL_PUBLIC_SDK_PACKAGE` for this package's published name.

This release is intended for a pinned local tarball during backend migration.
No npm publication or complete M6 access workflow is claimed here.

## Development

Exact development pins are TypeScript 6.0.3, Node types 24.13.3, Vitest 4.1.10,
and Biome 2.5.4. Package scripts are `build`, `typecheck`, `test`, `lint`, and
`format:check`. `prepack` builds the declarations and ESM output.

An existing compatible Linux toolchain can validate a staging checkout without
installing dependencies. Mount the backend read-only at `/workspace` and this
package read-write at `/sdk`. Invoke the pinned binaries directly:

Mount the installed protobuf `2.12.1` directory read-only at
`/sdk/node_modules/@bufbuild/protobuf` for runtime and declaration resolution.

```sh
node /workspace/packages/sdk-ts/node_modules/typescript/bin/tsc \
  -p /sdk/tsconfig.build.json \
  --typeRoots /workspace/packages/sdk-ts/node_modules/@types

RAZIEL_BACKEND_ROOT=/workspace \
node /workspace/packages/sdk-ts/node_modules/vitest/vitest.mjs \
  run --root /sdk --config /sdk/vitest.config.mjs

node /workspace/node_modules/@biomejs/biome/bin/biome lint /sdk/src /sdk/test
```

The Vitest config uses that explicit optional backend path. It creates no links
into another repository. A normal standalone checkout uses its own installed
dev dependencies. There are no workspace dependencies or private server modules.

## License

MIT. The existing repository LICENSE is retained unchanged.
