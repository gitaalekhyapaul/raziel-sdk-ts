export const CAPABILITY_REQUEST_FORMAT_VERSION = 1;
export const AGENT_API_FORMAT_VERSION = 1;
export const MAX_PROTOBUF_TIMESTAMP_SECONDS = 253_402_300_799n;
export const PROTECTED_REQUEST_FORMAT_VERSION = 1;
export const DIGEST_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;
export const MAX_CONTEXT_ENTRIES = 16;
export const MAX_STRING_BYTES = 256;
export const MAX_CANONICAL_REQUEST_TARGET_BYTES = 2_048;

export type AuthorizationContextValue =
  | { readonly kind: "bool"; readonly value: boolean }
  | { readonly kind: "int"; readonly value: bigint }
  | { readonly kind: "string"; readonly value: string };

export interface AuthorizationContextEntry {
  readonly name: string;
  readonly value: AuthorizationContextValue;
}

export interface CapabilityRequestBinding {
  readonly formatVersion: typeof CAPABILITY_REQUEST_FORMAT_VERSION;
  readonly agentKeyThumbprint: Uint8Array;
  readonly taskId: string;
  readonly purpose: string;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceScope: string;
  readonly requestedExpiresAtUnixSeconds: bigint;
  readonly issuanceNonce: Uint8Array;
  readonly snapshotId: string;
  readonly requestContext: readonly AuthorizationContextEntry[];
}

export interface CapabilityRequestDraft {
  readonly agentId: string;
  readonly taskId: string;
  readonly purpose: string;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceScope: string;
  readonly requestedExpiresAtUnixSeconds: bigint;
  readonly snapshotId: string;
  readonly requestContext?: readonly AuthorizationContextEntry[];
  readonly issuanceNonce?: Uint8Array;
}

export interface SignedCapabilityRequest extends CapabilityRequestBinding {
  readonly agentId: string;
  readonly agentPublicKey: Uint8Array;
  readonly capabilityRequestCommitment: Uint8Array;
  readonly requestSignature: Uint8Array;
}

export interface ProtectedRequestDraft {
  readonly capabilityId: string;
  readonly method: string;
  readonly target: string;
  readonly body: Uint8Array;
  readonly requestTimestampUnixSeconds: bigint;
  readonly requestNonce?: Uint8Array;
}

export interface SignedProtectedRequest {
  readonly formatVersion: typeof PROTECTED_REQUEST_FORMAT_VERSION;
  readonly capabilityId: string;
  readonly agentPublicKey: Uint8Array;
  readonly requestMethod: string;
  readonly canonicalRequestTarget: string;
  readonly requestBodyHash: Uint8Array;
  readonly requestNonce: Uint8Array;
  readonly requestTimestampUnixSeconds: bigint;
  readonly agentRequestSignature: Uint8Array;
}

export interface AgentIdentity {
  readonly publicKey: Uint8Array;
  readonly keyThumbprint: Uint8Array;
  readonly privateKey: CryptoKey;
}

export interface AgentSigner {
  readonly publicKey: Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export interface AgentApiRequestSignatureInput {
  readonly formatVersion: typeof AGENT_API_FORMAT_VERSION;
  readonly audience: string;
  readonly tokenId: string;
  readonly agentKeyThumbprint: Uint8Array;
  readonly requestMethod: string;
  readonly canonicalRequestTarget: string;
  readonly requestBodyHash: Uint8Array;
  readonly requestNonce: Uint8Array;
  readonly requestTimestampUnixSeconds: bigint;
}

/** Strict Agent API v1 ProtoJSON projection, with canonical base64 byte fields. */
export interface AgentMe {
  readonly formatVersion: typeof AGENT_API_FORMAT_VERSION;
  readonly agentId: string;
  readonly publicKey: string;
  readonly keyThumbprint: string;
  readonly audience: string;
  readonly tokenExpiresAtUnixSeconds: string;
}
