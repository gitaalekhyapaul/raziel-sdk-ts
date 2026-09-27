import { webcrypto } from "node:crypto";

import {
  canonicalizeRequestMethod,
  canonicalizeRequestTarget,
  capabilityRequestCommitment,
  normalizeContext,
  protectedRequestSignatureMessage,
  sha256,
} from "./canonical.js";
import {
  type AgentIdentity,
  CAPABILITY_REQUEST_FORMAT_VERSION,
  type CapabilityRequestBinding,
  type CapabilityRequestDraft,
  DIGEST_BYTES,
  PROTECTED_REQUEST_FORMAT_VERSION,
  type ProtectedRequestDraft,
  type SignedCapabilityRequest,
  type SignedProtectedRequest,
} from "./types.js";

export async function createAgentIdentity(): Promise<AgentIdentity> {
  const generated = (await webcrypto.subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
    "verify",
  ])) as CryptoKey | CryptoKeyPair;
  if (!("privateKey" in generated) || !("publicKey" in generated)) {
    throw new Error("Ed25519 key generation did not return a key pair");
  }
  const pair = generated;
  const publicKey = new Uint8Array(await webcrypto.subtle.exportKey("raw", pair.publicKey));
  return {
    publicKey,
    keyThumbprint: await sha256(publicKey),
    privateKey: pair.privateKey,
  };
}

export async function signCapabilityRequest(
  identity: AgentIdentity,
  draft: CapabilityRequestDraft,
): Promise<SignedCapabilityRequest> {
  const issuanceNonce = draft.issuanceNonce?.slice() ?? randomDigest();
  const requestContext = normalizeContext(draft.requestContext);
  const binding: CapabilityRequestBinding = {
    formatVersion: CAPABILITY_REQUEST_FORMAT_VERSION,
    agentKeyThumbprint: identity.keyThumbprint.slice(),
    taskId: draft.taskId,
    purpose: draft.purpose,
    action: draft.action,
    resourceType: draft.resourceType,
    resourceScope: draft.resourceScope,
    requestedExpiresAtUnixSeconds: draft.requestedExpiresAtUnixSeconds,
    issuanceNonce,
    snapshotId: draft.snapshotId,
    requestContext,
  };
  const commitment = await capabilityRequestCommitment(binding);
  const requestSignature = new Uint8Array(
    await webcrypto.subtle.sign("Ed25519", identity.privateKey, commitment),
  );
  return {
    ...binding,
    agentId: draft.agentId,
    agentPublicKey: identity.publicKey.slice(),
    capabilityRequestCommitment: commitment,
    requestSignature,
  };
}

export async function signProtectedRequest(
  identity: AgentIdentity,
  draft: ProtectedRequestDraft,
): Promise<SignedProtectedRequest> {
  const requestMethod = canonicalizeRequestMethod(draft.method);
  const canonicalRequestTarget = canonicalizeRequestTarget(draft.target);
  const requestBodyHash = await sha256(draft.body);
  const requestNonce = draft.requestNonce?.slice() ?? randomDigest();
  const message = protectedRequestSignatureMessage({
    formatVersion: PROTECTED_REQUEST_FORMAT_VERSION,
    capabilityId: draft.capabilityId,
    requestMethod,
    canonicalRequestTarget,
    requestBodyHash,
    requestNonce,
    requestTimestampUnixSeconds: draft.requestTimestampUnixSeconds,
  });
  const agentRequestSignature = new Uint8Array(
    await webcrypto.subtle.sign("Ed25519", identity.privateKey, message),
  );
  return {
    formatVersion: PROTECTED_REQUEST_FORMAT_VERSION,
    capabilityId: draft.capabilityId,
    agentPublicKey: identity.publicKey.slice(),
    requestMethod,
    canonicalRequestTarget,
    requestBodyHash,
    requestNonce,
    requestTimestampUnixSeconds: draft.requestTimestampUnixSeconds,
    agentRequestSignature,
  };
}

export async function verifyProtectedRequestSignature(
  request: SignedProtectedRequest,
): Promise<boolean> {
  const message = protectedRequestSignatureMessage({
    formatVersion: request.formatVersion,
    capabilityId: request.capabilityId,
    requestMethod: request.requestMethod,
    canonicalRequestTarget: request.canonicalRequestTarget,
    requestBodyHash: request.requestBodyHash,
    requestNonce: request.requestNonce,
    requestTimestampUnixSeconds: request.requestTimestampUnixSeconds,
  });
  try {
    const verifyingKey = await webcrypto.subtle.importKey(
      "raw",
      request.agentPublicKey,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await webcrypto.subtle.verify(
      "Ed25519",
      verifyingKey,
      request.agentRequestSignature,
      message,
    );
  } catch {
    return false;
  }
}

export function randomDigest(): Uint8Array {
  return webcrypto.getRandomValues(new Uint8Array(DIGEST_BYTES));
}
