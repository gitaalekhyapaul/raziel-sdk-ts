import { webcrypto } from "node:crypto";

import { type AgentIdentity, type AgentSigner, DIGEST_BYTES } from "./types.js";

export function copyAgentPublicKey(publicKey: Uint8Array): Uint8Array {
  if (!(publicKey instanceof Uint8Array) || publicKey.byteLength !== DIGEST_BYTES) {
    throw new TypeError("signer public key must contain exactly 32 bytes");
  }
  return new Uint8Array(publicKey);
}

/** Adapt an existing key. This function never generates, stores, or rotates keys. */
export function createWebCryptoSigner(
  identity: Pick<AgentIdentity, "publicKey" | "privateKey">,
): AgentSigner {
  const publicKey = copyAgentPublicKey(identity.publicKey);
  const privateKey = identity.privateKey;
  if (
    privateKey.type !== "private" ||
    privateKey.algorithm.name !== "Ed25519" ||
    !privateKey.usages.includes("sign")
  ) {
    throw new TypeError("signer requires an Ed25519 private key with sign usage");
  }
  return {
    get publicKey() {
      return new Uint8Array(publicKey);
    },
    async sign(message) {
      return new Uint8Array(
        await webcrypto.subtle.sign("Ed25519", privateKey, new Uint8Array(message)),
      );
    },
  };
}
