import { Buffer } from "node:buffer";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  type AgentApiRequestSignatureInput,
  agentApiRequestSignatureMessage,
  createAgentIdentity,
  decodeHex,
  encodeHex,
  MAX_PROTOBUF_TIMESTAMP_SECONDS,
  sha256,
} from "../src/index.ts";

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/agent-api-request-signature-v1.json", import.meta.url), "utf8"),
);

function input(): AgentApiRequestSignatureInput {
  return {
    formatVersion: fixture.format_version,
    audience: fixture.audience,
    tokenId: fixture.token_id,
    agentKeyThumbprint: decodeHex(fixture.agent_key_thumbprint_hex),
    requestMethod: fixture.request_method,
    canonicalRequestTarget: fixture.canonical_request_target,
    requestBodyHash: decodeHex(fixture.request_body_hash_hex),
    requestNonce: decodeHex(fixture.request_nonce_hex),
    requestTimestampUnixSeconds: BigInt(fixture.request_timestamp_unix_seconds),
  };
}

describe("agent API signature encoding", () => {
  it("matches the Rust message, thumbprint, body hash, and deterministic signature vector", async () => {
    const message = agentApiRequestSignatureMessage(input());
    expect(encodeHex(message)).toBe(fixture.signature_message_hex);
    expect(encodeHex(await sha256(decodeHex(fixture.agent_public_key_hex)))).toBe(
      fixture.agent_key_thumbprint_hex,
    );
    expect(encodeHex(await sha256(decodeHex(fixture.request_body_hex)))).toBe(
      fixture.request_body_hash_hex,
    );
    const publicKey = await webcrypto.subtle.importKey(
      "raw",
      decodeHex(fixture.agent_public_key_hex),
      "Ed25519",
      false,
      ["verify"],
    );
    expect(
      await webcrypto.subtle.verify(
        "Ed25519",
        publicKey,
        decodeHex(fixture.request_signature_hex),
        message,
      ),
    ).toBe(true);
    const privateKey = await webcrypto.subtle.importKey(
      "pkcs8",
      Buffer.from(`302e020100300506032b657004220420${fixture.seed_hex}`, "hex"),
      "Ed25519",
      false,
      ["sign"],
    );
    expect(
      encodeHex(new Uint8Array(await webcrypto.subtle.sign("Ed25519", privateKey, message))),
    ).toBe(fixture.request_signature_hex);
  });

  it("binds every signed field in the separately framed Ed25519 message", async () => {
    const identity = await createAgentIdentity();
    const key = await webcrypto.subtle.importKey("raw", identity.publicKey, "Ed25519", false, [
      "verify",
    ]);
    const message = agentApiRequestSignatureMessage(input());
    const signature = await webcrypto.subtle.sign("Ed25519", identity.privateKey, message);
    expect(await webcrypto.subtle.verify("Ed25519", key, signature, message)).toBe(true);
    const mutations: Partial<AgentApiRequestSignatureInput>[] = [
      { audience: "another-installation" },
      { tokenId: "44".repeat(16) },
      { agentKeyThumbprint: new Uint8Array(32).fill(0x44) },
      { requestMethod: "POST" },
      { canonicalRequestTarget: "/api/agent/v1/access-requests" },
      { requestBodyHash: new Uint8Array(32).fill(0x44) },
      { requestNonce: new Uint8Array(32).fill(0x44) },
      { requestTimestampUnixSeconds: input().requestTimestampUnixSeconds + 1n },
    ];
    for (const mutation of mutations) {
      expect(
        await webcrypto.subtle.verify(
          "Ed25519",
          key,
          signature,
          agentApiRequestSignatureMessage({ ...input(), ...mutation }),
        ),
      ).toBe(false);
    }
    expect(await webcrypto.subtle.verify("Ed25519", key, signature, await sha256(message))).toBe(
      false,
    );
  });

  it.each(["", "a".repeat(129), "\n", "\x7f", "\u00e9"])("rejects audience %j", (audience) => {
    expect(() => agentApiRequestSignatureMessage({ ...input(), audience })).toThrow("audience");
  });

  it.each(["1".repeat(31), "A".repeat(32), "0".repeat(33), "g".repeat(32)])(
    "rejects token ID %j",
    (tokenId) => {
      expect(() => agentApiRequestSignatureMessage({ ...input(), tokenId })).toThrow(
        "token identifier",
      );
    },
  );

  it.each([-1n, MAX_PROTOBUF_TIMESTAMP_SECONDS + 1n, 1n << 63n])(
    "rejects timestamp %s",
    (requestTimestampUnixSeconds) => {
      expect(() =>
        agentApiRequestSignatureMessage({ ...input(), requestTimestampUnixSeconds }),
      ).toThrow("timestamp");
    },
  );

  it.each([0n, MAX_PROTOBUF_TIMESTAMP_SECONDS])(
    "accepts timestamp boundary %s",
    (requestTimestampUnixSeconds) => {
      expect(() =>
        agentApiRequestSignatureMessage({ ...input(), requestTimestampUnixSeconds }),
      ).not.toThrow();
    },
  );

  it("accepts printable ASCII boundaries without normalization", () => {
    expect(() =>
      agentApiRequestSignatureMessage({ ...input(), audience: " ".repeat(128) }),
    ).not.toThrow();
    expect(() => agentApiRequestSignatureMessage({ ...input(), audience: "~" })).not.toThrow();
  });

  it.each(["agentKeyThumbprint", "requestBodyHash", "requestNonce"] as const)(
    "checks %s lengths",
    (field) => {
      for (const size of [0, 31, 33]) {
        expect(() =>
          agentApiRequestSignatureMessage({ ...input(), [field]: new Uint8Array(size) }),
        ).toThrow("32 bytes");
      }
    },
  );

  it("rejects noncanonical methods, targets, and versions", () => {
    for (const mutation of [
      { formatVersion: 2 },
      { requestMethod: "get" },
      { requestMethod: "HEAD" },
      { canonicalRequestTarget: "/api/%61gent/v1/me" },
      { canonicalRequestTarget: "/api/agent/v1/me?z=1&a=2" },
      { canonicalRequestTarget: "/api/agent/v1/../me" },
      { canonicalRequestTarget: "/api/agent/v1/me#x" },
    ]) {
      expect(() =>
        agentApiRequestSignatureMessage({
          ...input(),
          ...mutation,
        } as AgentApiRequestSignatureInput),
      ).toThrow();
    }
  });
});
