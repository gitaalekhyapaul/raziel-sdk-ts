import { webcrypto } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  canonicalizeRequestMethod,
  canonicalizeRequestTarget,
  capabilityRequestCommitment,
  createAgentIdentity,
  decodeHex,
  encodeHex,
  getSdkPackageInfo,
  protectedRequestSignatureMessage,
  RAZIEL_SDK_PACKAGE,
  sha256,
  signCapabilityRequest,
  signProtectedRequest,
  verifyProtectedRequestSignature,
} from "../src/index.ts";

describe("SDK package info", () => {
  it("reports the M5 signing capability", () => {
    expect(RAZIEL_SDK_PACKAGE).toBe("@raziel/sdk-ts");
    expect(getSdkPackageInfo()).toEqual({
      packageName: RAZIEL_SDK_PACKAGE,
      readiness: "m5-signing",
      authorizationBehavior: "proof-capability-client",
    });
  });
});

describe("capability request commitment", () => {
  it("matches the approved Rust authorization vector", async () => {
    const commitment = await capabilityRequestCommitment({
      formatVersion: 1,
      agentKeyThumbprint: new Uint8Array(32).fill(0x11),
      taskId: "reconcile-july",
      purpose: "payment-reconciliation",
      action: "view",
      resourceType: "payment_batch",
      resourceScope: "batch-caveat",
      requestedExpiresAtUnixSeconds: 1_800_000_000n,
      issuanceNonce: new Uint8Array(32).fill(0x22),
      snapshotId: "snapshot-2026-07-24",
      requestContext: [{ name: "requested_amount", value: { kind: "int", value: 900n } }],
    });

    expect(encodeHex(commitment)).toBe(
      "4ff6989fadcd3e3ec9f24a2303675c130c0f6497eb0a9c91686c6116de88e6bd",
    );
  });

  it("sorts context by name and rejects duplicate names", async () => {
    const base = {
      formatVersion: 1 as const,
      agentKeyThumbprint: new Uint8Array(32).fill(0x11),
      taskId: "task",
      purpose: "payment-reconciliation",
      action: "query",
      resourceType: "payment_batch",
      resourceScope: "batch-1",
      requestedExpiresAtUnixSeconds: 1_800_000_000n,
      issuanceNonce: new Uint8Array(32).fill(0x22),
      snapshotId: "snapshot-1",
    };
    const sorted = await capabilityRequestCommitment({
      ...base,
      requestContext: [
        { name: "amount", value: { kind: "int" as const, value: 9n } },
        { name: "currency", value: { kind: "string" as const, value: "SGD" } },
      ],
    });
    const reversed = await capabilityRequestCommitment({
      ...base,
      requestContext: [
        { name: "currency", value: { kind: "string" as const, value: "SGD" } },
        { name: "amount", value: { kind: "int" as const, value: 9n } },
      ],
    });
    expect(reversed).toEqual(sorted);
    await expect(
      capabilityRequestCommitment({
        ...base,
        requestContext: [
          { name: "amount", value: { kind: "int", value: 9n } },
          { name: "amount", value: { kind: "int", value: 10n } },
        ],
      }),
    ).rejects.toThrow("unique");
  });
});

describe("protected request canonicalization", () => {
  it("matches the approved method, target, and signed-byte vector", () => {
    const method = canonicalizeRequestMethod("post");
    const target = canonicalizeRequestTarget("/payments/%72econcile?status=pending&account=%61-1");
    expect(method).toBe("POST");
    expect(target).toBe("/payments/reconcile?account=a-1&status=pending");

    const message = protectedRequestSignatureMessage({
      formatVersion: 1,
      capabilityId: "33".repeat(32),
      requestMethod: method,
      canonicalRequestTarget: target,
      requestBodyHash: new Uint8Array(32).fill(0x11),
      requestNonce: new Uint8Array(32).fill(0x22),
      requestTimestampUnixSeconds: 1_800_000_000n,
    });
    expect(encodeHex(message)).toBe(
      "0000001b72617a69656c2f70726f7465637465642d726571756573742f7631000000d2" +
        "0000000100000040" +
        "33".repeat(64) +
        "00000004504f5354" +
        "0000002e2f7061796d656e74732f7265636f6e63696c653f6163636f756e743d612d31267374617475733d70656e64696e67" +
        "00000020" +
        "11".repeat(32) +
        "00000020" +
        "22".repeat(32) +
        "000000006b49d200",
    );
  });

  it("normalizes query plus and rejects ambiguous targets", () => {
    expect(canonicalizeRequestTarget("/payments?flag&q=a+b")).toBe("/payments?flag=&q=a%2Bb");
    for (const target of [
      "//payments",
      "/payments/",
      "/payments/../admin",
      "/payments/%2fadmin",
      "/payments?a=1&%61=2",
      "/payments?",
    ]) {
      expect(() => canonicalizeRequestTarget(target)).toThrow();
    }
  });
});

describe("agent signatures", () => {
  it("creates a raw-key identity and signs issuance and protected requests", async () => {
    const identity = await createAgentIdentity();
    expect(identity.publicKey).toHaveLength(32);
    expect(identity.keyThumbprint).toHaveLength(32);
    await expect(sha256(identity.publicKey)).resolves.toEqual(identity.keyThumbprint);

    const issuance = await signCapabilityRequest(identity, {
      agentId: "demo-agent",
      taskId: "task-1",
      purpose: "payment-reconciliation",
      action: "query",
      resourceType: "payment_batch",
      resourceScope: "batch-1",
      requestedExpiresAtUnixSeconds: 1_800_000_000n,
      issuanceNonce: new Uint8Array(32).fill(0x22),
      snapshotId: "snapshot-1",
    });
    expect(issuance.requestSignature).toHaveLength(64);
    const verifyingKey = await webcrypto.subtle.importKey(
      "raw",
      identity.publicKey,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    await expect(
      webcrypto.subtle.verify(
        "Ed25519",
        verifyingKey,
        issuance.requestSignature,
        issuance.capabilityRequestCommitment,
      ),
    ).resolves.toBe(true);

    const protectedRequest = await signProtectedRequest(identity, {
      capabilityId: encodeHex(issuance.capabilityRequestCommitment),
      method: "post",
      target: "/payments/reconcile?status=pending&account=a-1",
      body: new TextEncoder().encode("{}"),
      requestNonce: decodeHex("44".repeat(32)),
      requestTimestampUnixSeconds: 1_799_999_900n,
    });
    expect(protectedRequest.requestMethod).toBe("POST");
    expect(protectedRequest.agentRequestSignature).toHaveLength(64);
    const protectedMessage = protectedRequestSignatureMessage({
      formatVersion: 1,
      capabilityId: protectedRequest.capabilityId,
      requestMethod: protectedRequest.requestMethod,
      canonicalRequestTarget: protectedRequest.canonicalRequestTarget,
      requestBodyHash: protectedRequest.requestBodyHash,
      requestNonce: protectedRequest.requestNonce,
      requestTimestampUnixSeconds: protectedRequest.requestTimestampUnixSeconds,
    });
    await expect(
      webcrypto.subtle.verify(
        "Ed25519",
        verifyingKey,
        protectedRequest.agentRequestSignature,
        protectedMessage,
      ),
    ).resolves.toBe(true);
    const alteredTargetMessage = protectedRequestSignatureMessage({
      formatVersion: 1,
      capabilityId: protectedRequest.capabilityId,
      requestMethod: protectedRequest.requestMethod,
      canonicalRequestTarget: "/payments/reconcile?account=a-2&status=pending",
      requestBodyHash: protectedRequest.requestBodyHash,
      requestNonce: protectedRequest.requestNonce,
      requestTimestampUnixSeconds: protectedRequest.requestTimestampUnixSeconds,
    });
    await expect(
      webcrypto.subtle.verify(
        "Ed25519",
        verifyingKey,
        protectedRequest.agentRequestSignature,
        alteredTargetMessage,
      ),
    ).resolves.toBe(false);
    await expect(verifyProtectedRequestSignature(protectedRequest)).resolves.toBe(true);
    await expect(
      verifyProtectedRequestSignature({
        ...protectedRequest,
        canonicalRequestTarget: "/payments/reconcile?account=a-2&status=pending",
      }),
    ).resolves.toBe(false);
  });
});
