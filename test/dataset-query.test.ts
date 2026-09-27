import { Buffer } from "node:buffer";
import { webcrypto } from "node:crypto";
import { create, toBinary } from "@bufbuild/protobuf";
import { TimestampSchema } from "@bufbuild/protobuf/wkt";
import { describe, expect, it, vi } from "vitest";
import {
  agentApiRequestSignatureMessage,
  createAgentIdentity,
  createRazielClient,
  createWebCryptoSigner,
  decodeHex,
  encodeHex,
  ProofCapabilitySchema,
  protectedRequestSignatureMessage,
  sha256,
} from "../src/index.ts";

const query = {
  fromOccurredAt: "2026-09-01T00:00:00Z",
  toOccurredAt: "2026-09-02T00:00:00Z",
  limit: 20,
};
const dataset = "processor:ledger";
const target = `/api/datasets/${encodeURIComponent(dataset)}/protected-query`;
async function setup() {
  const identity = await createAgentIdentity();
  const capability = create(ProofCapabilitySchema, {
    formatVersion: 1,
    capabilityId: "a".repeat(64),
    agentKeyThumbprint: identity.keyThumbprint,
    taskId: "reconcile",
    purpose: "match payments",
    action: "query",
    resourceType: `dataset_${"b".repeat(32)}`,
    resourceScope: dataset,
    policyHash: new Uint8Array(32).fill(1),
    relationshipSnapshotRoot: new Uint8Array(32).fill(2),
    snapshotId: `snapshot-v1:${"02".repeat(32)}`,
    expiresAt: { seconds: BigInt(Math.floor(Date.now() / 1000)) + 1000n },
  });
  const result = {
    classification: "SYNTHETIC",
    dataset_id: dataset,
    verification_path: "VERIFIER",
    row_count: 1,
    rows: [
      {
        transactionId: "txn-1",
        occurredAt: query.fromOccurredAt,
        amountMinor: "1200",
        currency: "SGD",
        reconciliationStatus: "UNMATCHED",
        sourceRecordDigest: "c".repeat(64),
      },
    ],
    receipt: {
      format_version: 1,
      receipt_id: "receipt-1",
      receipt_type: "AUDIT_RECEIPT_TYPE_PROTECTED_REQUEST",
      request_id: "request-1",
      occurred_at: query.fromOccurredAt,
      task_id: "reconcile",
      capability_id: capability.capabilityId,
      proof_job_id: capability.capabilityId,
      policy_record_id: "policy-1",
      policy_hash: encodeHex(capability.policyHash),
      snapshot_id: capability.snapshotId,
      relationship_snapshot_root: encodeHex(capability.relationshipSnapshotRoot),
      public_claims_digest: "d".repeat(64),
      proof_digest: "e".repeat(64),
      action: "query",
      resource_type: capability.resourceType,
      resource_scope: dataset,
      outcome: "AUDIT_OUTCOME_ACCEPTED",
      reason_code: "PUBLIC_ERROR_CODE_UNSPECIFIED",
    },
  };
  const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json(result));
  const sign = vi.fn(createWebCryptoSigner(identity).sign);
  const client = createRazielClient({
    baseUrl: "https://raziel.example",
    audience: "raziel-test",
    tokenProvider: () => `rz1.${"11".repeat(16)}.${Buffer.alloc(32, 2).toString("base64url")}`,
    signer: { publicKey: identity.publicKey, sign },
    fetch,
  });
  return {
    identity,
    capability,
    result,
    fetch,
    sign,
    client,
    bytes: toBinary(ProofCapabilitySchema, capability),
  };
}

describe("capability reuse through the SDK", () => {
  it("reuses capability bytes but signs both envelopes afresh on each explicit read", async () => {
    const f = await setup();
    expect((await f.client.queryDataset(dataset, f.bytes, query)).verification_path).toBe(
      "VERIFIER",
    );
    f.result.verification_path = "CACHE";
    expect((await f.client.queryDataset(dataset, f.bytes, query)).verification_path).toBe("CACHE");
    const key = await webcrypto.subtle.importKey("raw", f.identity.publicKey, "Ed25519", false, [
      "verify",
    ]);
    const inners: string[] = [];
    const outers: string[] = [];
    for (const [url, init] of f.fetch.mock.calls) {
      expect(url).toBe(`https://raziel.example${target}`);
      const body = String(init?.body);
      const envelope = JSON.parse(body);
      const headers = new Headers(init?.headers);
      expect(envelope.capability_proto_hex).toBe(encodeHex(f.bytes));
      expect(JSON.parse(Buffer.from(envelope.request_body_base64, "base64").toString())).toEqual(
        query,
      );
      const inner = protectedRequestSignatureMessage({
        formatVersion: 1,
        capabilityId: f.capability.capabilityId,
        requestMethod: "POST",
        canonicalRequestTarget: target,
        requestBodyHash: decodeHex(envelope.request_body_hash),
        requestNonce: decodeHex(envelope.request_nonce),
        requestTimestampUnixSeconds: BigInt(envelope.request_timestamp_unix_seconds),
      });
      const outer = agentApiRequestSignatureMessage({
        formatVersion: 1,
        audience: "raziel-test",
        tokenId: "11".repeat(16),
        agentKeyThumbprint: f.identity.keyThumbprint,
        requestMethod: "POST",
        canonicalRequestTarget: target,
        requestBodyHash: await sha256(new TextEncoder().encode(body)),
        requestNonce: decodeHex(headers.get("X-Raziel-Agent-Nonce") ?? ""),
        requestTimestampUnixSeconds: BigInt(headers.get("X-Raziel-Agent-Timestamp") ?? "0"),
      });
      expect(
        await webcrypto.subtle.verify(
          "Ed25519",
          key,
          decodeHex(envelope.agent_request_signature),
          inner,
        ),
      ).toBe(true);
      expect(
        await webcrypto.subtle.verify(
          "Ed25519",
          key,
          decodeHex(headers.get("X-Raziel-Agent-Signature") ?? ""),
          outer,
        ),
      ).toBe(true);
      inners.push(envelope.request_nonce);
      outers.push(headers.get("X-Raziel-Agent-Nonce") ?? "");
    }
    expect(new Set([...inners, ...outers]).size).toBe(4);
  });

  it("rejects another key, dataset, expiry, and query bounds before transmitting", async () => {
    const f = await setup();
    for (const patch of [
      { resourceScope: "other" },
      { agentKeyThumbprint: new Uint8Array(32) },
      { expiresAt: create(TimestampSchema, { seconds: 1n }) },
    ]) {
      await expect(
        f.client.queryDataset(
          dataset,
          toBinary(
            ProofCapabilitySchema,
            create(ProofCapabilitySchema, { ...f.capability, ...patch }),
          ),
          query,
        ),
      ).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    }
    for (const patch of [
      { limit: 101 },
      { toOccurredAt: "2026-11-01T00:00:00Z" },
      { fromOccurredAt: "2026-02-30T00:00:00Z" },
    ]) {
      await expect(
        f.client.queryDataset(dataset, f.bytes, { ...query, ...patch }),
      ).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    }
    expect(f.fetch).not.toHaveBeenCalled();
  });

  it("rejects substituted receipts and unexpected response fields", async () => {
    const f = await setup();
    for (const result of [
      { ...f.result, receipt: { ...f.result.receipt, policy_hash: "0".repeat(64) } },
      { ...f.result, receipt: { ...f.result.receipt, capability_id: "0".repeat(64) } },
      { ...f.result, rows: [{ ...f.result.rows[0], witness: "private" }] },
      { ...f.result, row_count: 2 },
    ]) {
      f.fetch.mockResolvedValueOnce(Response.json(result));
      await expect(f.client.queryDataset(dataset, f.bytes, query)).rejects.toMatchObject({
        code: "INVALID_RESPONSE",
      });
    }
  });

  it("preserves coarse denials without retrying or generating a replacement capability", async () => {
    const f = await setup();
    f.fetch.mockResolvedValueOnce(
      Response.json({ error: "AUTHORIZATION_REJECTED" }, { status: 403 }),
    );
    await expect(f.client.queryDataset(dataset, f.bytes, query)).rejects.toMatchObject({
      code: "AUTHORIZATION_REJECTED",
      status: 403,
    });
    expect(f.fetch).toHaveBeenCalledOnce();
  });
});
