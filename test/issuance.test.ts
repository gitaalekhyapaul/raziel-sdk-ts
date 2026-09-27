import { Buffer } from "node:buffer";
import { create, toJson } from "@bufbuild/protobuf";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AccessIntentSchema,
  AccessIssuanceSubmissionSchema,
  AccessRequestMutationSchema,
  AccessRequestSchema,
  AccessRequestState,
  createAgentIdentity,
  createRazielClient,
  createWebCryptoSigner,
  signCapabilityRequest,
} from "../src/index.ts";

const now = 1800000000n;
const id = "12345678-1234-4234-8234-123456789abc";
const root = `/api/agent/v1/access-requests/${id}`;
const token = `rz1.${"11".repeat(16)}.${Buffer.alloc(32, 2).toString("base64url")}`;
function present<T>(value: T | undefined): T {
  if (value === undefined) throw new Error("missing test fixture");
  return value;
}

async function setup() {
  vi.spyOn(Date, "now").mockReturnValue(Number(now) * 1000);
  const identity = await createAgentIdentity();
  const signer = createWebCryptoSigner(identity);
  const sign = vi.fn(signer.sign);
  const intent = create(AccessIntentSchema, {
    formatVersion: 1,
    requestId: id,
    taskId: "reconcile",
    purpose: "settlement review",
    action: "query",
    datasetId: "bank:payments",
    datasetRevision: 1n,
    requestContext: [
      { name: "z_offset", value: { case: "intValue", value: -12n } },
      { name: "a_approved", value: { case: "boolValue", value: true } },
    ],
  });
  const policyBinding = {
    policyRecordId: "approved-policy-1",
    policyHash: new Uint8Array(32).fill(3),
    resourceType: `dataset_${"44".repeat(16)}`,
    resourceScope: intent.datasetId,
  };
  const request = create(AccessRequestSchema, {
    formatVersion: 1,
    requestId: id,
    agentId: "aa".repeat(16),
    taskId: intent.taskId,
    purpose: intent.purpose,
    action: "query",
    datasetId: intent.datasetId,
    datasetRevision: 1n,
    state: AccessRequestState.AWAITING_SIGNATURE,
    generation: 4n,
    createdAtUnixSeconds: now - 60n,
    updatedAtUnixSeconds: now,
    deadlineUnixSeconds: now + 86400n,
    policyBinding,
    proposal: {
      formatVersion: 1,
      proposalId: "55".repeat(16),
      generation: 4n,
      signatureDeadlineUnixSeconds: now + 120n,
      agentPublicKey: identity.publicKey,
      taskId: intent.taskId,
      purpose: intent.purpose,
      action: "query",
      policyBinding,
      snapshotId: `snapshot-v1:${"66".repeat(32)}`,
      snapshotRoot: new Uint8Array(32).fill(0x66),
      requestedExpiresAtUnixSeconds: now + 4800n,
    },
  });
  const fetch = vi.fn<typeof globalThis.fetch>(async () =>
    Response.json(toJson(AccessRequestSchema, request), { status: 202 }),
  );
  const client = createRazielClient({
    baseUrl: "https://raziel.example",
    audience: "raziel-test",
    tokenProvider: () => token,
    signer: { publicKey: signer.publicKey, sign },
    fetch,
  });
  return { identity, sign, intent, request, fetch, client };
}
afterEach(() => vi.restoreAllMocks());

describe("explicit agent issuance", () => {
  it("signs the existing canonical commitment with the external signer without sending it", async () => {
    const { identity, sign, intent, request, fetch, client } = await setup();
    const nonce = new Uint8Array(32).fill(9);
    const signed = await client.signIssuance(intent, request, { issuanceNonce: nonce });
    const oldApi = await signCapabilityRequest(identity, {
      agentId: request.agentId,
      taskId: intent.taskId,
      purpose: intent.purpose,
      action: "query",
      resourceType: present(request.policyBinding).resourceType,
      resourceScope: intent.datasetId,
      snapshotId: present(request.proposal).snapshotId,
      requestedExpiresAtUnixSeconds: now + 4800n,
      issuanceNonce: nonce,
      requestContext: [
        { name: "z_offset", value: { kind: "int", value: -12n } },
        { name: "a_approved", value: { kind: "bool", value: true } },
      ],
    });
    expect(signed.request?.requestSignature).toEqual(oldApi.requestSignature);
    expect(sign.mock.calls[0]?.[0]).toEqual(oldApi.capabilityRequestCommitment);
    expect(signed.request?.requestContext.map((entry) => entry.name)).toEqual([
      "a_approved",
      "z_offset",
    ]);
    expect(intent.requestContext[0]?.name).toBe("z_offset");
    nonce.fill(0);
    expect(signed.request?.issuanceNonce).toEqual(new Uint8Array(32).fill(9));
    expect(fetch).not.toHaveBeenCalled();
  });

  it("submits identical retained bytes with fresh API signatures after the proposal expires", async () => {
    const { client, intent, request, fetch } = await setup();
    const signed = await client.signIssuance(intent, request);
    await client.submitIssuance(id, signed);
    vi.spyOn(Date, "now").mockReturnValue(Number(now + 300n) * 1000);
    await client.submitIssuance(id, signed);
    const [first, second] = fetch.mock.calls;
    expect(first?.[0]).toBe(`https://raziel.example${root}/issuance`);
    expect(first?.[1]?.body).toBe(second?.[1]?.body);
    expect(JSON.parse(String(first?.[1]?.body))).toEqual(
      toJson(AccessIssuanceSubmissionSchema, signed),
    );
    expect(new Headers(first?.[1]?.headers).get("X-Raziel-Agent-Nonce")).not.toBe(
      new Headers(second?.[1]?.headers).get("X-Raziel-Agent-Nonce"),
    );
  });

  it("resumes only on an explicit generation-checked call", async () => {
    const { client, fetch } = await setup();
    await client.resumeAccessRequest(
      id,
      create(AccessRequestMutationSchema, {
        formatVersion: 1,
        expectedGeneration: 4n,
      }),
    );
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0]?.[0]).toBe(`https://raziel.example${root}/resume`);
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toEqual({
      formatVersion: 1,
      expectedGeneration: "4",
    });
  });

  it.each(["key", "dataset", "scope", "policy", "snapshot", "deadline", "generation", "state"])(
    "rejects changed %s before signing or submitting",
    async (field) => {
      const { client, intent, request, sign, fetch } = await setup();
      const proposal = present(request.proposal);
      const binding = present(proposal.policyBinding);
      switch (field) {
        case "key":
          proposal.agentPublicKey = new Uint8Array(32);
          break;
        case "dataset":
          request.datasetRevision = 2n;
          break;
        case "scope":
          binding.resourceScope = "other";
          break;
        case "policy":
          binding.policyHash = new Uint8Array(32);
          break;
        case "snapshot":
          proposal.snapshotRoot = new Uint8Array(32);
          break;
        case "deadline":
          proposal.signatureDeadlineUnixSeconds = now;
          break;
        case "generation":
          proposal.generation = 3n;
          break;
        default:
          request.state = AccessRequestState.SUBMITTING;
      }
      await expect(client.signIssuance(intent, request)).rejects.toMatchObject({
        code: "INVALID_REQUEST",
      });
      expect(sign).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it("rejects a truncated signature and stops an aborted signing operation before submission", async () => {
    const { client, intent, request, sign, fetch } = await setup();
    sign.mockResolvedValueOnce(new Uint8Array(63));
    await expect(client.signIssuance(intent, request)).rejects.toMatchObject({
      code: "INVALID_SIGNATURE",
    });
    const controller = new AbortController();
    controller.abort();
    await expect(
      client.signIssuance(intent, request, { signal: controller.signal }),
    ).rejects.toMatchObject({ code: "ABORTED" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects changed submission key and fractional transport timestamps locally", async () => {
    const { client, intent, request, fetch } = await setup();
    const signed = await client.signIssuance(intent, request);
    const submitted = present(signed.request);
    const expiry = present(submitted.requestedExpiresAt);
    expiry.nanos = 1;
    await expect(client.submitIssuance(id, signed)).rejects.toMatchObject({
      code: "INVALID_REQUEST",
    });
    expiry.nanos = 0;
    submitted.agentPublicKey = new Uint8Array(32);
    await expect(client.submitIssuance(id, signed)).rejects.toMatchObject({
      code: "INVALID_REQUEST",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("aborts a blocked external signer without sending a server cancellation", async () => {
    const { client, intent, request, sign, fetch } = await setup();
    sign.mockImplementationOnce(() => new Promise(() => {}));
    const controller = new AbortController();
    const signing = client.signIssuance(intent, request, { signal: controller.signal });
    await vi.waitFor(() => expect(sign).toHaveBeenCalledTimes(1));
    controller.abort();
    await expect(signing).rejects.toMatchObject({ code: "ABORTED" });
    expect(fetch).not.toHaveBeenCalled();
  });
});
