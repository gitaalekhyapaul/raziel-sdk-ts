import { Buffer } from "node:buffer";
import { webcrypto } from "node:crypto";
import { create, toJson } from "@bufbuild/protobuf";
import { describe, expect, it, vi } from "vitest";

import {
  type AccessIntent,
  AccessIntentSchema,
  AccessRequestMutationSchema,
  AccessRequestSchema,
  AccessRequestState,
  agentApiRequestSignatureMessage,
  createAgentIdentity,
  createRazielClient,
  createWebCryptoSigner,
  decodeHex,
  ListAccessRequestsResponseSchema,
  sha256,
} from "../src/index.ts";
import * as publicDtos from "../src/public.ts";

const id = "12345678-1234-4234-8234-123456789abc";
const otherId = "87654321-1234-4234-8234-123456789abc";
const root = "/api/agent/v1/access-requests";
const tokenId = "11".repeat(16);
const token = `rz1.${tokenId}.${Buffer.alloc(32, 0x22).toString("base64url")}`;
function present<T>(value: T | undefined): T {
  if (value === undefined) throw new Error("missing test fixture");
  return value;
}
const intent = () =>
  create(AccessIntentSchema, {
    formatVersion: 1,
    requestId: id,
    taskId: "reconcile",
    purpose: "payment review",
    action: "query",
    datasetId: "payments:bank",
    datasetRevision: 9007199254740991n,
    requestContext: [
      { name: "approved", value: { case: "boolValue", value: false } },
      { name: "offset", value: { case: "intValue", value: -9223372036854775808n } },
      { name: "memo", value: { case: "stringValue", value: "caller-private-input" } },
    ],
  });
const row = (state = AccessRequestState.PENDING_REVIEW) =>
  create(AccessRequestSchema, {
    formatVersion: 1,
    requestId: id,
    agentId: "aa".repeat(16),
    taskId: "reconcile",
    purpose: "payment review",
    action: "query",
    datasetId: "payments:bank",
    datasetRevision: 9007199254740991n,
    state,
    generation: 1n,
    createdAtUnixSeconds: 1800000000n,
    updatedAtUnixSeconds: 1800000001n,
    deadlineUnixSeconds: 1800086400n,
  });
const rowJson = () => toJson(AccessRequestSchema, row());
const mutation = () =>
  create(AccessRequestMutationSchema, { formatVersion: 1, expectedGeneration: 1n });

async function setup() {
  const identity = await createAgentIdentity();
  const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json(rowJson()));
  const options = {
    baseUrl: "https://raziel.example",
    audience: "raziel-test",
    tokenProvider: () => token,
    signer: createWebCryptoSigner(identity),
    fetch,
  };
  return { identity, fetch, options, client: createRazielClient(options) };
}

async function verifyCall(
  identity: Awaited<ReturnType<typeof createAgentIdentity>>,
  url: unknown,
  init: RequestInit | undefined,
) {
  const headers = new Headers(init?.headers);
  const target = new URL(String(url)).pathname + new URL(String(url)).search;
  const body = init?.body === undefined ? "" : String(init.body);
  const key = await webcrypto.subtle.importKey("raw", identity.publicKey, "Ed25519", false, [
    "verify",
  ]);
  const message = agentApiRequestSignatureMessage({
    formatVersion: 1,
    audience: "raziel-test",
    tokenId,
    agentKeyThumbprint: identity.keyThumbprint,
    requestMethod: init?.method ?? "",
    canonicalRequestTarget: target,
    requestBodyHash: await sha256(new TextEncoder().encode(body)),
    requestNonce: decodeHex(headers.get("X-Raziel-Agent-Nonce") ?? ""),
    requestTimestampUnixSeconds: BigInt(headers.get("X-Raziel-Agent-Timestamp") ?? "-1"),
  });
  expect(
    await webcrypto.subtle.verify(
      "Ed25519",
      key,
      decodeHex(headers.get("X-Raziel-Agent-Signature") ?? ""),
      message,
    ),
  ).toBe(true);
  expect(init).toMatchObject({
    credentials: "omit",
    redirect: "error",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
  return { headers, body, target };
}

describe("access request wire contract", () => {
  it("creates once and explicitly resends the same intent with fresh transport authentication", async () => {
    const { client, fetch, identity } = await setup();
    fetch
      .mockResolvedValueOnce(Response.json(rowJson(), { status: 201 }))
      .mockResolvedValueOnce(Response.json(rowJson(), { status: 200 }));
    const input = intent();
    const saved = structuredClone(input);
    expect(await client.createAccessRequest(input)).toEqual(row());
    expect(await client.createAccessRequest(input)).toEqual(row());
    expect(input).toEqual(saved);
    expect(fetch).toHaveBeenCalledTimes(2);
    const calls = [];
    for (const [url, init] of fetch.mock.calls) calls.push(await verifyCall(identity, url, init));
    expect(calls[0]?.target).toBe(root);
    expect(calls[0]?.headers.get("Content-Type")).toBe("application/json");
    expect(calls[0]?.body).toBe(calls[1]?.body);
    expect(JSON.parse(calls[0]?.body ?? "")).toEqual({
      formatVersion: 1,
      requestId: id,
      taskId: "reconcile",
      purpose: "payment review",
      action: "query",
      datasetId: "payments:bank",
      datasetRevision: "9007199254740991",
      requestContext: [
        { name: "approved", boolValue: false },
        { name: "offset", intValue: "-9223372036854775808" },
        { name: "memo", stringValue: "caller-private-input" },
      ],
    });
    expect(calls[0]?.headers.get("X-Raziel-Agent-Nonce")).not.toBe(
      calls[1]?.headers.get("X-Raziel-Agent-Nonce"),
    );
  });

  it("signs a sorted list query and returns the generated list type", async () => {
    const { client, fetch, identity } = await setup();
    const list = create(ListAccessRequestsResponseSchema, {
      formatVersion: 1,
      requests: [row()],
      nextCursor: "next_1-",
    });
    fetch.mockResolvedValue(Response.json(toJson(ListAccessRequestsResponseSchema, list)));
    expect(await client.listAccessRequests({ limit: 50, cursor: "opaque_2-" })).toEqual(list);
    const call = await verifyCall(identity, ...present(fetch.mock.calls[0]));
    expect(call.target).toBe(`${root}?cursor=opaque_2-&limit=50`);
    expect(call.body).toBe("");
    expect(call.headers.has("Content-Type")).toBe(false);
  });

  it("gets one request and sends cancellation as an explicit generation-checked command", async () => {
    const { client, fetch, identity } = await setup();
    expect(await client.getAccessRequest(id)).toEqual(row());
    for (const [status, state] of [
      [202, AccessRequestState.CANCELLING],
      [200, AccessRequestState.CANCELED],
      [200, AccessRequestState.READY],
    ] as const) {
      fetch.mockResolvedValueOnce(
        Response.json(toJson(AccessRequestSchema, row(state)), { status }),
      );
      expect((await client.cancelAccessRequest(id, mutation())).state).toBe(state);
    }
    for (const [index, [url, init]] of fetch.mock.calls.entries()) {
      const call = await verifyCall(identity, url, init);
      expect(call.target).toBe(`${root}/${id}${index === 0 ? "" : "/cancel"}`);
      expect(call.body).toBe(index === 0 ? "" : '{"formatVersion":1,"expectedGeneration":"1"}');
    }
    expect(
      new Set(
        fetch.mock.calls.map(([, init]) => new Headers(init?.headers).get("X-Raziel-Agent-Nonce")),
      ).size,
    ).toBe(4);
  });

  it("snapshots input bytes before an asynchronous token provider finishes", async () => {
    const { options, fetch } = await setup();
    let release = (_value: string) => {};
    const client = createRazielClient({
      ...options,
      tokenProvider: () =>
        new Promise<string>((resolve) => {
          release = resolve;
        }),
    });
    const input = intent();
    const pending = client.createAccessRequest(input);
    input.requestId = otherId;
    present(input.requestContext[2]).value = { case: "stringValue", value: "changed" };
    await Promise.resolve();
    release(token);
    expect((await pending).requestId).toBe(id);
    expect(String(fetch.mock.calls[0]?.[1]?.body)).toContain("caller-private-input");
    expect(String(fetch.mock.calls[0]?.[1]?.body)).not.toContain("changed");
  });
});

describe("input bounds", () => {
  const invalidIntents: [string, (input: AccessIntent) => void][] = [
    [
      "missing version",
      (input) => {
        delete (input as Partial<AccessIntent>).formatVersion;
      },
    ],
    [
      "version",
      (input) => {
        input.formatVersion = 2;
      },
    ],
    [
      "missing id",
      (input) => {
        input.requestId = "";
      },
    ],
    [
      "uppercase id",
      (input) => {
        input.requestId = id.toUpperCase();
      },
    ],
    [
      "uuid version",
      (input) => {
        input.requestId = id.replace("-4234", "-1234");
      },
    ],
    [
      "revision zero",
      (input) => {
        input.datasetRevision = 0n;
      },
    ],
    [
      "unsafe revision",
      (input) => {
        input.datasetRevision = 9007199254740992n;
      },
    ],
    [
      "numeric revision",
      (input) => {
        Object.assign(input, { datasetRevision: 1 });
      },
    ],
    [
      "unknown field",
      (input) => {
        Object.assign(input, { owner: "private" });
      },
    ],
    [
      "blank task",
      (input) => {
        input.taskId = " \t";
      },
    ],
    [
      "control purpose",
      (input) => {
        input.purpose = "x\u0085y";
      },
    ],
    [
      "large purpose",
      (input) => {
        input.purpose = "x".repeat(257);
      },
    ],
    [
      "action",
      (input) => {
        input.action = "read";
      },
    ],
    [
      "dataset",
      (input) => {
        input.datasetId = "../payments";
      },
    ],
    [
      "duplicate context",
      (input) => {
        input.requestContext.push(present(input.requestContext[0]));
      },
    ],
    [
      "large context list",
      (input) => {
        input.requestContext = Array.from({ length: 17 }, (_, index) =>
          create(publicDtos.AccessRequestContextEntrySchema, {
            name: `key_${index}`,
            value: { case: "boolValue", value: true },
          }),
        );
      },
    ],
    [
      "uppercase context",
      (input) => {
        present(input.requestContext[0]).name = "Key";
      },
    ],
    [
      "underscore context",
      (input) => {
        present(input.requestContext[0]).name = "_key";
      },
    ],
    [
      "long context name",
      (input) => {
        present(input.requestContext[0]).name = "a".repeat(257);
      },
    ],
    [
      "long context string",
      (input) => {
        present(input.requestContext[2]).value = { case: "stringValue", value: "x".repeat(257) };
      },
    ],
    [
      "int range",
      (input) => {
        present(input.requestContext[1]).value = { case: "intValue", value: 9223372036854775808n };
      },
    ],
    [
      "missing context value",
      (input) => {
        present(input.requestContext[0]).value = { case: undefined };
      },
    ],
    [
      "context unknown field",
      (input) => {
        Object.assign(present(input.requestContext[0]), { secret: true });
      },
    ],
  ];
  it.each(invalidIntents)("rejects %s without signing or sending", async (_name, change) => {
    const { options, fetch } = await setup();
    const sign = vi.fn(options.signer.sign);
    const input = intent();
    change(input);
    await expect(
      createRazielClient({ ...options, signer: { ...options.signer, sign } }).createAccessRequest(
        input,
      ),
    ).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    expect(fetch).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
  });

  it("accepts boundary context names and UTF-8 values", async () => {
    const { client, fetch } = await setup();
    const input = intent();
    present(input.requestContext[0]).name = "a".repeat(256);
    present(input.requestContext[2]).value = { case: "stringValue", value: "\u00e9".repeat(128) };
    await client.createAccessRequest(input);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("caps serialized workflow input at 16 KiB", async () => {
    const { client, fetch } = await setup();
    const input = intent();
    input.requestContext = Array.from({ length: 16 }, (_, index) =>
      create(publicDtos.AccessRequestContextEntrySchema, {
        name: `key_${index}`,
        value: { case: "stringValue", value: "\u0000".repeat(256) },
      }),
    );
    await expect(client.createAccessRequest(input)).rejects.toMatchObject({
      code: "INVALID_REQUEST",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([0, -1, 51, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects limit %s",
    async (limit) => {
      const { client, fetch } = await setup();
      await expect(client.listAccessRequests({ limit })).rejects.toMatchObject({
        code: "INVALID_REQUEST",
      });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each(["", "a&limit=50", "with space", "percent%2f", "x".repeat(513)])(
    "rejects cursor %#",
    async (cursor) => {
      const { client, fetch } = await setup();
      await expect(client.listAccessRequests({ cursor })).rejects.toMatchObject({
        code: "INVALID_REQUEST",
      });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each(["", `${id}/cancel`, `${id}?owner=other`, id.toUpperCase(), "../other"])(
    "rejects request target injection %#",
    async (invalidId) => {
      const { client, fetch } = await setup();
      await expect(client.getAccessRequest(invalidId)).rejects.toMatchObject({
        code: "INVALID_REQUEST",
      });
      await expect(client.cancelAccessRequest(invalidId, mutation())).rejects.toMatchObject({
        code: "INVALID_REQUEST",
      });
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each([0n, -1n, 18446744073709551616n, 1, "1", undefined])(
    "rejects mutation generation %s",
    async (expectedGeneration) => {
      const { client, fetch } = await setup();
      await expect(
        client.cancelAccessRequest(id, Object.assign(mutation(), { expectedGeneration })),
      ).rejects.toMatchObject({ code: "INVALID_REQUEST" });
      expect(fetch).not.toHaveBeenCalled();
    },
  );
});

describe("strict public responses", () => {
  it.each([
    { formatVersion: 2 },
    { formatVersion: null },
    { formatVersion: "1" },
    { datasetRevision: 1 },
    { datasetRevision: "01" },
    { datasetRevision: "1e3" },
    { datasetRevision: "9007199254740992" },
    { generation: "18446744073709551616" },
    { generation: "0" },
    { state: 1 },
    { state: 999 },
    { state: "ACCESS_REQUEST_STATE_UNKNOWN" },
    { state: "ACCESS_REQUEST_STATE_UNSPECIFIED" },
    { requestId: otherId },
    { capability: "YQ" },
    { capability: "YQ==\n" },
    { capability: "_w==" },
    { createdAtUnixSeconds: "253402300800" },
    { request_id: id },
    { requestContext: [{ name: "secret", stringValue: "private" }] },
    { policyBinding: { policyHash: "YQ", policyIr: "private" } },
    { metrics: { proofSizeBytes: 12 } },
    { proposal: { formatVersion: 2 } },
  ])("rejects noncanonical or private response mutation %#", async (change) => {
    const { client, fetch } = await setup();
    fetch.mockResolvedValue(Response.json({ ...(rowJson() as object), ...change }));
    await expect(client.getAccessRequest(id)).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
      status: 200,
    });
  });

  it("rejects the owner create wrapper and missing required version", async () => {
    const { client, fetch } = await setup();
    fetch.mockResolvedValueOnce(
      Response.json({ formatVersion: 1, request: rowJson(), created: true }, { status: 201 }),
    );
    await expect(client.createAccessRequest(intent())).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
    const { formatVersion: _version, ...withoutVersion } = rowJson() as Record<string, unknown>;
    fetch.mockResolvedValueOnce(Response.json(withoutVersion));
    await expect(client.getAccessRequest(id)).rejects.toMatchObject({ code: "INVALID_RESPONSE" });
  });

  it("decodes known enums, durations, exact uint64 metrics, and public capability bytes", async () => {
    const { client, fetch } = await setup();
    fetch.mockResolvedValue(
      Response.json({
        ...(rowJson() as object),
        proofJobState: "PROOF_JOB_STATE_SUCCEEDED",
        capability: "AQID",
        metrics: { provingDuration: "1.250s", executionCycleCount: "18446744073709551615" },
      }),
    );
    const result = await client.getAccessRequest(id);
    expect(result.capability).toEqual(new Uint8Array([1, 2, 3]));
    expect(result.metrics?.executionCycleCount).toBe(18446744073709551615n);
    expect(result.metrics?.provingDuration).toMatchObject({ seconds: 1n, nanos: 250000000 });
  });

  it("accepts an empty generated list but rejects excessive rows, proof bytes, and bad cursors", async () => {
    const { client, fetch } = await setup();
    fetch.mockResolvedValueOnce(Response.json({ formatVersion: 1 }));
    expect((await client.listAccessRequests()).requests).toEqual([]);
    for (const body of [
      { formatVersion: 1, requests: [rowJson(), rowJson()] },
      { formatVersion: 1, requests: [{ ...(rowJson() as object), capability: "AQID" }] },
      { formatVersion: 1, nextCursor: "bad+cursor" },
      { formatVersion: 1, requests: [], privateIntent: "secret" },
    ]) {
      fetch.mockResolvedValueOnce(Response.json(body));
      await expect(client.listAccessRequests({ limit: 1 })).rejects.toMatchObject({
        code: "INVALID_RESPONSE",
      });
    }
  });

  it("caps decoded capability bytes independently of the HTTP byte limit", async () => {
    const { client, fetch } = await setup();
    const capability = Buffer.alloc(2 * 1024 * 1024).toString("base64");
    fetch.mockResolvedValueOnce(Response.json({ ...(rowJson() as object), capability }));
    expect((await client.getAccessRequest(id)).capability.length).toBe(2 * 1024 * 1024);
    fetch.mockResolvedValueOnce(
      Response.json({
        ...(rowJson() as object),
        capability: Buffer.alloc(2 * 1024 * 1024 + 1).toString("base64"),
      }),
    );
    await expect(client.getAccessRequest(id)).rejects.toMatchObject({ code: "INVALID_RESPONSE" });
  });

  it("cancels oversized streams, including a misleading small Content-Length", async () => {
    const { client, fetch } = await setup();
    const cancel = vi.fn();
    fetch.mockResolvedValue(
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(1024 * 1024 + 1));
          },
          cancel,
        }),
        { headers: { "Content-Type": "application/json", "Content-Length": "1" } },
      ),
    );
    await expect(client.listAccessRequests()).rejects.toMatchObject({ code: "INVALID_RESPONSE" });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("has an explicit public export allowlist without owner RPCs or diagnostics", () => {
    expect(Object.keys(publicDtos).sort()).toEqual(
      [
        "AccessIntentSchema",
        "AccessPolicyBindingSchema",
        "AccessRequestContextEntrySchema",
        "AccessRequestMutationSchema",
        "AccessRequestSchema",
        "AccessRequestState",
        "AccessRequestStateSchema",
        "IssuanceProposalSchema",
        "ListAccessRequestsResponseSchema",
        "ProofCapabilitySchema",
        "ProofJobState",
        "ProofMetricsSchema",
      ].sort(),
    );
  });
});

describe("abort and uncertain outcomes", () => {
  it.each([409, 429, 503])(
    "does not retry HTTP %s or create a replacement request",
    async (status) => {
      const { client, fetch } = await setup();
      const code =
        status === 409 ? "CONFLICT" : status === 429 ? "CAPACITY_EXCEEDED" : "SERVICE_UNAVAILABLE";
      fetch.mockResolvedValue(
        Response.json(
          { error: { code, retryable: true } },
          { status, headers: { "Retry-After": "30" } },
        ),
      );
      await expect(client.createAccessRequest(intent())).rejects.toMatchObject({
        code,
        status,
        retryable: true,
      });
      expect(fetch).toHaveBeenCalledOnce();
    },
  );

  it("aborts before any token, signature, or send", async () => {
    const { options, fetch } = await setup();
    const tokenProvider = vi.fn(options.tokenProvider);
    const controller = new AbortController();
    controller.abort(new Error("caller-private-reason"));
    const client = createRazielClient({ ...options, tokenProvider });
    await expect(
      client.createAccessRequest(intent(), { signal: controller.signal }),
    ).rejects.toMatchObject({ code: "ABORTED" });
    expect(tokenProvider).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("aborts a pending signer, removes listeners, and blocks a late send", async () => {
    const { options, fetch } = await setup();
    let release = (_value: Uint8Array) => {};
    const sign = vi.fn(
      async () =>
        new Promise<Uint8Array>((resolve) => {
          release = resolve;
        }),
    );
    const controller = new AbortController();
    const remove = vi.spyOn(controller.signal, "removeEventListener");
    const pending = createRazielClient({
      ...options,
      signer: { ...options.signer, sign },
    }).cancelAccessRequest(id, mutation(), { signal: controller.signal });
    const rejection = expect(pending).rejects.toMatchObject({ code: "ABORTED" });
    await vi.waitFor(() => expect(sign).toHaveBeenCalledOnce());
    controller.abort("private-reason");
    await rejection;
    release(new Uint8Array(64));
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(fetch).not.toHaveBeenCalled();
    expect(remove).toHaveBeenCalledWith("abort", expect.any(Function));
  });

  it("aborts a local body wait without sending a server cancel", async () => {
    const { client, fetch } = await setup();
    const cancel = vi.fn();
    fetch.mockResolvedValue(
      new Response(new ReadableStream({ cancel }), {
        headers: { "Content-Type": "application/json" },
      }),
    );
    const controller = new AbortController();
    const pending = client.getAccessRequest(id, { signal: controller.signal });
    const rejection = expect(pending).rejects.toMatchObject({ code: "ABORTED" });
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce());
    controller.abort();
    await rejection;
    expect(cancel).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(String(fetch.mock.calls[0]?.[0])).not.toContain("/cancel");
  });

  it("reports timeout as unknown outcome without another create", async () => {
    const { options, fetch } = await setup();
    fetch.mockImplementation(async () => new Promise<Response>(() => {}));
    await expect(
      createRazielClient({ ...options, timeoutMs: 30 }).createAccessRequest(intent()),
    ).rejects.toMatchObject({ code: "TIMEOUT" });
    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });
});
