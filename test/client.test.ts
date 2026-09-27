import { Buffer } from "node:buffer";
import { webcrypto } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  type AgentMe,
  type AgentSigner,
  agentApiRequestSignatureMessage,
  createAgentIdentity,
  createRazielClient,
  createWebCryptoSigner,
  decodeHex,
  RazielClientError,
  sha256,
} from "../src/index.ts";

const audience = "raziel-local";
const token = `rz1.${"11".repeat(16)}.${Buffer.alloc(32, 0x22).toString("base64url")}`;

async function setup() {
  const identity = await createAgentIdentity();
  const signer = createWebCryptoSigner(identity);
  const me: AgentMe = {
    formatVersion: 1,
    agentId: "agent-test-only",
    publicKey: Buffer.from(identity.publicKey).toString("base64"),
    keyThumbprint: Buffer.from(identity.keyThumbprint).toString("base64"),
    audience,
    tokenExpiresAtUnixSeconds: "1800000000",
  };
  const fetch = vi.fn<typeof globalThis.fetch>(async () => Response.json(me));
  const options = {
    baseUrl: "https://raziel.example",
    audience,
    tokenProvider: () => token,
    signer,
    fetch,
  };
  return { identity, signer, me, fetch, options };
}

describe("signed identity lookup", () => {
  it("sends the exact GET envelope without body, cookies, cache, or redirects", async () => {
    const { identity, me, fetch, options } = await setup();
    const startedAt = Math.floor(Date.now() / 1_000);
    expect(await createRazielClient(options).me()).toEqual(me);
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe("https://raziel.example/api/agent/v1/me");
    expect(init).toMatchObject({
      method: "GET",
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
    expect(init?.body).toBeUndefined();
    const headers = new Headers(init?.headers);
    expect(headers.get("Authorization")).toBe(`Bearer ${token}`);
    expect(headers.get("X-Raziel-Agent-Version")).toBe("1");
    expect(headers.get("X-Raziel-Agent-Nonce")).toMatch(/^[0-9a-f]{64}$/);
    expect(headers.get("X-Raziel-Agent-Signature")).toMatch(/^[0-9a-f]{128}$/);
    expect(Number(headers.get("X-Raziel-Agent-Timestamp"))).toBeGreaterThanOrEqual(startedAt);
    expect(headers.has("Content-Type")).toBe(false);
    const verifyingKey = await webcrypto.subtle.importKey(
      "raw",
      identity.publicKey,
      "Ed25519",
      false,
      ["verify"],
    );
    const message = agentApiRequestSignatureMessage({
      formatVersion: 1,
      audience,
      tokenId: "11".repeat(16),
      agentKeyThumbprint: identity.keyThumbprint,
      requestMethod: "GET",
      canonicalRequestTarget: "/api/agent/v1/me",
      requestBodyHash: await sha256(new Uint8Array()),
      requestNonce: decodeHex(headers.get("X-Raziel-Agent-Nonce") ?? ""),
      requestTimestampUnixSeconds: BigInt(headers.get("X-Raziel-Agent-Timestamp") ?? "-1"),
    });
    expect(
      await webcrypto.subtle.verify(
        "Ed25519",
        verifyingKey,
        decodeHex(headers.get("X-Raziel-Agent-Signature") ?? ""),
        message,
      ),
    ).toBe(true);
  });

  it("gets a token and fresh nonce for each concurrent call", async () => {
    const { fetch, options } = await setup();
    const rotated = token.replace("11".repeat(16), "33".repeat(16));
    const provider = vi.fn().mockResolvedValueOnce(token).mockResolvedValueOnce(rotated);
    const client = createRazielClient({ ...options, tokenProvider: provider });
    await Promise.all([client.me(), client.me()]);
    expect(provider).toHaveBeenCalledTimes(2);
    expect(fetch).toHaveBeenCalledTimes(2);
    const headers = fetch.mock.calls.map(([, init]) => new Headers(init?.headers));
    expect(new Set(headers.map((value) => value.get("X-Raziel-Agent-Nonce"))).size).toBe(2);
    expect(headers.map((value) => value.get("Authorization")).sort()).toEqual(
      [`Bearer ${token}`, `Bearer ${rotated}`].sort(),
    );
  });

  it("copies a Buffer public key and ignores a caller-supplied thumbprint", async () => {
    const { identity, signer, me, options } = await setup();
    const key = Buffer.from(identity.publicKey);
    const externalSigner = { publicKey: key, keyThumbprint: new Uint8Array(32), sign: signer.sign };
    const client = createRazielClient({ ...options, signer: externalSigner });
    key.fill(0);
    expect(await client.me()).toEqual(me);
  });

  it("adapts an existing WebCrypto identity without exposing its private key", async () => {
    const { signer, identity } = await setup();
    const key = signer.publicKey;
    key.fill(0);
    expect(signer.publicKey).toEqual(identity.publicKey);
    expect(Object.keys(signer).sort()).toEqual(["publicKey", "sign"]);
    expect(await signer.sign(new Uint8Array([1, 2, 3]))).toHaveLength(64);
  });
});

describe("configuration and credential validation", () => {
  it.each([
    "http://example.com",
    "http://localhost.example.com",
    "http://192.168.0.1",
    "http://[::]",
    "https://user:password@example.com",
    "https://@example.com",
    "https://example.com/api",
    "https://example.com/..",
    "https://example.com?",
    "https://example.com/?x=1",
    "https://example.com/#",
    "https://example.com#frag",
    "ftp://example.com",
    "file:///etc/passwd",
    " https://example.com",
    "https://example.com\n",
    "https://example.com\\path",
    "https://example.com//",
    "not-a-url",
  ])("rejects origin %s", async (baseUrl) => {
    const { fetch, options } = await setup();
    expect(() => createRazielClient({ ...options, baseUrl })).toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([
    "https://example.com",
    "https://example.com/",
    "https://example.com:8443",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://127.2.3.4",
    "http://[::1]:3000",
  ])("accepts origin %s", async (baseUrl) => {
    const { options } = await setup();
    expect(() => createRazielClient({ ...options, baseUrl })).not.toThrow();
  });

  it.each(["", "a".repeat(129), "\r\n", "\u00e9", "\x7f"])(
    "rejects audience %j",
    async (invalid) => {
      const { options } = await setup();
      expect(() => createRazielClient({ ...options, audience: invalid })).toThrow("audience");
    },
  );

  it.each([0, 31, 33])("rejects %i-byte public keys", async (length) => {
    const { signer, options } = await setup();
    expect(() =>
      createRazielClient({ ...options, signer: { ...signer, publicKey: new Uint8Array(length) } }),
    ).toThrow("32 bytes");
  });

  it.each([0, -1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, 2_147_483_648])(
    "rejects timeout %s",
    async (timeoutMs) => {
      const { options } = await setup();
      expect(() => createRazielClient({ ...options, timeoutMs })).toThrow("timeoutMs");
    },
  );

  it.each([
    "",
    `${token}=`,
    `${token}\n`,
    ` ${token}`,
    token.replace("rz1", "rz2"),
    token.replace("11".repeat(16), "AA".repeat(16)),
    `rz1.${"11".repeat(16)}.${"A".repeat(42)}B`,
    `rz1.${"11".repeat(16)}.${"A".repeat(42)}`,
    `rz1.${"11".repeat(16)}.${"A".repeat(44)}`,
    `rz1.${"11".repeat(16)}.${"+".repeat(43)}`,
    `rz1.${"11".repeat(16)}.${"/".repeat(43)}`,
  ])("rejects malformed or noncanonical token case %#", async (invalid) => {
    const { options, fetch } = await setup();
    const sign = vi.fn(options.signer.sign);
    const client = createRazielClient({
      ...options,
      tokenProvider: () => invalid,
      signer: { ...options.signer, sign },
    });
    await expect(client.me()).rejects.toMatchObject({ code: "INVALID_TOKEN" });
    expect(sign).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([0, 63, 65])("rejects %i-byte signatures", async (length) => {
    const { options, fetch } = await setup();
    const signer: AgentSigner = {
      publicKey: options.signer.publicKey,
      sign: async () => new Uint8Array(length),
    };
    await expect(createRazielClient({ ...options, signer }).me()).rejects.toMatchObject({
      code: "INVALID_SIGNATURE",
    });
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("strict identity response", () => {
  const mutations: Record<string, unknown>[] = [
    { formatVersion: 2 },
    { formatVersion: "1" },
    { agentId: "" },
    { agentId: 12 },
    { agentId: "x".repeat(257) },
    { publicKey: "" },
    { publicKey: Buffer.alloc(32).toString("base64") },
    { keyThumbprint: Buffer.alloc(32).toString("base64") },
    { audience: "different" },
    { tokenExpiresAtUnixSeconds: "01" },
    { tokenExpiresAtUnixSeconds: "-1" },
    { tokenExpiresAtUnixSeconds: "1.0" },
    { tokenExpiresAtUnixSeconds: "1e9" },
    { tokenExpiresAtUnixSeconds: " 1" },
    { tokenExpiresAtUnixSeconds: "253402300800" },
    { tokenExpiresAtUnixSeconds: 1800000000 },
    { policy: "private-diagnostic" },
  ];
  it.each(mutations)("rejects response mutation %#", async (mutation) => {
    const { options, me, fetch } = await setup();
    fetch.mockResolvedValue(Response.json({ ...me, ...mutation }));
    await expect(createRazielClient(options).me()).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    "formatVersion",
    "agentId",
    "publicKey",
    "keyThumbprint",
    "audience",
    "tokenExpiresAtUnixSeconds",
  ])("rejects missing %s", async (key) => {
    const { options, me, fetch } = await setup();
    fetch.mockResolvedValue(
      Response.json(Object.fromEntries(Object.entries(me).filter(([name]) => name !== key))),
    );
    await expect(createRazielClient(options).me()).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
  });

  it("requires canonical padded base64 for both byte fields", async () => {
    const { options, me, fetch } = await setup();
    for (const field of ["publicKey", "keyThumbprint"] as const) {
      for (const value of [
        me[field].slice(0, -1),
        `${me[field]}\n`,
        Buffer.from(me[field], "base64").toString("base64url"),
      ]) {
        fetch.mockResolvedValue(Response.json({ ...me, [field]: value }));
        await expect(createRazielClient(options).me()).rejects.toMatchObject({
          code: "INVALID_RESPONSE",
        });
      }
    }
  });

  it.each([null, [], "string", 1])("rejects nonobject response %#", async (value) => {
    const { options, fetch } = await setup();
    fetch.mockResolvedValue(Response.json(value));
    await expect(createRazielClient(options).me()).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
  });

  it("bounds response bytes and rejects malformed JSON, media types, and unexpected success status", async () => {
    const { options, fetch } = await setup();
    for (const response of [
      Response.json({ oversized: "x".repeat(4_097) }),
      new Response("{", { headers: { "Content-Type": "application/json" } }),
      new Response("<html>private diagnostics</html>"),
      new Response(new Uint8Array([0xff]), { headers: { "Content-Type": "application/json" } }),
      new Response(null, { status: 204 }),
      Response.json({}, { status: 201 }),
    ]) {
      fetch.mockResolvedValue(response);
      await expect(createRazielClient(options).me()).rejects.toMatchObject({
        code: "INVALID_RESPONSE",
      });
    }
  });

  it("rejects followed redirects reported by an injected transport", async () => {
    const { options, me, fetch } = await setup();
    const response = Response.json(me);
    Object.defineProperty(response, "redirected", { value: true });
    fetch.mockResolvedValue(response);
    await expect(createRazielClient(options).me()).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
  });
});

describe("failure handling", () => {
  it.each([
    [400, "INVALID_REQUEST"],
    [401, "NOT_AUTHORIZED"],
    [403, "NOT_AUTHORIZED"],
    [404, "NOT_FOUND"],
    [409, "CONFLICT"],
    [409, "REQUEST_REPLAYED"],
    [410, "EXPIRED"],
    [429, "CAPACITY_EXCEEDED"],
    [503, "SERVICE_UNAVAILABLE"],
  ] as const)("preserves coarse error %s/%s without retry", async (status, code) => {
    const { options, fetch } = await setup();
    fetch.mockResolvedValue(
      Response.json({ error: { code, retryable: status === 503 } }, { status }),
    );
    await expect(createRazielClient(options).me()).rejects.toMatchObject({
      code,
      status,
      retryable: status === 503,
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("redacts arbitrary server errors and invalid status/code combinations", async () => {
    const { options, fetch } = await setup();
    for (const error of [
      { code: token, retryable: true },
      { code: "NOT_AUTHORIZED", retryable: false, detail: token },
      { code: "CONFLICT", retryable: false },
    ]) {
      fetch.mockResolvedValue(Response.json({ error }, { status: 401 }));
      const result = await createRazielClient(options)
        .me()
        .catch((error: unknown) => error);
      expect(result).toMatchObject({ code: "HTTP_ERROR", status: 401 });
      expect(String(result)).not.toContain(token);
    }
  });

  it.each(["provider", "signer", "fetch"] as const)("redacts %s exceptions", async (source) => {
    const { options } = await setup();
    const fail = async () => {
      throw new Error(token);
    };
    const overrides =
      source === "provider"
        ? { tokenProvider: fail }
        : source === "signer"
          ? { signer: { ...options.signer, sign: fail } }
          : { fetch: fail };
    const error = await createRazielClient({ ...options, ...overrides })
      .me()
      .catch((error: unknown) => error);
    expect(error).toBeInstanceOf(RazielClientError);
    expect(String(error)).not.toContain(token);
    expect(error).not.toHaveProperty("cause");
  });

  it("times out a pending token provider and never sends after its late return", async () => {
    const { options, fetch } = await setup();
    let release: (token: string) => void = () => {};
    const client = createRazielClient({
      ...options,
      timeoutMs: 15,
      tokenProvider: () =>
        new Promise<string>((resolve) => {
          release = resolve;
        }),
    });
    await expect(client.me()).rejects.toMatchObject({ code: "TIMEOUT" });
    release(token);
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(fetch).not.toHaveBeenCalled();
  });

  it("aborts a pending fetch and does not retry", async () => {
    const { options, fetch } = await setup();
    let signal: AbortSignal | null | undefined;
    fetch.mockImplementation(async (_url, init) => {
      signal = init?.signal;
      return new Promise<Response>(() => {});
    });
    await expect(createRazielClient({ ...options, timeoutMs: 30 }).me()).rejects.toMatchObject({
      code: "TIMEOUT",
    });
    expect(signal?.aborted).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("bounds the response read and cancels a stalled body", async () => {
    const { options, fetch } = await setup();
    const cancel = vi.fn();
    fetch.mockResolvedValue(
      new Response(new ReadableStream({ cancel }), {
        headers: { "Content-Type": "application/json" },
      }),
    );
    await expect(createRazielClient({ ...options, timeoutMs: 30 }).me()).rejects.toMatchObject({
      code: "TIMEOUT",
    });
    expect(cancel).toHaveBeenCalledOnce();
  });
});
