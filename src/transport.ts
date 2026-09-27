import { Buffer } from "node:buffer";

import { randomDigest } from "./agent.js";
import {
  agentApiRequestSignatureMessage,
  encodeHex,
  sha256,
  validateAgentAudience,
} from "./canonical.js";
import { copyAgentPublicKey } from "./signer.js";
import { AGENT_API_FORMAT_VERSION, type AgentSigner, ED25519_SIGNATURE_BYTES } from "./types.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const API_ERROR_STATUS = {
  INVALID_REQUEST: [400],
  NOT_AUTHORIZED: [401, 403],
  NOT_FOUND: [404],
  CONFLICT: [409],
  REQUEST_REPLAYED: [409],
  EXPIRED: [410],
  CAPACITY_EXCEEDED: [429],
  SERVICE_UNAVAILABLE: [503],
} as const;

export type RazielApiErrorCode = keyof typeof API_ERROR_STATUS;
export type RazielClientErrorCode =
  | RazielApiErrorCode
  | "INVALID_TOKEN"
  | "TOKEN_PROVIDER_FAILED"
  | "SIGNER_FAILED"
  | "INVALID_SIGNATURE"
  | "TRANSPORT_ERROR"
  | "TIMEOUT"
  | "ABORTED"
  | "INVALID_RESPONSE"
  | "AUTHORIZATION_REJECTED"
  | "PROTECTED_QUERY_UNAVAILABLE"
  | "HTTP_ERROR";

export class RazielClientError extends Error {
  public constructor(
    public readonly code: RazielClientErrorCode,
    public readonly status: number | undefined = undefined,
    public readonly retryable = false,
    public readonly retryAfterMs: number | undefined = undefined,
  ) {
    super(`Raziel request failed: ${code}`);
    this.name = "RazielClientError";
  }
}

export interface RazielClientOptions {
  readonly baseUrl: string;
  readonly audience: string;
  readonly tokenProvider: () => string | Promise<string>;
  readonly signer: AgentSigner;
  readonly fetch?: typeof globalThis.fetch;
  readonly timeoutMs?: number;
}

export interface RequestOptions {
  readonly signal?: AbortSignal;
}

interface RequestSpec<T> extends RequestOptions {
  readonly method: "GET" | "POST";
  readonly target: string;
  readonly body?: string;
  readonly statuses: readonly number[];
  readonly maxResponseBytes: number;
  readonly parse: (body: unknown, status: number, keyThumbprint: Uint8Array) => T;
}

/** Build a caller-owned signer client. A call performs one signed request, with no retries. */
export function createTransport(options: RazielClientOptions) {
  const origin = validateBaseUrl(options.baseUrl);
  validateAgentAudience(options.audience);
  const audience = options.audience;
  const publicKey = copyAgentPublicKey(options.signer.publicKey);
  if (typeof options.signer.sign !== "function" || typeof options.tokenProvider !== "function") {
    throw new TypeError("signer and token provider must be functions");
  }
  const sign = options.signer.sign.bind(options.signer);
  const tokenProvider = options.tokenProvider;
  const fetchRequest = options.fetch ?? globalThis.fetch;
  if (typeof fetchRequest !== "function") {
    throw new TypeError("fetch is required");
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2_147_483_647) {
    throw new TypeError("timeoutMs must be a positive 32-bit timer duration");
  }

  return {
    publicKey,
    audience,
    request<T>(spec: RequestSpec<T>): Promise<T> {
      return withTimeout(timeoutMs, spec.signal, async (signal) => {
        let token: string;
        try {
          token = await tokenProvider();
        } catch {
          throw new RazielClientError("TOKEN_PROVIDER_FAILED");
        }
        signal.throwIfAborted();
        const tokenId = parseTokenId(token);
        const keyThumbprint = await sha256(publicKey);
        const requestBodyHash = await sha256(new TextEncoder().encode(spec.body ?? ""));
        signal.throwIfAborted();
        const requestNonce = randomDigest();
        const requestTimestampUnixSeconds = BigInt(Math.floor(Date.now() / 1_000));
        const message = agentApiRequestSignatureMessage({
          formatVersion: AGENT_API_FORMAT_VERSION,
          audience,
          tokenId,
          agentKeyThumbprint: keyThumbprint,
          requestMethod: spec.method,
          canonicalRequestTarget: spec.target,
          requestBodyHash,
          requestNonce,
          requestTimestampUnixSeconds,
        });
        let signature: Uint8Array;
        try {
          signature = await sign(message);
        } catch {
          throw new RazielClientError("SIGNER_FAILED");
        }
        signal.throwIfAborted();
        if (
          !(signature instanceof Uint8Array) ||
          signature.byteLength !== ED25519_SIGNATURE_BYTES
        ) {
          throw new RazielClientError("INVALID_SIGNATURE");
        }
        const url = `${origin}${spec.target}`;
        const response = await fetchRequest(url, {
          method: spec.method,
          ...(spec.body === undefined ? {} : { body: spec.body }),
          headers: {
            Accept: "application/json",
            ...(spec.body === undefined ? {} : { "Content-Type": "application/json" }),
            Authorization: `Bearer ${token}`,
            "X-Raziel-Agent-Version": "1",
            "X-Raziel-Agent-Timestamp": requestTimestampUnixSeconds.toString(),
            "X-Raziel-Agent-Nonce": encodeHex(requestNonce),
            "X-Raziel-Agent-Signature": encodeHex(signature),
          },
          redirect: "error",
          credentials: "omit",
          cache: "no-store",
          referrerPolicy: "no-referrer",
          signal,
        });
        signal.throwIfAborted();
        if (response.redirected || (response.url !== "" && response.url !== url)) {
          discard(response);
          throw new RazielClientError("INVALID_RESPONSE", response.status);
        }
        if (!response.ok) {
          throw await apiError(response, signal);
        }
        if (!spec.statuses.includes(response.status)) {
          discard(response);
          throw new RazielClientError("INVALID_RESPONSE", response.status);
        }
        const body = await readJson(response, signal, spec.maxResponseBytes);
        return spec.parse(body, response.status, keyThumbprint);
      });
    },
  };
}

function validateBaseUrl(value: string): string {
  if (typeof value !== "string" || !/^https?:\/\/[^/?#\\\s@]+\/?$/.test(value)) {
    throw new TypeError(
      "baseUrl must be an HTTP(S) origin without credentials, path, query, or hash",
    );
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("baseUrl must be a valid HTTP(S) origin");
  }
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "[::1]" ||
    /^127\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}$/.test(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new TypeError("baseUrl requires HTTPS outside loopback development");
  }
  return url.origin;
}

function parseTokenId(token: string): string {
  if (typeof token !== "string") {
    throw new RazielClientError("INVALID_TOKEN");
  }
  const match = /^rz1\.([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$/.exec(token);
  const tokenId = match?.[1];
  const secret = match?.[2];
  if (tokenId === undefined || secret === undefined) {
    throw new RazielClientError("INVALID_TOKEN");
  }
  const decoded = Buffer.from(secret, "base64url");
  if (decoded.byteLength !== 32 || decoded.toString("base64url") !== secret) {
    throw new RazielClientError("INVALID_TOKEN");
  }
  return tokenId;
}

export async function withTimeout<T>(
  timeoutMs: number,
  callerSignal: AbortSignal | undefined,
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abort = () => {};
  const deadline = new Promise<never>((_resolve, reject) => {
    const stop = (code: "ABORTED" | "TIMEOUT") => {
      if (controller.signal.aborted) return;
      const error = new RazielClientError(code);
      controller.abort(error);
      reject(error);
    };
    abort = () => stop("ABORTED");
    callerSignal?.addEventListener("abort", abort, { once: true });
    if (callerSignal?.aborted) abort();
    else timer = setTimeout(() => stop("TIMEOUT"), timeoutMs);
  });
  try {
    return await Promise.race([
      deadline,
      Promise.resolve().then(() => {
        controller.signal.throwIfAborted();
        return operation(controller.signal);
      }),
    ]);
  } catch (error) {
    if (controller.signal.aborted) {
      throw controller.signal.reason;
    }
    if (error instanceof RazielClientError) {
      throw error;
    }
    throw new RazielClientError("TRANSPORT_ERROR");
  } finally {
    clearTimeout(timer);
    callerSignal?.removeEventListener("abort", abort);
  }
}

function discard(response: Response) {
  void response.body?.cancel().catch(() => {});
}

async function readJson(
  response: Response,
  signal: AbortSignal,
  maxBytes: number,
): Promise<unknown> {
  const length = response.headers.get("content-length");
  if (
    response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() !==
      "application/json" ||
    (length !== null && (!/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > maxBytes))
  ) {
    discard(response);
    throw new RazielClientError("INVALID_RESPONSE", response.status);
  }
  const reader = response.body?.getReader();
  if (!reader) {
    throw new RazielClientError("INVALID_RESPONSE", response.status);
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  const cancel = () => {
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    for (;;) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        cancel();
        throw new RazielClientError("INVALID_RESPONSE", response.status);
      }
      chunks.push(value);
    }
    try {
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
    } catch {
      throw new RazielClientError("INVALID_RESPONSE", response.status);
    }
  } finally {
    signal.removeEventListener("abort", cancel);
    reader.releaseLock();
  }
}

export function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return (
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key))
  );
}

async function apiError(response: Response, signal: AbortSignal): Promise<RazielClientError> {
  try {
    const value = await readJson(response, signal, 4_096);
    if (record(value) && exactKeys(value, ["error"])) {
      if (response.status === 403 && value.error === "AUTHORIZATION_REJECTED")
        return new RazielClientError("AUTHORIZATION_REJECTED", 403);
      if (response.status === 503 && value.error === "PROTECTED_QUERY_UNAVAILABLE")
        return new RazielClientError(
          "PROTECTED_QUERY_UNAVAILABLE",
          503,
          true,
          retryAfter(response),
        );
    }
    if (
      record(value) &&
      exactKeys(value, ["error"]) &&
      record(value.error) &&
      exactKeys(value.error, ["code", "retryable"]) &&
      typeof value.error.code === "string" &&
      Object.hasOwn(API_ERROR_STATUS, value.error.code) &&
      typeof value.error.retryable === "boolean"
    ) {
      const code = value.error.code as RazielApiErrorCode;
      const statuses: readonly number[] = API_ERROR_STATUS[code];
      if (statuses.includes(response.status)) {
        return new RazielClientError(
          code,
          response.status,
          value.error.retryable,
          retryAfter(response),
        );
      }
    }
  } catch {
    // Server diagnostics and malformed error bodies never become public error messages.
  }
  return new RazielClientError("HTTP_ERROR", response.status);
}

function retryAfter(response: Response): number | undefined {
  const value = response.headers.get("retry-after");
  if (value === null || value.length > 128) return undefined;
  const delay = /^(0|[1-9][0-9]*)$/.test(value)
    ? Number(value) * 1000
    : Date.parse(value) - Date.now();
  return Number.isFinite(delay) ? Math.min(30_000, Math.max(0, Math.ceil(delay))) : undefined;
}
