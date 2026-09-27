import { webcrypto } from "node:crypto";

import {
  AGENT_API_FORMAT_VERSION,
  type AgentApiRequestSignatureInput,
  type AuthorizationContextEntry,
  CAPABILITY_REQUEST_FORMAT_VERSION,
  type CapabilityRequestBinding,
  DIGEST_BYTES,
  MAX_CANONICAL_REQUEST_TARGET_BYTES,
  MAX_CONTEXT_ENTRIES,
  MAX_PROTOBUF_TIMESTAMP_SECONDS,
  MAX_STRING_BYTES,
  PROTECTED_REQUEST_FORMAT_VERSION,
} from "./types.js";

const TEXT_ENCODER = new TextEncoder();
const CAPABILITY_REQUEST_DOMAIN = ascii("raziel/capability-request/v1");
const PROTECTED_REQUEST_DOMAIN = ascii("raziel/protected-request/v1");
const AGENT_API_REQUEST_DOMAIN = ascii("raziel/agent-api-request/v1");
const ALLOWED_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const LOWER_HEX = /^[0-9a-f]{64}$/;
const IDENTIFIER = /^[a-z][a-z0-9_]*$/;

export class RazielCanonicalError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "RazielCanonicalError";
  }
}

class Encoder {
  readonly #parts: Uint8Array[] = [];

  public writeU8(value: number): void {
    this.#parts.push(Uint8Array.of(value));
  }

  public writeU32(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
      throw new RazielCanonicalError("u32 value is outside the supported range");
    }
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, false);
    this.#parts.push(bytes);
  }

  public writeI64(value: bigint): void {
    if (value < -(1n << 63n) || value > (1n << 63n) - 1n) {
      throw new RazielCanonicalError("i64 value is outside the supported range");
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigInt64(0, value, false);
    this.#parts.push(bytes);
  }

  public writeBytes(value: Uint8Array): void {
    this.writeU32(value.byteLength);
    this.#parts.push(value.slice());
  }

  public writeString(value: string): void {
    this.writeBytes(TEXT_ENCODER.encode(value));
  }

  public finish(): Uint8Array {
    return concatenate(this.#parts);
  }
}

export function normalizeContext(
  entries: readonly AuthorizationContextEntry[] = [],
): readonly AuthorizationContextEntry[] {
  if (entries.length > MAX_CONTEXT_ENTRIES) {
    throw new RazielCanonicalError("request context exceeds the supported entry count");
  }
  const normalized = entries.map((entry) => ({
    name: entry.name,
    value: { ...entry.value },
  }));
  normalized.sort((left, right) => compareAscii(left.name, right.name));
  for (let index = 0; index < normalized.length; index += 1) {
    const entry = normalized[index];
    if (!entry || !IDENTIFIER.test(entry.name)) {
      throw new RazielCanonicalError("request context names must be lowercase identifiers");
    }
    validateString(entry.name, "request context name");
    if (index > 0 && normalized[index - 1]?.name === entry.name) {
      throw new RazielCanonicalError("request context names must be unique");
    }
    if (entry.value.kind === "string") {
      validateString(entry.value.value, "request context string");
    }
  }
  return normalized;
}

export async function capabilityRequestCommitment(
  request: CapabilityRequestBinding,
): Promise<Uint8Array> {
  validateCapabilityRequest(request);
  const payload = new Encoder();
  payload.writeU32(request.formatVersion);
  payload.writeBytes(request.agentKeyThumbprint);
  payload.writeString(request.taskId);
  payload.writeString(request.purpose);
  payload.writeString(request.action);
  payload.writeString(request.resourceType);
  payload.writeString(request.resourceScope);
  payload.writeI64(request.requestedExpiresAtUnixSeconds);
  payload.writeBytes(request.issuanceNonce);
  payload.writeString(request.snapshotId);
  const context = normalizeContext(request.requestContext);
  payload.writeU32(context.length);
  for (const entry of context) {
    encodeContextEntry(payload, entry);
  }
  return framedHash(CAPABILITY_REQUEST_DOMAIN, payload.finish());
}

export function canonicalizeRequestMethod(value: string): string {
  if (!isAscii(value)) {
    throw new RazielCanonicalError("request method must be ASCII");
  }
  const canonical = value.toUpperCase();
  if (!ALLOWED_METHODS.has(canonical)) {
    throw new RazielCanonicalError("request method is unsupported");
  }
  return canonical;
}

export function canonicalizeRequestTarget(value: string): string {
  if (
    value.length === 0 ||
    value.length > MAX_CANONICAL_REQUEST_TARGET_BYTES ||
    !isAscii(value) ||
    value.includes("#")
  ) {
    throw new RazielCanonicalError("request target is invalid");
  }

  const question = value.indexOf("?");
  let path = value;
  let query: string | undefined;
  if (question >= 0) {
    path = value.slice(0, question);
    query = value.slice(question + 1);
    if (query.length === 0 || query.includes("?")) {
      throw new RazielCanonicalError("request target query is invalid");
    }
  }

  const canonicalPath = canonicalizePath(path);
  const canonical =
    query === undefined ? canonicalPath : `${canonicalPath}?${canonicalizeQuery(query)}`;
  if (canonical.length > MAX_CANONICAL_REQUEST_TARGET_BYTES) {
    throw new RazielCanonicalError("canonical request target is too large");
  }
  return canonical;
}

export interface ProtectedRequestSignatureInput {
  readonly formatVersion: typeof PROTECTED_REQUEST_FORMAT_VERSION;
  readonly capabilityId: string;
  readonly requestMethod: string;
  readonly canonicalRequestTarget: string;
  readonly requestBodyHash: Uint8Array;
  readonly requestNonce: Uint8Array;
  readonly requestTimestampUnixSeconds: bigint;
}

export function protectedRequestSignatureMessage(
  input: ProtectedRequestSignatureInput,
): Uint8Array {
  if (input.formatVersion !== PROTECTED_REQUEST_FORMAT_VERSION) {
    throw new RazielCanonicalError("protected request version is unsupported");
  }
  if (!LOWER_HEX.test(input.capabilityId)) {
    throw new RazielCanonicalError("capability identifier must be 32-byte lowercase hex");
  }
  if (canonicalizeRequestMethod(input.requestMethod) !== input.requestMethod) {
    throw new RazielCanonicalError("request method is not canonical");
  }
  if (canonicalizeRequestTarget(input.canonicalRequestTarget) !== input.canonicalRequestTarget) {
    throw new RazielCanonicalError("request target is not canonical");
  }
  fixedDigest(input.requestBodyHash, "request body hash");
  fixedDigest(input.requestNonce, "request nonce");
  if (input.requestTimestampUnixSeconds < 0n) {
    throw new RazielCanonicalError("request timestamp must be non-negative");
  }

  const payload = new Encoder();
  payload.writeU32(input.formatVersion);
  payload.writeString(input.capabilityId);
  payload.writeString(input.requestMethod);
  payload.writeString(input.canonicalRequestTarget);
  payload.writeBytes(input.requestBodyHash);
  payload.writeBytes(input.requestNonce);
  payload.writeI64(input.requestTimestampUnixSeconds);
  return framedMessage(PROTECTED_REQUEST_DOMAIN, payload.finish());
}

export async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await webcrypto.subtle.digest("SHA-256", value));
}

export function validateAgentAudience(value: string): void {
  if (typeof value !== "string" || !/^[\x20-\x7e]{1,128}$/.test(value)) {
    throw new RazielCanonicalError("agent API audience must be 1-128 printable ASCII bytes");
  }
}

export function agentApiRequestSignatureMessage(input: AgentApiRequestSignatureInput): Uint8Array {
  if (input.formatVersion !== AGENT_API_FORMAT_VERSION) {
    throw new RazielCanonicalError("agent API request version is unsupported");
  }
  validateAgentAudience(input.audience);
  if (typeof input.tokenId !== "string" || !/^[0-9a-f]{32}$/.test(input.tokenId)) {
    throw new RazielCanonicalError("token identifier must be 16-byte lowercase hex");
  }
  if (canonicalizeRequestMethod(input.requestMethod) !== input.requestMethod) {
    throw new RazielCanonicalError("request method is not canonical");
  }
  if (canonicalizeRequestTarget(input.canonicalRequestTarget) !== input.canonicalRequestTarget) {
    throw new RazielCanonicalError("request target is not canonical");
  }
  fixedDigest(input.agentKeyThumbprint, "agent key thumbprint");
  fixedDigest(input.requestBodyHash, "request body hash");
  fixedDigest(input.requestNonce, "request nonce");
  if (
    typeof input.requestTimestampUnixSeconds !== "bigint" ||
    input.requestTimestampUnixSeconds < 0n ||
    input.requestTimestampUnixSeconds > MAX_PROTOBUF_TIMESTAMP_SECONDS
  ) {
    throw new RazielCanonicalError("agent API timestamp is outside the supported range");
  }

  const payload = new Encoder();
  payload.writeU32(input.formatVersion);
  payload.writeString(input.audience);
  payload.writeString(input.tokenId);
  payload.writeBytes(input.agentKeyThumbprint);
  payload.writeString(input.requestMethod);
  payload.writeString(input.canonicalRequestTarget);
  payload.writeBytes(input.requestBodyHash);
  payload.writeBytes(input.requestNonce);
  payload.writeI64(input.requestTimestampUnixSeconds);
  return framedMessage(AGENT_API_REQUEST_DOMAIN, payload.finish());
}

export function encodeHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function decodeHex(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) {
    throw new RazielCanonicalError("hex value must be lowercase and byte aligned");
  }
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (pair) => Number.parseInt(pair, 16));
}

function validateCapabilityRequest(request: CapabilityRequestBinding): void {
  if (request.formatVersion !== CAPABILITY_REQUEST_FORMAT_VERSION) {
    throw new RazielCanonicalError("capability request version is unsupported");
  }
  fixedNonZeroDigest(request.agentKeyThumbprint, "agent key thumbprint");
  fixedNonZeroDigest(request.issuanceNonce, "issuance nonce");
  validateNonemptyString(request.taskId, "task identifier");
  validateNonemptyString(request.purpose, "purpose");
  validateIdentifier(request.action, "action");
  validateIdentifier(request.resourceType, "resource type");
  validateNonemptyString(request.resourceScope, "resource scope");
  validateNonemptyString(request.snapshotId, "snapshot identifier");
  if (request.requestedExpiresAtUnixSeconds < 0n) {
    throw new RazielCanonicalError("requested expiry must be non-negative");
  }
}

function encodeContextEntry(encoder: Encoder, entry: AuthorizationContextEntry): void {
  encoder.writeString(entry.name);
  switch (entry.value.kind) {
    case "bool":
      encoder.writeU8(0x01);
      encoder.writeU8(entry.value.value ? 0x01 : 0x00);
      return;
    case "int":
      encoder.writeU8(0x02);
      encoder.writeI64(entry.value.value);
      return;
    case "string":
      encoder.writeU8(0x03);
      encoder.writeString(entry.value.value);
      return;
  }
}

function canonicalizePath(path: string): string {
  if (!path.startsWith("/") || (path.length > 1 && path.endsWith("/"))) {
    throw new RazielCanonicalError("request path is invalid");
  }
  if (path === "/") {
    return path;
  }
  const segments = path.slice(1).split("/");
  return `/${segments
    .map((segment) => {
      if (segment.length === 0) {
        throw new RazielCanonicalError("request path has an empty segment");
      }
      const value = canonicalizeComponent(segment, "path");
      if (value === "." || value === "..") {
        throw new RazielCanonicalError("request path has a dot segment");
      }
      return value;
    })
    .join("/")}`;
}

function canonicalizeQuery(query: string): string {
  const entries = new Map<string, string>();
  for (const rawEntry of query.split("&")) {
    if (rawEntry.length === 0) {
      throw new RazielCanonicalError("request query has an empty entry");
    }
    const equals = rawEntry.indexOf("=");
    const rawKey = equals < 0 ? rawEntry : rawEntry.slice(0, equals);
    const rawValue = equals < 0 ? "" : rawEntry.slice(equals + 1);
    if (rawKey.length === 0) {
      throw new RazielCanonicalError("request query key is empty");
    }
    const key = canonicalizeComponent(rawKey, "query");
    const value = canonicalizeComponent(rawValue, "query");
    if (entries.has(key)) {
      throw new RazielCanonicalError("request query has a duplicate canonical key");
    }
    entries.set(key, value);
  }
  return [...entries.entries()]
    .sort(([left], [right]) => compareAscii(left, right))
    .map(([key, value]) => `${key}=${value}`)
    .join("&");
}

function canonicalizeComponent(value: string, kind: "path" | "query"): string {
  let canonical = "";
  for (let index = 0; index < value.length; ) {
    const code = value.charCodeAt(index);
    if (isUnreserved(code)) {
      canonical += value[index];
      index += 1;
      continue;
    }
    if (kind === "query" && code === 0x2b) {
      canonical += "%2B";
      index += 1;
      continue;
    }
    const percentEscape = value.slice(index + 1, index + 3);
    if (code !== 0x25 || percentEscape.length !== 2 || !/^[0-9a-fA-F]{2}$/.test(percentEscape)) {
      throw new RazielCanonicalError("request target percent escape is invalid");
    }
    const decoded = Number.parseInt(percentEscape, 16);
    if (kind === "path" && [0x2f, 0x5c, 0x3f, 0x23].includes(decoded)) {
      throw new RazielCanonicalError("request path contains an escaped delimiter");
    }
    canonical += isUnreserved(decoded)
      ? String.fromCharCode(decoded)
      : `%${decoded.toString(16).toUpperCase().padStart(2, "0")}`;
    index += 3;
  }
  return canonical;
}

function validateIdentifier(value: string, label: string): void {
  validateString(value, label);
  if (!IDENTIFIER.test(value)) {
    throw new RazielCanonicalError(`${label} must be a lowercase identifier`);
  }
}

function validateNonemptyString(value: string, label: string): void {
  validateString(value, label);
  if (value.length === 0) {
    throw new RazielCanonicalError(`${label} must not be empty`);
  }
}

function validateString(value: string, label: string): void {
  if (TEXT_ENCODER.encode(value).byteLength > MAX_STRING_BYTES) {
    throw new RazielCanonicalError(`${label} exceeds the supported byte length`);
  }
}

function fixedDigest(value: Uint8Array, label: string): void {
  if (value.byteLength !== DIGEST_BYTES) {
    throw new RazielCanonicalError(`${label} must contain exactly ${DIGEST_BYTES} bytes`);
  }
}

function fixedNonZeroDigest(value: Uint8Array, label: string): void {
  fixedDigest(value, label);
  if (value.every((byte) => byte === 0)) {
    throw new RazielCanonicalError(`${label} must not be zero`);
  }
}

function framedMessage(domain: Uint8Array, payload: Uint8Array): Uint8Array {
  const encoder = new Encoder();
  encoder.writeBytes(domain);
  encoder.writeBytes(payload);
  return encoder.finish();
}

async function framedHash(domain: Uint8Array, payload: Uint8Array): Promise<Uint8Array> {
  return sha256(framedMessage(domain, payload));
}

function concatenate(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }
  return joined;
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isAscii(value: string): boolean {
  return [...value].every((character) => character.charCodeAt(0) <= 0x7f);
}

function isUnreserved(value: number): boolean {
  return (
    (value >= 0x30 && value <= 0x39) ||
    (value >= 0x41 && value <= 0x5a) ||
    (value >= 0x61 && value <= 0x7a) ||
    [0x2d, 0x2e, 0x5f, 0x7e].includes(value)
  );
}

function ascii(value: string): Uint8Array {
  if (!isAscii(value)) {
    throw new RazielCanonicalError("protocol domain must be ASCII");
  }
  return TEXT_ENCODER.encode(value);
}
