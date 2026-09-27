import { Buffer } from "node:buffer";
import { toJson } from "@bufbuild/protobuf";

import { canonicalizeRequestTarget } from "./canonical.js";
import {
  type AccessIntent,
  AccessIntentSchema,
  type AccessRequest,
  AccessRequestSchema,
  type AccessRequestMutation,
  AccessRequestMutationSchema,
  AccessRequestState,
  type ListAccessRequestsResponse,
  ListAccessRequestsResponseSchema,
} from "./gen/raziel/v1/agent_api_pb.js";
import { parseProtoJson } from "./protojson.js";
import {
  type createTransport,
  record,
  RazielClientError,
  type RequestOptions,
} from "./transport.js";
import { MAX_PROTOBUF_TIMESTAMP_SECONDS } from "./types.js";

const ROOT = "/api/agent/v1/access-requests";
const MAX_BODY_BYTES = 16 * 1024;
const MAX_CAPABILITY_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 3 * 1024 * 1024;
const MAX_LIST_BYTES = 1024 * 1024;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CURSOR = /^[A-Za-z0-9_-]{1,512}$/;

export interface ListAccessRequestsOptions extends RequestOptions {
  readonly limit?: number;
  readonly cursor?: string;
}

export function accessRequestMethods(transport: ReturnType<typeof createTransport>) {
  return {
    async createAccessRequest(
      intent: AccessIntent,
      options: RequestOptions = {},
    ): Promise<AccessRequest> {
      const body = encodeIntent(intent);
      const id = intent.requestId;
      return transport.request({
        ...options,
        method: "POST",
        target: ROOT,
        body,
        statuses: [200, 201],
        maxResponseBytes: MAX_RESPONSE_BYTES,
        parse: (value, status) => parseRequest(value, status, id),
      });
    },
    async listAccessRequests(
      options: ListAccessRequestsOptions = {},
    ): Promise<ListAccessRequestsResponse> {
      const limit = options.limit ?? 25;
      if (
        !Number.isInteger(limit) ||
        limit < 1 ||
        limit > 50 ||
        (options.cursor !== undefined &&
          (typeof options.cursor !== "string" || !CURSOR.test(options.cursor)))
      )
        throw invalid();
      const query = `limit=${limit}${options.cursor === undefined ? "" : `&cursor=${encodeURIComponent(options.cursor)}`}`;
      return transport.request({
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        method: "GET",
        target: canonicalizeRequestTarget(`${ROOT}?${query}`),
        statuses: [200],
        maxResponseBytes: MAX_LIST_BYTES,
        parse: (value, status) => {
          try {
            const list = parseProtoJson(ListAccessRequestsResponseSchema, value);
            if (
              list.requests.length > limit ||
              (list.nextCursor !== undefined && !CURSOR.test(list.nextCursor))
            )
              throw invalid();
            for (const row of list.requests) {
              validateRequest(row);
              if (row.capability.length !== 0) throw invalid();
            }
            return list;
          } catch {
            throw new RazielClientError("INVALID_RESPONSE", status);
          }
        },
      });
    },
    async getAccessRequest(id: string, options: RequestOptions = {}): Promise<AccessRequest> {
      requestId(id);
      return transport.request({
        ...options,
        method: "GET",
        target: `${ROOT}/${id}`,
        statuses: [200],
        maxResponseBytes: MAX_RESPONSE_BYTES,
        parse: (value, status) => parseRequest(value, status, id),
      });
    },
    async cancelAccessRequest(
      id: string,
      mutation: AccessRequestMutation,
      options: RequestOptions = {},
    ): Promise<AccessRequest> {
      requestId(id);
      const body = encodeMutation(mutation);
      return transport.request({
        ...options,
        method: "POST",
        target: `${ROOT}/${id}/cancel`,
        body,
        statuses: [200, 202],
        maxResponseBytes: MAX_RESPONSE_BYTES,
        parse: (value, status) => parseRequest(value, status, id),
      });
    },
  };
}

function encodeIntent(intent: AccessIntent): string {
  try {
    messageKeys(
      intent,
      AccessIntentSchema.fields.map((field) => field.localName),
    );
    if (intent.formatVersion !== 1) throw invalid();
    requestId(intent.requestId);
    claim(intent.taskId);
    claim(intent.purpose);
    if (
      intent.action !== "query" ||
      typeof intent.datasetId !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(intent.datasetId)
    )
      throw invalid();
    revision(intent.datasetRevision);
    if (!Array.isArray(intent.requestContext) || intent.requestContext.length > 16) throw invalid();
    const names = new Set<string>();
    for (const entry of intent.requestContext) {
      messageKeys(entry, ["name", "value"]);
      if (
        typeof entry.name !== "string" ||
        !/^[a-z][a-z0-9_]{0,255}$/.test(entry.name) ||
        names.has(entry.name)
      )
        throw invalid();
      names.add(entry.name);
      if (
        !record(entry.value) ||
        Object.keys(entry.value).some((key) => key !== "case" && key !== "value")
      )
        throw invalid();
      switch (entry.value.case) {
        case "boolValue":
          if (typeof entry.value.value !== "boolean") throw invalid();
          break;
        case "intValue":
          if (
            typeof entry.value.value !== "bigint" ||
            entry.value.value < -9223372036854775808n ||
            entry.value.value > 9223372036854775807n
          )
            throw invalid();
          break;
        case "stringValue":
          if (typeof entry.value.value !== "string" || Buffer.byteLength(entry.value.value) > 256)
            throw invalid();
          break;
        default:
          throw invalid();
      }
    }
    const value = toJson(AccessIntentSchema, intent);
    parseProtoJson(AccessIntentSchema, value);
    return boundedBody(value);
  } catch {
    throw invalid();
  }
}

function encodeMutation(mutation: AccessRequestMutation): string {
  try {
    messageKeys(mutation, ["formatVersion", "expectedGeneration"]);
    if (mutation.formatVersion !== 1) throw invalid();
    generation(mutation.expectedGeneration);
    const value = toJson(AccessRequestMutationSchema, mutation);
    parseProtoJson(AccessRequestMutationSchema, value);
    return boundedBody(value);
  } catch {
    throw invalid();
  }
}

function boundedBody(value: unknown): string {
  const body = JSON.stringify(value);
  if (Buffer.byteLength(body) > MAX_BODY_BYTES) throw invalid();
  return body;
}

function messageKeys(value: unknown, fields: string[]) {
  if (
    !record(value) ||
    Object.keys(value).some((key) => !fields.includes(key) && key !== "$typeName")
  )
    throw invalid();
}

function parseRequest(value: unknown, status: number, id: string): AccessRequest {
  try {
    const row = parseProtoJson(AccessRequestSchema, value);
    validateRequest(row);
    if (row.requestId !== id) throw invalid();
    return row;
  } catch {
    throw new RazielClientError("INVALID_RESPONSE", status);
  }
}

function validateRequest(row: AccessRequest) {
  requestId(row.requestId);
  claim(row.agentId);
  claim(row.taskId);
  claim(row.purpose);
  if (row.action !== "query" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(row.datasetId))
    throw invalid();
  revision(row.datasetRevision);
  generation(row.generation);
  if (
    row.state < AccessRequestState.PENDING_REVIEW ||
    row.state > AccessRequestState.FAILED ||
    row.capability.length > MAX_CAPABILITY_BYTES
  )
    throw invalid();
  for (const time of [
    row.createdAtUnixSeconds,
    row.updatedAtUnixSeconds,
    row.deadlineUnixSeconds,
  ]) {
    if (time < 0n || time > MAX_PROTOBUF_TIMESTAMP_SECONDS) throw invalid();
  }
  if (row.proposal) {
    generation(row.proposal.generation);
    for (const time of [
      row.proposal.signatureDeadlineUnixSeconds,
      row.proposal.requestedExpiresAtUnixSeconds,
    ]) {
      if (time < 0n || time > MAX_PROTOBUF_TIMESTAMP_SECONDS) throw invalid();
    }
  }
}

function requestId(value: string) {
  if (typeof value !== "string" || !UUID_V4.test(value)) throw invalid();
}
function claim(value: string) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    Buffer.byteLength(value) > 256 ||
    /\p{Cc}/u.test(value)
  )
    throw invalid();
}
function revision(value: bigint) {
  if (typeof value !== "bigint" || value < 1n || value > BigInt(Number.MAX_SAFE_INTEGER))
    throw invalid();
}
function generation(value: bigint) {
  if (typeof value !== "bigint" || value < 1n || value > 18446744073709551615n) throw invalid();
}
function invalid() {
  return new RazielClientError("INVALID_REQUEST");
}
