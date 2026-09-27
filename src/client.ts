import { Buffer } from "node:buffer";

import { accessRequestMethods } from "./access-requests.js";
import { datasetQueryMethods } from "./dataset-query.js";
import { issuanceMethods } from "./issuance.js";
import { pollingMethods } from "./polling.js";
import {
  createTransport,
  exactKeys,
  RazielClientError,
  type RazielClientOptions,
  type RequestOptions,
  record,
} from "./transport.js";
import { AGENT_API_FORMAT_VERSION, type AgentMe, MAX_PROTOBUF_TIMESTAMP_SECONDS } from "./types.js";

export {
  type RazielApiErrorCode,
  RazielClientError,
  type RazielClientErrorCode,
  type RazielClientOptions,
  type RequestOptions,
} from "./transport.js";

export interface RazielClient
  extends ReturnType<typeof accessRequestMethods>,
    ReturnType<typeof issuanceMethods>,
    ReturnType<typeof pollingMethods>,
    ReturnType<typeof datasetQueryMethods> {
  me(options?: RequestOptions): Promise<AgentMe>;
}

/** Caller-owned intent and signing. No call retries or starts a proof implicitly. */
export function createRazielClient(options: RazielClientOptions): RazielClient {
  const transport = createTransport(options);
  const access = accessRequestMethods(transport);
  return {
    ...access,
    ...issuanceMethods(options.signer, options.timeoutMs),
    ...pollingMethods(access),
    ...datasetQueryMethods(transport, options.signer, options.timeoutMs),
    me(requestOptions = {}) {
      return transport.request({
        ...requestOptions,
        method: "GET",
        target: "/api/agent/v1/me",
        statuses: [200],
        maxResponseBytes: 4_096,
        parse: (body, _status, keyThumbprint) =>
          parseMe(body, transport.publicKey, keyThumbprint, transport.audience),
      });
    },
  };
}

function parseMe(
  value: unknown,
  publicKey: Uint8Array,
  keyThumbprint: Uint8Array,
  audience: string,
): AgentMe {
  if (
    !record(value) ||
    !exactKeys(value, [
      "formatVersion",
      "agentId",
      "publicKey",
      "keyThumbprint",
      "audience",
      "tokenExpiresAtUnixSeconds",
    ]) ||
    value.formatVersion !== AGENT_API_FORMAT_VERSION ||
    typeof value.agentId !== "string" ||
    value.agentId.length === 0 ||
    Buffer.byteLength(value.agentId, "utf8") > 256 ||
    value.publicKey !== Buffer.from(publicKey).toString("base64") ||
    value.keyThumbprint !== Buffer.from(keyThumbprint).toString("base64") ||
    value.audience !== audience ||
    typeof value.tokenExpiresAtUnixSeconds !== "string" ||
    !/^(0|[1-9][0-9]{0,11})$/.test(value.tokenExpiresAtUnixSeconds) ||
    BigInt(value.tokenExpiresAtUnixSeconds) > MAX_PROTOBUF_TIMESTAMP_SECONDS
  )
    throw new RazielClientError("INVALID_RESPONSE", 200);
  return {
    formatVersion: AGENT_API_FORMAT_VERSION,
    agentId: value.agentId,
    publicKey: value.publicKey,
    keyThumbprint: value.keyThumbprint,
    audience: value.audience,
    tokenExpiresAtUnixSeconds: value.tokenExpiresAtUnixSeconds,
  };
}
