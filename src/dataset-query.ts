import { Buffer } from "node:buffer";
import { fromBinary } from "@bufbuild/protobuf";
import { randomDigest } from "./agent.js";
import { encodeHex, protectedRequestSignatureMessage, sha256 } from "./canonical.js";
import { type ProofCapability, ProofCapabilitySchema } from "./public.js";
import { parseDatasetResult } from "./query-result.js";
import { copyAgentPublicKey } from "./signer.js";
import {
  type createTransport,
  RazielClientError,
  type RequestOptions,
  withTimeout,
} from "./transport.js";
import type { AgentSigner } from "./types.js";

export interface DatasetQuery {
  readonly fromOccurredAt: string;
  readonly toOccurredAt: string;
  readonly limit: number;
}
export type DatasetQueryResult = ReturnType<typeof parseDatasetResult>;

export function datasetQueryMethods(
  transport: ReturnType<typeof createTransport>,
  signer: AgentSigner,
  timeoutMs = 10_000,
) {
  const publicKey = copyAgentPublicKey(signer.publicKey);
  const sign = signer.sign.bind(signer);
  return {
    /** One read attempt. Repeating this call keeps the capability and refreshes both signatures. */
    async queryDataset(
      datasetId: string,
      capabilityBytes: Uint8Array,
      query: DatasetQuery,
      options: RequestOptions = {},
    ): Promise<DatasetQueryResult> {
      return withTimeout(timeoutMs, options.signal, async (signal) => {
        if (
          typeof datasetId !== "string" ||
          !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(datasetId) ||
          !(capabilityBytes instanceof Uint8Array) ||
          capabilityBytes.length === 0 ||
          capabilityBytes.length > 2 * 1024 * 1024
        )
          throw invalid();
        const retained = new Uint8Array(capabilityBytes);
        let capability: ProofCapability;
        try {
          capability = fromBinary(ProofCapabilitySchema, retained);
        } catch {
          throw invalid();
        }
        const body = queryBody(query);
        const target = `/api/datasets/${encodeURIComponent(datasetId)}/protected-query`;
        const now = BigInt(Math.floor(Date.now() / 1000));
        const thumbprint = await sha256(publicKey);
        if (
          capability.formatVersion !== 1 ||
          !/^[0-9a-f]{64}$/.test(capability.capabilityId) ||
          capability.resourceScope !== datasetId ||
          capability.action !== "query" ||
          !/^(dataset|dataset_[0-9a-f]{32})$/.test(capability.resourceType) ||
          encodeHex(capability.agentKeyThumbprint) !== encodeHex(thumbprint) ||
          !capability.expiresAt ||
          capability.expiresAt.nanos !== 0 ||
          capability.expiresAt.seconds <= now
        )
          throw invalid();
        // These are local scope checks, not proof verification. The gateway remains authoritative.
        const nonce = randomDigest();
        const bodyHash = await sha256(body);
        const message = protectedRequestSignatureMessage({
          formatVersion: 1,
          capabilityId: capability.capabilityId,
          requestMethod: "POST",
          canonicalRequestTarget: target,
          requestBodyHash: bodyHash,
          requestNonce: nonce,
          requestTimestampUnixSeconds: now,
        });
        signal.throwIfAborted();
        let signature: Uint8Array;
        try {
          signature = await sign(message);
        } catch {
          throw new RazielClientError("SIGNER_FAILED");
        }
        signal.throwIfAborted();
        if (!(signature instanceof Uint8Array) || signature.length !== 64)
          throw new RazielClientError("INVALID_SIGNATURE");
        return transport.request({
          signal,
          method: "POST",
          target,
          statuses: [200],
          maxResponseBytes: 1024 * 1024,
          body: JSON.stringify({
            format_version: 1,
            capability_proto_hex: encodeHex(retained),
            agent_public_key: encodeHex(publicKey),
            request_method: "POST",
            canonical_request_target: target,
            request_body_base64: Buffer.from(body).toString("base64"),
            request_body_hash: encodeHex(bodyHash),
            request_nonce: encodeHex(nonce),
            request_timestamp_unix_seconds: now.toString(),
            agent_request_signature: encodeHex(signature),
          }),
          parse: (value) => parseDatasetResult(value, datasetId, capability),
        });
      });
    },
  };
}

function queryBody(query: DatasetQuery): Uint8Array {
  try {
    const { fromOccurredAt, toOccurredAt, limit } = query;
    const start = timestamp(fromOccurredAt);
    const end = timestamp(toOccurredAt);
    if (
      start > end ||
      end - start > 31 * 86_400_000 ||
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 100
    )
      throw invalid();
    return new TextEncoder().encode(JSON.stringify({ fromOccurredAt, toOccurredAt, limit }));
  } catch {
    throw invalid();
  }
}

export function timestamp(value: unknown): number {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value))
    throw invalid();
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString().replace(".000Z", "Z") !== value
  )
    throw invalid();
  return milliseconds;
}
function invalid() {
  return new RazielClientError("INVALID_REQUEST");
}
