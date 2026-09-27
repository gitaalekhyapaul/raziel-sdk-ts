import { create, toJson } from "@bufbuild/protobuf";

import { encodeIntent, validateRequest } from "./access-requests.js";
import { randomDigest } from "./agent.js";
import { capabilityRequestCommitment, encodeHex, normalizeContext, sha256 } from "./canonical.js";
import {
  type AccessIntent,
  type AccessIssuanceSubmission,
  AccessIssuanceSubmissionSchema,
  type AccessRequest,
  AccessRequestState,
} from "./gen/raziel/v1/agent_api_pb.js";
import { parseProtoJson } from "./protojson.js";
import { copyAgentPublicKey } from "./signer.js";
import { RazielClientError, type RequestOptions, withTimeout } from "./transport.js";
import type { AgentSigner, AuthorizationContextEntry } from "./types.js";

export interface SignIssuanceOptions extends RequestOptions {
  readonly issuanceNonce?: Uint8Array;
}

/** Signs only. The caller persists the returned attempt before explicitly submitting it. */
export function issuanceMethods(signer: AgentSigner, timeoutMs = 10_000) {
  const publicKey = copyAgentPublicKey(signer.publicKey);
  const sign = signer.sign.bind(signer);
  return {
    async signIssuance(
      intent: AccessIntent,
      request: AccessRequest,
      options: SignIssuanceOptions = {},
    ): Promise<AccessIssuanceSubmission> {
      return withTimeout(timeoutMs, options.signal, async (signal) => {
        signal.throwIfAborted();
        // Snapshot caller-owned values before awaiting a hardware or remote signer.
        encodeIntent(intent);
        const original = structuredClone(intent);
        const current = structuredClone(request);
        const { proposal, binding } = validateProposal(original, current, publicKey);
        const context = normalizeContext(original.requestContext.map(contextValue));
        const providedNonce = options.issuanceNonce;
        if (providedNonce !== undefined && !(providedNonce instanceof Uint8Array)) throw invalid();
        const nonce = providedNonce === undefined ? randomDigest() : new Uint8Array(providedNonce);
        if (!(nonce instanceof Uint8Array) || nonce.length !== 32) throw invalid();
        const commitment = await capabilityRequestCommitment({
          formatVersion: 1,
          agentKeyThumbprint: await sha256(publicKey),
          taskId: original.taskId,
          purpose: original.purpose,
          action: original.action,
          resourceType: binding.resourceType,
          resourceScope: binding.resourceScope,
          requestedExpiresAtUnixSeconds: proposal.requestedExpiresAtUnixSeconds,
          issuanceNonce: nonce,
          snapshotId: proposal.snapshotId,
          requestContext: context,
        });
        signal.throwIfAborted();
        let signature: Uint8Array;
        try {
          signature = await sign(commitment);
        } catch {
          throw new RazielClientError("SIGNER_FAILED");
        }
        signal.throwIfAborted();
        if (!(signature instanceof Uint8Array) || signature.length !== 64)
          throw new RazielClientError("INVALID_SIGNATURE");
        validateProposal(original, current, publicKey);
        return create(AccessIssuanceSubmissionSchema, {
          formatVersion: 1,
          proposalId: proposal.proposalId,
          generation: proposal.generation,
          request: {
            formatVersion: 1,
            agentId: current.agentId,
            agentPublicKey: publicKey.slice(),
            taskId: original.taskId,
            purpose: original.purpose,
            action: original.action,
            resourceType: binding.resourceType,
            resourceScope: binding.resourceScope,
            requestedExpiresAt: { seconds: proposal.requestedExpiresAtUnixSeconds, nanos: 0 },
            issuanceNonce: nonce,
            snapshotId: proposal.snapshotId,
            requestSignature: new Uint8Array(signature),
            requestContext: [...original.requestContext].sort((a, b) =>
              a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
            ),
          },
        });
      });
    },
  };
}

export function encodeIssuance(value: AccessIssuanceSubmission, publicKey: Uint8Array) {
  try {
    const request = value.request;
    if (
      value.formatVersion !== 1 ||
      !/^[0-9a-f]{32}$/.test(value.proposalId) ||
      value.generation < 1n ||
      !request ||
      request.formatVersion !== 1 ||
      !same(request.agentPublicKey, publicKey) ||
      request.issuanceNonce.length !== 32 ||
      request.requestSignature.length !== 64 ||
      !request.requestedExpiresAt ||
      request.requestedExpiresAt.nanos !== 0
    )
      throw invalid();
    // No deadline check here: an accepted exact retry remains valid after signing expiry.
    return parseProtoJson(
      AccessIssuanceSubmissionSchema,
      toJson(AccessIssuanceSubmissionSchema, value),
    );
  } catch {
    throw invalid();
  }
}

function validateProposal(intent: AccessIntent, current: AccessRequest, publicKey: Uint8Array) {
  try {
    validateRequest(current);
    const proposal = current.proposal;
    const binding = current.policyBinding;
    const proposed = proposal?.policyBinding;
    const now = BigInt(Math.floor(Date.now() / 1000));
    if (
      current.formatVersion !== 1 ||
      current.state !== AccessRequestState.AWAITING_SIGNATURE ||
      current.requestId !== intent.requestId ||
      current.datasetId !== intent.datasetId ||
      current.datasetRevision !== intent.datasetRevision ||
      current.taskId !== intent.taskId ||
      current.purpose !== intent.purpose ||
      current.action !== intent.action ||
      !/^[0-9a-f]{32}$/.test(current.agentId) ||
      !proposal ||
      proposal.formatVersion !== 1 ||
      !/^[0-9a-f]{32}$/.test(proposal.proposalId) ||
      proposal.generation !== current.generation ||
      proposal.signatureDeadlineUnixSeconds <= now ||
      proposal.requestedExpiresAtUnixSeconds <= now ||
      proposal.requestedExpiresAtUnixSeconds > current.deadlineUnixSeconds ||
      !same(proposal.agentPublicKey, publicKey) ||
      proposal.taskId !== intent.taskId ||
      proposal.purpose !== intent.purpose ||
      proposal.action !== intent.action ||
      !binding ||
      !proposed ||
      !binding.policyRecordId ||
      binding.policyHash.length !== 32 ||
      proposed.policyRecordId !== binding.policyRecordId ||
      !same(proposed.policyHash, binding.policyHash) ||
      proposed.resourceType !== binding.resourceType ||
      proposed.resourceScope !== binding.resourceScope ||
      !/^dataset_[0-9a-f]{32}$/.test(binding.resourceType) ||
      binding.resourceScope !== intent.datasetId ||
      !/^snapshot-v1:[0-9a-f]{64}$/.test(proposal.snapshotId) ||
      proposal.snapshotRoot.length !== 32 ||
      proposal.snapshotId !== `snapshot-v1:${encodeHex(proposal.snapshotRoot)}`
    )
      throw invalid();
    return { proposal, binding };
  } catch {
    throw invalid();
  }
}

function contextValue(entry: AccessIntent["requestContext"][number]): AuthorizationContextEntry {
  switch (entry.value.case) {
    case "boolValue":
      return { name: entry.name, value: { kind: "bool", value: entry.value.value } };
    case "intValue":
      return { name: entry.name, value: { kind: "int", value: entry.value.value } };
    case "stringValue":
      return { name: entry.name, value: { kind: "string", value: entry.value.value } };
    default:
      throw invalid();
  }
}
function same(a: Uint8Array, b: Uint8Array) {
  return (
    a instanceof Uint8Array && a.length === b.length && a.every((byte, index) => byte === b[index])
  );
}
function invalid() {
  return new RazielClientError("INVALID_REQUEST");
}
