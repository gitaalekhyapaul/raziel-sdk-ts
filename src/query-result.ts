import { Buffer } from "node:buffer";
import { encodeHex } from "./canonical.js";
import { timestamp } from "./dataset-query.js";
import type { ProofCapability } from "./public.js";
import { exactKeys, RazielClientError, record } from "./transport.js";

export function parseDatasetResult(value: unknown, datasetId: string, capability: ProofCapability) {
  try {
    if (
      !record(value) ||
      !exactKeys(value, [
        "classification",
        "dataset_id",
        "verification_path",
        "row_count",
        "rows",
        "receipt",
      ]) ||
      value.classification !== "SYNTHETIC" ||
      value.dataset_id !== datasetId ||
      (value.verification_path !== "VERIFIER" && value.verification_path !== "CACHE") ||
      !Array.isArray(value.rows) ||
      value.rows.length > 100 ||
      value.row_count !== value.rows.length
    )
      throw invalid();
    return {
      classification: "SYNTHETIC" as const,
      dataset_id: datasetId,
      verification_path: value.verification_path,
      row_count: value.rows.length,
      rows: value.rows.map(transaction),
      receipt: receipt(value.receipt, capability),
    };
  } catch {
    throw invalid();
  }
}

function receipt(value: unknown, capability: ProofCapability) {
  const fields = [
    "format_version",
    "receipt_id",
    "receipt_type",
    "request_id",
    "occurred_at",
    "task_id",
    "capability_id",
    "proof_job_id",
    "policy_record_id",
    "policy_hash",
    "snapshot_id",
    "relationship_snapshot_root",
    "public_claims_digest",
    "proof_digest",
    "action",
    "resource_type",
    "resource_scope",
    "outcome",
    "reason_code",
  ];
  if (
    !record(value) ||
    !exactKeys(value, fields) ||
    value.format_version !== 1 ||
    value.receipt_type !== "AUDIT_RECEIPT_TYPE_PROTECTED_REQUEST" ||
    value.capability_id !== capability.capabilityId ||
    value.proof_job_id !== capability.capabilityId ||
    value.task_id !== capability.taskId ||
    value.policy_hash !== encodeHex(capability.policyHash) ||
    value.snapshot_id !== capability.snapshotId ||
    value.relationship_snapshot_root !== encodeHex(capability.relationshipSnapshotRoot) ||
    value.action !== "query" ||
    value.resource_type !== capability.resourceType ||
    value.resource_scope !== capability.resourceScope ||
    value.outcome !== "AUDIT_OUTCOME_ACCEPTED" ||
    value.reason_code !== "PUBLIC_ERROR_CODE_UNSPECIFIED"
  )
    throw invalid();
  return {
    format_version: 1 as const,
    receipt_type: "AUDIT_RECEIPT_TYPE_PROTECTED_REQUEST" as const,
    receipt_id: safeId(value.receipt_id),
    request_id: safeId(value.request_id),
    occurred_at: utc(value.occurred_at),
    task_id: capability.taskId,
    capability_id: capability.capabilityId,
    proof_job_id: capability.capabilityId,
    policy_record_id: safeId(value.policy_record_id),
    policy_hash: digest(value.policy_hash),
    snapshot_id: capability.snapshotId,
    relationship_snapshot_root: digest(value.relationship_snapshot_root),
    public_claims_digest: digest(value.public_claims_digest),
    proof_digest: digest(value.proof_digest),
    action: "query" as const,
    resource_type: capability.resourceType,
    resource_scope: capability.resourceScope,
    outcome: "AUDIT_OUTCOME_ACCEPTED" as const,
    reason_code: "PUBLIC_ERROR_CODE_UNSPECIFIED" as const,
  };
}

function transaction(value: unknown) {
  const fields = [
    "transactionId",
    "occurredAt",
    "amountMinor",
    "currency",
    "merchantReference",
    "accountReference",
    "transactionType",
    "reconciliationStatus",
    "sourceRecordDigest",
  ];
  if (
    !record(value) ||
    Object.keys(value).some((key) => !fields.includes(key)) ||
    (value.reconciliationStatus !== "UNMATCHED" &&
      value.reconciliationStatus !== "MATCHED" &&
      value.reconciliationStatus !== "REVIEW")
  )
    throw invalid();
  return {
    transactionId: text(value.transactionId, 128),
    occurredAt: utc(value.occurredAt),
    amountMinor: text(value.amountMinor, 32),
    currency: text(value.currency, 3),
    ...optional(value, "merchantReference"),
    ...optional(value, "accountReference"),
    ...optional(value, "transactionType"),
    reconciliationStatus: value.reconciliationStatus,
    sourceRecordDigest: digest(value.sourceRecordDigest),
  };
}
function text(value: unknown, max: number): string {
  if (typeof value !== "string" || !value.length || Buffer.byteLength(value) > max) throw invalid();
  return value;
}
function optional<K extends string>(
  value: Record<string, unknown>,
  key: K,
): Partial<Record<K, string>> {
  return value[key] === undefined ? {} : ({ [key]: text(value[key], 128) } as Record<K, string>);
}
function safeId(value: unknown): string {
  const result = text(value, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(result)) throw invalid();
  return result;
}
function digest(value: unknown): string {
  const result = text(value, 64);
  if (!/^[0-9a-f]{64}$/.test(result)) throw invalid();
  return result;
}
function utc(value: unknown): string {
  const result = text(value, 20);
  timestamp(result);
  return result;
}
function invalid() {
  return new RazielClientError("INVALID_RESPONSE", 200);
}
