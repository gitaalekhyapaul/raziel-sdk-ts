// Explicit exports keep owner RPCs and internal diagnostic DTOs out of the public API.
export {
  type AccessIntent,
  AccessIntentSchema,
  type AccessPolicyBinding,
  AccessPolicyBindingSchema,
  type AccessRequest,
  AccessRequestSchema,
  type AccessRequestMutation,
  AccessRequestMutationSchema,
  AccessRequestState,
  AccessRequestStateSchema,
  type IssuanceProposal,
  IssuanceProposalSchema,
  type ListAccessRequestsResponse,
  ListAccessRequestsResponseSchema,
  type ListAccessRequestsResponse as AccessRequestList,
} from "./gen/raziel/v1/agent_api_pb.js";
export {
  type AuthorizationContextEntry as AccessRequestContextEntry,
  AuthorizationContextEntrySchema as AccessRequestContextEntrySchema,
  type ProofCapability,
  ProofCapabilitySchema,
  ProofJobState,
  type ProofMetrics,
  ProofMetricsSchema,
} from "./gen/raziel/v1/capability_pb.js";
