/**
 * valiss: offline-verifiable delegated tenant authentication (wire spec 1).
 *
 * This entry point exposes the core wire layer: nkeys, token mint/verify,
 * credentials files, request signatures, and message-token verification.
 * Transport and framework adapters will ship as subpath exports (for example
 * `valiss/express`, `valiss/fetch`) without touching this surface.
 */

export { Reason, ValissError } from "./errors.js";

export * as nkeys from "./nkeys.js";

export {
  type AccountClaims,
  type Claims,
  DEFAULT_SKEW_MS,
  decode,
  expired,
  type Extensions,
  type IssueOptions,
  type IssueUserOptions,
  issueAccount,
  issueOperator,
  issuerOf,
  issueUser,
  notYetValid,
  type OperatorClaims,
  type UserClaims,
  verifyAccount,
  verifyOperator,
  verifyUser,
} from "./token.js";

export { newNonce, signRequest, verifySignature } from "./sign.js";

export { type Creds, formatCreds, parseCreds, signerOf } from "./creds.js";

export {
  type Chain,
  checksum,
  DEFAULT_MESSAGE_TTL_MS,
  type IssueMessageOptions,
  issueMessage,
  type MessageClaims,
  verifyMessage,
  type VerifyMessageOptions,
} from "./message.js";
