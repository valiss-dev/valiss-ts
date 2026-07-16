/**
 * Message tokens: per-message proofs of origin, the optional fourth chain
 * level of the valiss scheme (spec §6.12).
 *
 * A user key mints a short-lived, self-signed token (`iss == sub`) that binds
 * a message to a destination (`aud`) and a payload checksum, and may embed
 * the emitter's provenance chain — the operator-signed account token and the
 * account-signed user token — so a receiver verifies it offline with only the
 * operator public key. Message tokens are proofs, never credentials:
 * possession grants nothing, and a request verifier never accepts one.
 *
 * {@link verifyMessage} walks the chain operator → account → user → message,
 * requires every level to agree on the epoch, checks each validity window at
 * the verification instant, and enforces the audience and checksum bindings
 * the caller requests. It mirrors the Go `VerifyMessage` (valiss.dev/valiss,
 * message.go) check for check and reason for reason.
 */

import { hexEncode, sha256, utf8Encode } from "./encoding.js";
import { Reason, ValissError } from "./errors.js";
import * as nkeys from "./nkeys.js";
import {
  type AccountClaims,
  type Claims,
  claimsOf,
  DEFAULT_SKEW_MS,
  decodeToken,
  encodeV1,
  epochClaim,
  expired,
  type Extensions,
  extensionsClaim,
  type IssueOptions,
  issuerOf,
  MESSAGE_TYPE,
  notYetValid,
  type OperatorClaims,
  type UserClaims,
  validity,
  verifyAccount,
  verifyOperator,
  verifyUser,
} from "./token.js";

/**
 * The validity window transports typically mint message tokens with: long
 * enough for delivery latency and clock drift, short enough to bound capture
 * exposure.
 */
export const DEFAULT_MESSAGE_TTL_MS = 30 * 1000;

/** The provenance chain of a message token: the emitter's credential tokens. */
export interface Chain {
  /** The operator-signed account token, verbatim. */
  account: string;
  /** The account-signed user token of the emitter, verbatim. */
  user: string;
}

/**
 * Verified content of a message token, together with the chain identities it
 * was checked against. A message token is a proof, not a credential.
 */
export interface MessageClaims extends Claims {
  /** The destination the token was minted for (aud); empty when unbound. */
  audience: string;
  /** Lowercase-hex SHA-256 of the payload; empty when the token carries no binding. */
  checksum: string;
  /** The trust-domain epoch the token was issued in. */
  epoch: number;
  /** The named extension claims, decoded from JSON. */
  ext: Extensions;
  /** The verified tenant identity from the chain. */
  account: AccountClaims;
  /** The verified emitter identity from the chain; its subject key signed the token. */
  user: UserClaims;
  /** The trust domain the message verified under, when an operator policy was supplied. */
  operator: OperatorClaims | undefined;
}

/**
 * Lowercase-hex SHA-256 of a payload exactly as delivered: the value a
 * message token embeds and a receiver compares against.
 */
export async function checksum(payload: Uint8Array | string): Promise<string> {
  return hexEncode(await sha256(typeof payload === "string" ? utf8Encode(payload) : payload));
}

function isHexSha256(s: string): boolean {
  return /^[0-9a-f]{64}$/.test(s);
}

/**
 * Fail a mint fast when the embedded chain is structurally broken. No trust
 * anchor is available at mint time, so the account token is only checked for
 * self-consistency; verifyMessage roots it in the operator key.
 */
async function checkChain(chain: Chain, emitterPub: string): Promise<void> {
  const issuer = await issuerOf(chain.account);
  const account = await verifyAccount(chain.account, issuer);
  const user = await verifyUser(chain.user, account.subject);
  if (user.subject !== emitterPub) {
    throw new ValissError("valiss: chain user token is not for the minting user key");
  }
}

/** Options for {@link issueMessage}. */
export interface IssueMessageOptions extends Omit<IssueOptions, "name"> {
  /** Destination binding (the `aud` claim). */
  audience?: string;
  /** Lowercase-hex SHA-256 of the payload (the `valiss.checksum` claim). */
  checksum?: string;
  /** Embedded provenance chain (the `valiss.chain` claim). */
  chain?: Chain;
}

/**
 * Mint a per-message proof of origin signed by the emitter's user key over
 * itself (`iss == sub`). `audience` binds it to a destination, `checksum`
 * (the lowercase-hex SHA-256 of the payload) to the bytes, and `chain`
 * embeds the provenance chain so a receiver verifies offline with only the
 * operator public key. Message tokens must carry an expiry (`ttlMs` or
 * `expiresAt`): they are short-lived proofs (spec §3.8).
 */
export async function issueMessage(
  user: nkeys.KeyPair,
  opts: IssueMessageOptions = {},
): Promise<string> {
  if (!nkeys.isValidPublicUserKey(user.publicKey)) {
    throw new ValissError(
      "valiss: message tokens must be signed by a user-type nkey (expected an SU... seed)",
    );
  }
  const now = opts.now ?? new Date();
  // Validate the option-carried claims first (checksum shape, extension
  // names), matching Go's order where option errors surface before the
  // expiry check.
  if (opts.checksum !== undefined && opts.checksum !== "" && !isHexSha256(opts.checksum)) {
    throw new ValissError("valiss: checksum must be the lowercase-hex SHA-256 of the payload");
  }
  const ext = extensionsClaim(opts.extensions);
  const { expires, notBefore } = validity(opts, now);
  if (expires === 0) {
    throw new ValissError("valiss: message tokens must carry an expiry (ttlMs or expiresAt)");
  }
  const body: Record<string, unknown> = { type: MESSAGE_TYPE };
  const epoch = epochClaim(opts.epoch);
  if (epoch !== 0) body["epoch"] = epoch;
  if (opts.checksum) body["checksum"] = opts.checksum;
  if (opts.chain !== undefined) {
    await checkChain(opts.chain, user.publicKey);
    const chain: Record<string, unknown> = {};
    if (opts.chain.account) chain["account"] = opts.chain.account;
    if (opts.chain.user) chain["user"] = opts.chain.user;
    body["chain"] = chain;
  }
  if (ext !== undefined) body["ext"] = ext;
  return encodeV1(user, body, {
    subject: user.publicKey,
    audience: opts.audience ?? "",
    expires,
    notBefore,
    now,
  });
}

/** Options for {@link verifyMessage}. */
export interface VerifyMessageOptions {
  /** Verification instant; for a stored message, the receipt instant. Defaults to now. */
  now?: Date;
  /** Validity-window and epoch slack; defaults to {@link DEFAULT_SKEW_MS}. */
  skewMs?: number;
  /**
   * Require the token to be bound to exactly this destination; a token bound
   * elsewhere, or to nothing, is rejected.
   */
  audience?: string;
  /** Insist a checksum is present without comparing bytes. */
  requireChecksum?: boolean;
  /** Require the token's checksum to match these payload bytes as received. */
  payload?: Uint8Array | string;
  /**
   * Provenance chain supplied out of band for a token minted without one; a
   * token that embeds a chain must embed this exact chain.
   */
  chain?: Chain;
  /**
   * The operator's self-signed token, enforcing trust-domain policy (validity
   * window and epoch) on the whole chain.
   */
  operatorToken?: string;
}

/**
 * Verify a per-message proof of origin against a pinned operator public key:
 * walk the chain operator → account → user → message, require all levels to
 * agree on the epoch, check every validity window at the verification
 * instant, and enforce the bindings requested (spec §6.12).
 *
 * A verified message token proves origin only. It is not a credential.
 */
export async function verifyMessage(
  token: string,
  operatorPubKey: string,
  opts: VerifyMessageOptions = {},
): Promise<MessageClaims> {
  const d = await decodeToken(token);
  if (d.type !== MESSAGE_TYPE) {
    throw new ValissError(`valiss: not a message token (type "${d.type}")`, Reason.WRONG_TYPE);
  }
  if (d.issuer !== d.subject) {
    throw new ValissError(
      "valiss: message token not self-signed by its user key",
      Reason.WRONG_ISSUER,
    );
  }
  if (!nkeys.isValidPublicUserKey(d.subject)) {
    throw new ValissError(
      "valiss: message token subject is not a user public key",
      Reason.WRONG_SUBJECT_ROLE,
    );
  }

  // Resolve the chain: embedded, supplied out of band, or both (which must
  // match exactly, field for field).
  const embedded = d.chain;
  const supplied = opts.chain;
  let chainAccount: string;
  let chainUser: string;
  if (embedded === undefined && supplied === undefined) {
    throw new ValissError(
      "valiss: message token carries no chain and none was supplied",
      Reason.NO_CHAIN,
    );
  }
  if (embedded === undefined) {
    chainAccount = supplied!.account;
    chainUser = supplied!.user;
  } else {
    const embeddedAccount = typeof embedded["account"] === "string" ? embedded["account"] : "";
    const embeddedUser = typeof embedded["user"] === "string" ? embedded["user"] : "";
    if (
      supplied !== undefined &&
      (supplied.account !== embeddedAccount || supplied.user !== embeddedUser)
    ) {
      throw new ValissError(
        "valiss: message token embeds a chain that differs from the supplied chain",
        Reason.CHAIN_MISMATCH,
      );
    }
    chainAccount = embeddedAccount;
    chainUser = embeddedUser;
  }

  const at = opts.now ?? new Date();
  const skewMs = opts.skewMs ?? DEFAULT_SKEW_MS;

  // Anchor: verify the chain's account token against the pinned operator key,
  // then the emitter's user token against the account. verifyAccount and
  // verifyUser raise the same reason codes they would at top level. Operator
  // enforcement keys on the presence of the option, matching Go.
  const account = await verifyAccount(chainAccount, operatorPubKey);
  const operator =
    opts.operatorToken !== undefined
      ? await verifyOperator(opts.operatorToken, operatorPubKey)
      : undefined;

  const user = await verifyUser(chainUser, account.subject);
  if (user.subject !== d.issuer) {
    throw new ValissError(
      "valiss: message token not signed by the chain's user key",
      Reason.CHAIN_USER_MISMATCH,
    );
  }

  if (operator !== undefined) {
    if (expired(operator, at, skewMs)) {
      throw new ValissError(
        "valiss: operator token expired: the trust domain is closed",
        Reason.EXPIRED,
      );
    }
    if (notYetValid(operator, at, skewMs)) {
      throw new ValissError("valiss: operator token not yet valid", Reason.NOT_YET_VALID);
    }
    if (d.epoch !== operator.epoch) {
      throw new ValissError(
        `valiss: message token epoch ${d.epoch}, trust domain epoch ${operator.epoch}`,
        Reason.EPOCH_MISMATCH,
      );
    }
  }
  if (d.epoch !== account.epoch) {
    throw new ValissError(
      `valiss: message token epoch ${d.epoch}, account token epoch ${account.epoch}`,
      Reason.EPOCH_MISMATCH,
    );
  }
  if (d.epoch !== user.epoch) {
    throw new ValissError(
      `valiss: message token epoch ${d.epoch}, user token epoch ${user.epoch}`,
      Reason.EPOCH_MISMATCH,
    );
  }

  const claims: MessageClaims = {
    ...claimsOf(d),
    audience: d.audience,
    checksum: d.checksum,
    epoch: d.epoch,
    ext: d.ext,
    account,
    user,
    operator,
  };

  if (expired(account, at, skewMs)) {
    throw new ValissError("valiss: account token expired", Reason.EXPIRED);
  }
  if (notYetValid(account, at, skewMs)) {
    throw new ValissError("valiss: account token not yet valid", Reason.NOT_YET_VALID);
  }
  if (expired(user, at, skewMs)) {
    throw new ValissError("valiss: user token expired", Reason.EXPIRED);
  }
  if (notYetValid(user, at, skewMs)) {
    throw new ValissError("valiss: user token not yet valid", Reason.NOT_YET_VALID);
  }
  if (expired(claims, at, skewMs)) {
    throw new ValissError("valiss: message token expired", Reason.EXPIRED);
  }
  if (notYetValid(claims, at, skewMs)) {
    throw new ValissError("valiss: message token not yet valid", Reason.NOT_YET_VALID);
  }

  // An empty expected audience is a no-op, matching Go's `audience != ""` guard.
  if (opts.audience !== undefined && opts.audience !== "" && claims.audience !== opts.audience) {
    throw new ValissError(
      `valiss: message token audience "${claims.audience}", expected "${opts.audience}"`,
      Reason.WRONG_AUDIENCE,
    );
  }

  if (opts.payload !== undefined) {
    if (claims.checksum === "") {
      throw new ValissError("valiss: message token carries no checksum", Reason.CHECKSUM_MISSING);
    }
    if (claims.checksum !== (await checksum(opts.payload))) {
      throw new ValissError("valiss: payload checksum mismatch", Reason.CHECKSUM_MISMATCH);
    }
  } else if (opts.requireChecksum && claims.checksum === "") {
    throw new ValissError("valiss: message token carries no checksum", Reason.CHECKSUM_MISSING);
  }

  return claims;
}
