/**
 * Core of the valiss tenant authentication scheme: minting and verifying
 * nkey-signed JWTs (`ed25519-nkey` algorithm) per wire spec 1.
 *
 * The scheme is a three-level chain of Ed25519 nkeys plus an optional
 * per-message level:
 *
 * - An operator holds an nkey; its public key is the trust anchor servers pin.
 * - The operator signs each tenant an account token bound to the tenant's own
 *   account nkey. Issued account tokens go in a server-side allowlist.
 * - A tenant delegates by signing user tokens with its account seed. A bearer
 *   user token authenticates by the token alone, without per-request
 *   signatures.
 * - A user key may additionally mint per-message proof tokens (see message.ts).
 *
 * Tokens carry an explicit wire-format version in the header. A verifier
 * reads the version before parsing the payload and dispatches to the matching
 * per-version decoder, so a future spec version can coexist with this one; an
 * unrecognized version is rejected cleanly rather than mis-parsed. The
 * signature is always verified by the selected decoder — version dispatch
 * never skips it (spec §8, ADR 0009).
 */

import {
  base32Encode,
  base64UrlDecode,
  base64UrlEncode,
  sha256,
  utf8Decode,
  utf8Encode,
} from "./encoding.js";
import { Reason, ValissError } from "./errors.js";
import * as nkeys from "./nkeys.js";

/** Default bound on request-timestamp drift and token-expiry slack: 2 minutes. */
export const DEFAULT_SKEW_MS = 2 * 60 * 1000;

// The current wire-format version. It appears on the wire only as an integer:
// the `ver` header field on tokens, the `VALISS-CREDS-VERSION` line on creds
// files, and the `valiss-req-v1` prefix on request signatures. Adding a
// version is additive — a new per-version decoder plus one dispatch case — so
// the version never leaks into the public function or type names.
const WIRE_VERSION = 1;

// Frozen, byte-exact version-1 token header (spec §2.2). Producers emit it
// verbatim; it must stay in sync with WIRE_VERSION.
const TOKEN_HEADER_V1 = '{"typ":"JWT","alg":"ed25519-nkey","ver":1}';
const TOKEN_HEADER_V1_B64 = base64UrlEncode(utf8Encode(TOKEN_HEADER_V1));

/** @internal `valiss.type` discriminator values (spec §3.3). */
export const OPERATOR_TYPE = "operator";
/** @internal */
export const ACCOUNT_TYPE = "account";
/** @internal */
export const USER_TYPE = "user";
/** @internal */
export const MESSAGE_TYPE = "message";

/** Named extension claims of a token: opaque JSON values keyed by name. */
export type Extensions = Record<string, unknown>;

const GO_JSON_ESCAPES = new Map<string, string>([
  ["\u003c", "\\u003c"],
  ["\u003e", "\\u003e"],
  ["\u0026", "\\u0026"],
  ["\u2028", "\\u2028"],
  ["\u2029", "\\u2029"],
]);

/**
 * @internal Serialize like Go's `encoding/json`: no insignificant whitespace
 * and HTML-escaping of `<`, `>`, `&` plus U+2028/U+2029. Reproducing this
 * byte-for-byte is what keeps the content-derived `jti` identical across
 * implementations (spec §3.2). JSON.stringify never emits those characters
 * outside string values and never as part of an escape sequence, so
 * post-serialization replacement is unambiguous.
 */
export function goJsonBytes(value: unknown): Uint8Array {
  const s = JSON.stringify(value).replace(
    /[\u003c\u003e\u0026\u2028\u2029]/g,
    (c) => GO_JSON_ESCAPES.get(c)!,
  );
  return utf8Encode(s);
}

/**
 * @internal Recursively sort plain-object keys, matching Go's map marshaling
 * (`encoding/json` emits map keys in sorted order at every depth). Applied to
 * extension payloads so identical claims serialize identically on both sides.
 */
export function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto === Object.prototype || proto === null) {
      const src = value as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(src).sort()) out[key] = sortKeysDeep(src[key]);
      return out;
    }
  }
  return value;
}

/** Verified RFC 7519 registered-claims content of a token. */
export interface Claims {
  /** The token's unique identifier (jti), the allowlist key for account tokens. */
  id: string;
  /** The public key that signed the token (iss). */
  issuer: string;
  /** The subject's nkey public key (sub) that must sign requests. */
  subject: string;
  /** The token mint time (iat); undefined when absent. */
  issuedAt: Date | undefined;
  /** The token expiry (exp); undefined means the token never expires. */
  expiresAt: Date | undefined;
  /** The token activation time (nbf); undefined means immediately valid. */
  notBefore: Date | undefined;
}

/** Verified content of a self-signed operator token. */
export interface OperatorClaims extends Claims {
  /** The trust domain's label; falls back to the subject key when unnamed. */
  name: string;
  /** The trust domain's current epoch. */
  epoch: number;
  /** The named extension claims, decoded from JSON. */
  ext: Extensions;
}

/** Verified content of an account (tenant) token. */
export interface AccountClaims extends Claims {
  /** The tenant's label; falls back to the subject key when unnamed. */
  name: string;
  /** The trust-domain epoch the token was issued in. */
  epoch: number;
  /** The named extension claims, decoded from JSON. */
  ext: Extensions;
}

/** Verified content of a user token. */
export interface UserClaims extends Claims {
  /** The user's label; falls back to the subject key when unnamed. */
  name: string;
  /** The trust-domain epoch the token was issued in. */
  epoch: number;
  /** Marks a token whose holder authenticates by the token alone. */
  bearer: boolean;
  /** The named extension claims, decoded from JSON. */
  ext: Extensions;
}

/**
 * Whether a claims set has passed its expiry, with skew slack (spec §6.10):
 * expired iff `exp` is present and `now > exp + skew`.
 */
export function expired(
  claims: Pick<Claims, "expiresAt">,
  now: Date,
  skewMs: number = DEFAULT_SKEW_MS,
): boolean {
  return claims.expiresAt !== undefined && now.getTime() - skewMs > claims.expiresAt.getTime();
}

/**
 * Whether a claims set's not-before still lies in the future, with skew slack
 * (spec §6.10): not yet valid iff `nbf` is present and `now + skew < nbf`.
 */
export function notYetValid(
  claims: Pick<Claims, "notBefore">,
  now: Date,
  skewMs: number = DEFAULT_SKEW_MS,
): boolean {
  return claims.notBefore !== undefined && now.getTime() + skewMs < claims.notBefore.getTime();
}

/** Options shared by the token issuers. */
export interface IssueOptions {
  /** Human-readable subject label (the `name` claim). */
  name?: string;
  /** Expire the token this many milliseconds after mint time; exclusive with `expiresAt`. */
  ttlMs?: number;
  /** Absolute expiry (the `exp` claim); exclusive with `ttlMs`. */
  expiresAt?: Date;
  /** Activation time (the `nbf` claim). */
  notBefore?: Date;
  /** Trust-domain epoch (the `valiss.epoch` claim); 0 (the default) is omitted. */
  epoch?: number;
  /** Named extension claims, carried opaquely (the `valiss.ext` claim). */
  extensions?: Extensions;
  /** Mint instant override; defaults to the current time. */
  now?: Date;
}

/** Options for {@link issueUser}. */
export interface IssueUserOptions extends IssueOptions {
  /** Mark the token as bearer: the server accepts it without per-request signatures. */
  bearer?: boolean;
}

/** @internal Build the `ext` claim: validated names, Go map-marshaling key order. */
export function extensionsClaim(extensions: Extensions | undefined): Extensions | undefined {
  if (extensions === undefined) return undefined;
  const names = Object.keys(extensions);
  if (names.length === 0) return undefined;
  const out: Extensions = {};
  for (const name of names.sort()) {
    if (name === "") throw new ValissError("valiss: extension name must not be empty");
    out[name] = sortKeysDeep(extensions[name]);
  }
  return out;
}

/** @internal Resolve ttl/expiry/notBefore options into Unix-second claims. */
export function validity(
  opts: Pick<IssueOptions, "ttlMs" | "expiresAt" | "notBefore">,
  now: Date,
): { expires: number; notBefore: number } {
  if (opts.ttlMs !== undefined && opts.expiresAt !== undefined) {
    throw new ValissError("valiss: ttlMs and expiresAt are mutually exclusive");
  }
  let expires = 0;
  if (opts.ttlMs !== undefined) {
    if (opts.ttlMs <= 0) throw new ValissError("valiss: ttlMs must be positive");
    expires = Math.floor((now.getTime() + opts.ttlMs) / 1000);
  } else if (opts.expiresAt !== undefined) {
    expires = Math.floor(opts.expiresAt.getTime() / 1000);
  }
  const notBefore =
    opts.notBefore !== undefined ? Math.floor(opts.notBefore.getTime() / 1000) : 0;
  return { expires, notBefore };
}

/** @internal Validate the epoch mint option; 0 (the default) is omitted on the wire. */
export function epochClaim(epoch: number | undefined): number {
  if (epoch === undefined) return 0;
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new ValissError("valiss: epoch must be a non-negative safe integer");
  }
  return epoch;
}

/** @internal Fields of encodeV1 beyond the level body. */
export interface EncodeFields {
  name?: string;
  subject?: string;
  audience?: string;
  expires: number;
  notBefore: number;
  now: Date;
}

/**
 * @internal Encode and sign a version-1 token. Field order matches the wire
 * struct (jti, iat, iss, name, sub, aud, exp, nbf, valiss) with empty fields
 * omitted, keeping the jti derivation identical across implementations:
 * unpadded base32 of the SHA-256 of the claims JSON with jti absent (§3.5).
 */
export async function encodeV1(
  issuer: nkeys.KeyPair,
  body: Record<string, unknown>,
  fields: EncodeFields,
): Promise<string> {
  const claims: Record<string, unknown> = {};
  const iat = Math.floor(fields.now.getTime() / 1000);
  if (iat !== 0) claims["iat"] = iat;
  claims["iss"] = issuer.publicKey;
  if (fields.name) claims["name"] = fields.name;
  if (fields.subject) claims["sub"] = fields.subject;
  if (fields.audience) claims["aud"] = fields.audience;
  if (fields.expires !== 0) claims["exp"] = fields.expires;
  if (fields.notBefore !== 0) claims["nbf"] = fields.notBefore;
  claims["valiss"] = body;
  const jti = base32Encode(await sha256(goJsonBytes(claims)));
  const payload = { jti, ...claims };
  const signingInput = `${TOKEN_HEADER_V1_B64}.${base64UrlEncode(goJsonBytes(payload))}`;
  const signature = await issuer.sign(utf8Encode(signingInput));
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

/**
 * Mint the self-signed operator token: the trust domain's policy statement
 * (epoch, validity window, extensions), signed by the operator key over its
 * own public key.
 */
export async function issueOperator(
  operator: nkeys.KeyPair,
  opts: IssueOptions = {},
): Promise<string> {
  if (!nkeys.isValidPublicOperatorKey(operator.publicKey)) {
    throw new ValissError(
      "valiss: operator tokens must be signed by an operator-type nkey (expected an SO... seed)",
    );
  }
  const now = opts.now ?? new Date();
  const { expires, notBefore } = validity(opts, now);
  const body: Record<string, unknown> = { type: OPERATOR_TYPE };
  const epoch = epochClaim(opts.epoch);
  if (epoch !== 0) body["epoch"] = epoch;
  const ext = extensionsClaim(opts.extensions);
  if (ext !== undefined) body["ext"] = ext;
  return encodeV1(operator, body, {
    name: opts.name ?? "",
    subject: operator.publicKey,
    expires,
    notBefore,
    now,
  });
}

/**
 * Mint an account token signed by the operator key. The token subject is the
 * tenant's account public key and `name` carries the tenant id; the tenant
 * signs requests with the seed matching the subject key.
 */
export async function issueAccount(
  operator: nkeys.KeyPair,
  name: string,
  accountPubKey: string,
  opts: Omit<IssueOptions, "name"> = {},
): Promise<string> {
  if (!nkeys.isValidPublicOperatorKey(operator.publicKey)) {
    throw new ValissError(
      "valiss: account tokens must be signed by an operator-type nkey (expected an SO... seed)",
    );
  }
  if (!nkeys.isValidPublicAccountKey(accountPubKey)) {
    throw new ValissError("valiss: invalid tenant public key (expected an A... nkey)");
  }
  const now = opts.now ?? new Date();
  const { expires, notBefore } = validity(opts, now);
  const body: Record<string, unknown> = { type: ACCOUNT_TYPE };
  const epoch = epochClaim(opts.epoch);
  if (epoch !== 0) body["epoch"] = epoch;
  const ext = extensionsClaim(opts.extensions);
  if (ext !== undefined) body["ext"] = ext;
  return encodeV1(operator, body, { name, subject: accountPubKey, expires, notBefore, now });
}

/**
 * Mint a user token signed by a tenant's account key, delegating to an end
 * user. The token subject is the user's public key and `name` carries the
 * user id.
 *
 * `bearer: true` produces a token the server accepts without per-request
 * signatures. Bearer tokens are replayable until they expire or their account
 * leaves the allowlist, so pair them with TLS and a short ttl.
 */
export async function issueUser(
  account: nkeys.KeyPair,
  name: string,
  userPubKey: string,
  opts: Omit<IssueUserOptions, "name"> = {},
): Promise<string> {
  if (!nkeys.isValidPublicAccountKey(account.publicKey)) {
    throw new ValissError(
      "valiss: user tokens must be signed by an account-type nkey (expected an SA... seed)",
    );
  }
  if (!nkeys.isValidPublicUserKey(userPubKey)) {
    throw new ValissError("valiss: invalid user public key (expected a U... nkey)");
  }
  const now = opts.now ?? new Date();
  const { expires, notBefore } = validity(opts, now);
  const body: Record<string, unknown> = { type: USER_TYPE };
  const epoch = epochClaim(opts.epoch);
  if (epoch !== 0) body["epoch"] = epoch;
  if (opts.bearer) body["bearer"] = true;
  const ext = extensionsClaim(opts.extensions);
  if (ext !== undefined) body["ext"] = ext;
  return encodeV1(account, body, { name, subject: userPubKey, expires, notBefore, now });
}

/**
 * @internal Version-neutral view of a parsed, signature-verified token.
 * Per-version decoders normalize their wire layout into it, so the public
 * verify paths never depend on a wire version. Body fields are the union
 * across levels; a level leaves the ones it does not use at their zero value.
 */
export interface Decoded {
  id: string;
  issuer: string;
  subject: string;
  name: string;
  audience: string;
  issuedAt: number;
  expires: number;
  notBefore: number;
  type: string;
  epoch: number;
  bearer: boolean;
  checksum: string;
  chain: Record<string, unknown> | undefined;
  ext: Extensions;
}

// Go decodes iat/exp/nbf as int64 and epoch as uint64; a value outside the
// type range (or a non-integer JSON number) fails the unmarshal. Timestamps
// are additionally bounded to the RFC 3339 year range so downstream Date
// arithmetic stays exact. Epoch is bounded to Number.MAX_SAFE_INTEGER: JSON
// numbers above 2^53 do not round-trip through a JS number, so a larger epoch
// (legal uint64 in Go) is rejected as malformed rather than silently mangled.
const TS_MIN = -62135596800; // 0001-01-01T00:00:00Z
const TS_MAX = 253402300799; // 9999-12-31T23:59:59Z

function wireStr(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (v === undefined || v === null) return "";
  if (typeof v !== "string") {
    throw new ValissError(`valiss: token claims: ${key} is not a string`, Reason.MALFORMED);
  }
  return v;
}

function wireInt(obj: Record<string, unknown>, key: string, lo: number, hi: number): number {
  const v = obj[key];
  if (v === undefined || v === null) return 0;
  if (typeof v !== "number" || !Number.isInteger(v) || v < lo || v > hi) {
    throw new ValissError(
      `valiss: token claims: ${key} is not a valid integer`,
      Reason.MALFORMED,
    );
  }
  return v;
}

function wireBool(obj: Record<string, unknown>, key: string): boolean {
  const v = obj[key];
  if (v === undefined || v === null) return false;
  if (typeof v !== "boolean") {
    throw new ValissError(`valiss: token claims: ${key} is not a boolean`, Reason.MALFORMED);
  }
  return v;
}

function wireObj(obj: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  const v = obj[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "object" || Array.isArray(v)) {
    throw new ValissError(`valiss: token claims: ${key} is not an object`, Reason.MALFORMED);
  }
  return v as Record<string, unknown>;
}

function decodedOf(payload: Record<string, unknown>): Decoded {
  const body = wireObj(payload, "valiss") ?? {};
  return {
    id: wireStr(payload, "jti"),
    issuer: wireStr(payload, "iss"),
    subject: wireStr(payload, "sub"),
    name: wireStr(payload, "name"),
    audience: wireStr(payload, "aud"),
    issuedAt: wireInt(payload, "iat", TS_MIN, TS_MAX),
    expires: wireInt(payload, "exp", TS_MIN, TS_MAX),
    notBefore: wireInt(payload, "nbf", TS_MIN, TS_MAX),
    type: wireStr(body, "type"),
    epoch: wireInt(body, "epoch", 0, Number.MAX_SAFE_INTEGER),
    bearer: wireBool(body, "bearer"),
    checksum: wireStr(body, "checksum"),
    chain: wireObj(body, "chain"),
    ext: wireObj(body, "ext") ?? {},
  };
}

function parseJsonObject(part: string, what: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(base64UrlDecode(part)));
  } catch {
    throw new ValissError(`valiss: ${what}: malformed`, Reason.MALFORMED);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ValissError(`valiss: ${what}: not an object`, Reason.MALFORMED);
  }
  return parsed as Record<string, unknown>;
}

/**
 * @internal Read the wire-format version from a token's header without
 * decoding its payload, returning the version and the three JWS segments.
 * Version-agnostic: it checks only the envelope shape (three parts, JSON
 * header, JWT / ed25519-nkey) common to all versions, so it never changes as
 * versions are added.
 */
export function peekVersion(token: string): { ver: number; parts: [string, string, string] } {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new ValissError("valiss: malformed token", Reason.MALFORMED);
  }
  const header = parseJsonObject(parts[0]!, "token header");
  if (header["typ"] !== "JWT" || header["alg"] !== "ed25519-nkey") {
    throw new ValissError(
      `valiss: unsupported token type ${String(header["typ"])}/${String(header["alg"])}`,
      Reason.UNSUPPORTED_TYPE,
    );
  }
  const ver = header["ver"] ?? 0;
  // ver must be a JSON integer; a bool, a float, or a string fails Go's header
  // unmarshal (malformed) rather than dispatching to an unsupported version.
  if (typeof ver !== "number" || !Number.isInteger(ver)) {
    throw new ValissError("valiss: malformed token header version", Reason.MALFORMED);
  }
  return { ver, parts: parts as [string, string, string] };
}

/**
 * @internal Parse a token, verify its signature against the issuer key
 * embedded in the claims, and return a version-neutral view. Dispatches on
 * the wire version read from the header; an unrecognized version is rejected
 * without parsing the payload. Trust is NOT established here: the caller must
 * check the issuer's place in the chain.
 */
export async function decodeToken(token: string): Promise<Decoded> {
  const { ver, parts } = peekVersion(token);
  if (ver === WIRE_VERSION) return decodeV1(parts);
  throw new ValissError(`valiss: unsupported wire version ${ver}`, Reason.UNSUPPORTED_VERSION);
}

/**
 * Parse a version-1 payload, verify the signature, and normalize into
 * {@link Decoded}. Field types are validated up front (a wrong type is
 * malformed), then the issuer key is decoded and the signature verified.
 */
async function decodeV1(parts: [string, string, string]): Promise<Decoded> {
  const payload = parseJsonObject(parts[1], "token claims");
  const d = decodedOf(payload);
  let issuer: nkeys.KeyPair;
  try {
    issuer = nkeys.fromPublicKey(d.issuer);
  } catch (err) {
    throw new ValissError(
      `valiss: token issuer: ${(err as Error).message}`,
      Reason.BAD_ISSUER_KEY,
    );
  }
  let signature: Uint8Array;
  try {
    signature = base64UrlDecode(parts[2]);
  } catch {
    throw new ValissError("valiss: malformed token signature", Reason.MALFORMED);
  }
  try {
    await issuer.verify(utf8Encode(`${parts[0]}.${parts[1]}`), signature);
  } catch {
    throw new ValissError("valiss: token signature verification failed", Reason.BAD_SIGNATURE);
  }
  return d;
}

function dateOf(unixSeconds: number): Date | undefined {
  return unixSeconds === 0 ? undefined : new Date(unixSeconds * 1000);
}

/** @internal Registered-claims view of a decoded token. */
export function claimsOf(d: Decoded): Claims {
  return {
    id: d.id,
    issuer: d.issuer,
    subject: d.subject,
    issuedAt: dateOf(d.issuedAt),
    expiresAt: dateOf(d.expires),
    notBefore: dateOf(d.notBefore),
  };
}

/** @internal Fall back to the subject key when a token carries no name (§3.8). */
export function nameOf(name: string, subject: string): string {
  return name !== "" ? name : subject;
}

/**
 * Decode a self-signed operator token, check its type and that it is signed
 * by the pinned operator key over itself, and return the claims. Expiry and
 * activation checks are the caller's.
 */
export async function verifyOperator(
  token: string,
  operatorPubKey: string,
): Promise<OperatorClaims> {
  const d = await decodeToken(token);
  if (d.type !== OPERATOR_TYPE) {
    throw new ValissError(`valiss: not an operator token (type "${d.type}")`, Reason.WRONG_TYPE);
  }
  if (d.issuer !== operatorPubKey || d.subject !== operatorPubKey) {
    throw new ValissError(
      "valiss: operator token not self-signed by the expected operator",
      Reason.WRONG_ISSUER,
    );
  }
  if (!nkeys.isValidPublicOperatorKey(d.subject)) {
    throw new ValissError(
      "valiss: operator token subject is not an operator public key",
      Reason.WRONG_SUBJECT_ROLE,
    );
  }
  return { ...claimsOf(d), name: nameOf(d.name, d.subject), epoch: d.epoch, ext: d.ext };
}

/**
 * Decode an account token, check its type, signature, and issuer (the pinned
 * operator key), and return the claims. It does NOT check expiry, activation,
 * or the allowlist; those are chain-level checks of the request verifier.
 */
export async function verifyAccount(
  token: string,
  operatorPubKey: string,
): Promise<AccountClaims> {
  const d = await decodeToken(token);
  if (d.type !== ACCOUNT_TYPE) {
    throw new ValissError(`valiss: not an account token (type "${d.type}")`, Reason.WRONG_TYPE);
  }
  if (d.issuer !== operatorPubKey) {
    throw new ValissError(
      "valiss: account token not signed by the expected issuer",
      Reason.WRONG_ISSUER,
    );
  }
  if (!nkeys.isValidPublicAccountKey(d.subject)) {
    throw new ValissError(
      "valiss: account token subject is not an account public key",
      Reason.WRONG_SUBJECT_ROLE,
    );
  }
  return { ...claimsOf(d), name: nameOf(d.name, d.subject), epoch: d.epoch, ext: d.ext };
}

/**
 * Decode a user token, check its type, signature, and issuer (the account
 * public key that delegated it), and return the claims. Expiry and activation
 * checks are the caller's.
 */
export async function verifyUser(token: string, accountPubKey: string): Promise<UserClaims> {
  const d = await decodeToken(token);
  if (d.type !== USER_TYPE) {
    throw new ValissError(`valiss: not a user token (type "${d.type}")`, Reason.WRONG_TYPE);
  }
  if (d.issuer !== accountPubKey) {
    throw new ValissError(
      "valiss: user token not signed by the expected account",
      Reason.WRONG_ISSUER,
    );
  }
  if (!nkeys.isValidPublicUserKey(d.subject)) {
    throw new ValissError(
      "valiss: user token subject is not a user public key",
      Reason.WRONG_SUBJECT_ROLE,
    );
  }
  return {
    ...claimsOf(d),
    name: nameOf(d.name, d.subject),
    epoch: d.epoch,
    bearer: d.bearer,
    ext: d.ext,
  };
}

/**
 * Parse a token of any level without establishing trust: the signature is
 * checked against the token's own embedded issuer only. For inspection and
 * tooling.
 */
export async function decode(token: string): Promise<Claims> {
  return claimsOf(await decodeToken(token));
}

/**
 * Public key that signed a token, after checking the token's own signature
 * against it. Does not establish trust: the caller must still verify the
 * issuer's place in the chain.
 */
export async function issuerOf(token: string): Promise<string> {
  return (await decodeToken(token)).issuer;
}
