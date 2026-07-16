/**
 * Request signatures: the per-request proof that the sender holds the
 * subject's private key (spec §5).
 *
 * The subject signs `"valiss-req-v1\n" + timestamp + "\n" +
 * lowercasehex(SHA-256(request_context))` with its nkey seed; the transport
 * carries the RFC 3339 nanosecond UTC timestamp and the base64std-encoded
 * signature. The verifier reconstructs the signed bytes from the *received*
 * timestamp string (not a re-rendering, spec §5.4) and the locally derived
 * request context, so any precision the sender used round-trips exactly.
 */

import { base64StdDecode, base64StdEncode, hexEncode, sha256, utf8Encode } from "./encoding.js";
import { Reason, ValissError } from "./errors.js";
import * as nkeys from "./nkeys.js";
import { DEFAULT_SKEW_MS } from "./token.js";

// Version tag bound into the version-1 request-signature bytes (spec §5.1).
// Because it is part of the signed bytes, a v1 reconstruction fails closed on
// a signature made under any other version rather than mis-verifying it.
const REQUEST_PREFIX_V1 = "valiss-req-v1\n";

// RFC 3339 with an optional fraction, matching Go time.RFC3339Nano: a 'T'
// separator and a 'Z' or colon-separated numeric offset; no space separator
// and no lowercase 't'.
const RFC3339NANO = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/**
 * Fresh random per-request nonce (128 bits, hex). Client transports use it
 * when the server has a replay cache; the transport folds it into the signed
 * request context.
 */
export function newNonce(): string {
  return hexEncode(crypto.getRandomValues(new Uint8Array(16)));
}

/**
 * Render a Date like Go `time.RFC3339Nano` in UTC: the fraction is trimmed of
 * trailing zeros and omitted when zero. JS Dates carry millisecond precision,
 * which is legal RFC 3339 nanosecond output.
 */
function rfc3339Nano(date: Date): string {
  return date.toISOString().replace(/\.(\d*?)0*Z$/, (_, frac: string) =>
    frac === "" ? "Z" : `.${frac}Z`,
  );
}

function contextBytes(context: Uint8Array | string): Uint8Array {
  return typeof context === "string" ? utf8Encode(context) : context;
}

/**
 * Canonical byte string a subject signs per request (spec §5.1): a version
 * tag, then the timestamp bound to a hash of the request context. Binding the
 * context (the transport's canonical method/path) stops a captured signature
 * from authorizing a different operation; the timestamp and skew window bound
 * replay of the same operation.
 */
async function signedPayload(timestamp: string, context: Uint8Array): Promise<Uint8Array> {
  return utf8Encode(`${REQUEST_PREFIX_V1}${timestamp}\n${hexEncode(await sha256(context))}`);
}

/**
 * Produce the timestamp and base64std signature a subject attaches to a
 * request, signing the timestamp bound to the request context with its nkey
 * seed.
 *
 * `context` is the transport's canonical description of the request (e.g.
 * method and path); the server must reconstruct identical bytes. An empty
 * context binds nothing beyond the version tag and timestamp.
 */
export async function signRequest(
  subject: nkeys.KeyPair,
  context: Uint8Array | string = "",
  now?: Date,
): Promise<{ timestamp: string; signature: string }> {
  const timestamp = rfc3339Nano(now ?? new Date());
  const payload = await signedPayload(timestamp, contextBytes(context));
  return { timestamp, signature: base64StdEncode(await subject.sign(payload)) };
}

/**
 * Check a request signature against the subject public key, bound the
 * timestamp to a symmetric skew window around `now`, and confirm it was
 * signed over the request context (see {@link signRequest}). Throws
 * {@link ValissError} with the spec §7 reason on any failure.
 */
export async function verifySignature(
  subjectPubKey: string,
  timestamp: string,
  signature: string,
  context: Uint8Array | string = "",
  now?: Date,
  skewMs: number = DEFAULT_SKEW_MS,
): Promise<void> {
  const at = now ?? new Date();
  // Go parses the timestamp with time.RFC3339Nano, which is stricter than
  // Date.parse: gate on that shape so a non-RFC3339 timestamp maps to skew
  // (as Go does) rather than sneaking through to the signature check. The
  // fraction is applied separately because Date.parse only carries
  // millisecond precision.
  const m = RFC3339NANO.exec(timestamp);
  if (m === null) {
    throw new ValissError("valiss: bad request timestamp", Reason.SKEW);
  }
  const base = Date.parse(m[1]! + m[3]!);
  if (Number.isNaN(base)) {
    throw new ValissError("valiss: bad request timestamp", Reason.SKEW);
  }
  const tsMs = base + (m[2] !== undefined ? Number.parseFloat(m[2]) * 1000 : 0);
  const drift = at.getTime() - tsMs;
  if (drift > skewMs || drift < -skewMs) {
    throw new ValissError(
      `valiss: request timestamp outside the ${skewMs}ms skew window`,
      Reason.SKEW,
    );
  }
  let rawSignature: Uint8Array;
  try {
    rawSignature = base64StdDecode(signature);
  } catch (err) {
    throw new ValissError(
      `valiss: bad request signature encoding: ${(err as Error).message}`,
      Reason.BAD_SIGNATURE_ENCODING,
    );
  }
  let pub: nkeys.KeyPair;
  try {
    pub = nkeys.fromPublicKey(subjectPubKey);
  } catch (err) {
    throw new ValissError(
      `valiss: bad subject public key: ${(err as Error).message}`,
      Reason.BAD_REQUEST_SIGNATURE,
    );
  }
  // The payload embeds the timestamp string exactly as received: canonical
  // RFC3339Nano round-trips, and precision beyond milliseconds is preserved
  // because the string, not a parsed Date, is what gets signed over.
  const payload = await signedPayload(timestamp, contextBytes(context));
  try {
    await pub.verify(payload, rawSignature);
  } catch {
    throw new ValissError(
      "valiss: request signature verification failed",
      Reason.BAD_REQUEST_SIGNATURE,
    );
  }
}
