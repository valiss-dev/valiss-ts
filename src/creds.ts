/**
 * Client credentials file: the subject's token(s) plus the seed that signs
 * its requests, in one marker-delimited text file (spec §4). File-compatible
 * with the Go valiss/creds package.
 *
 * Account-level creds hold the operator-signed account token and the account
 * seed. User-level creds hold the account-signed user token and the user
 * seed; the server resolves the account token itself. A *bundle* additionally
 * carries the upstream account token, for servers that do not resolve it.
 * Bearer creds carry tokens only: their holder cannot sign requests and the
 * server accepts them only when the effective token is a bearer user token.
 *
 * The file begins with a `VALISS-CREDS-VERSION` line that versions the
 * container only (the tokens inside carry their own wire version). A parser
 * reads it before the payload and rejects a version it does not implement; an
 * absent line reads as the current version, since the pre-versioned format is
 * otherwise identical.
 */

import { Reason, ValissError } from "./errors.js";
import * as nkeys from "./nkeys.js";

// The creds-file container version, emitted as a header line and checked on
// parse, independent of the wire version of the tokens the file carries.
const CREDS_VERSION = 1;
const CREDS_VERSION_MARKER = "VALISS-CREDS-VERSION:";

// Go's strconv.Atoi accepts ASCII digits with an optional leading sign only.
const VERSION_VALUE = /^[+-]?[0-9]+$/;

// Section markers (spec §4.2). Note the asymmetry: BEGIN markers use five
// leading and trailing dashes; END markers use six.
const ACCOUNT_TOKEN_BEGIN = "-----BEGIN VALISS ACCOUNT TOKEN-----";
const ACCOUNT_TOKEN_END = "------END VALISS ACCOUNT TOKEN------";
const USER_TOKEN_BEGIN = "-----BEGIN VALISS USER TOKEN-----";
const USER_TOKEN_END = "------END VALISS USER TOKEN------";
const SEED_BEGIN = "-----BEGIN VALISS SEED-----";
const SEED_END = "------END VALISS SEED------";

/** Parsed content of a creds file. */
export interface Creds {
  /**
   * The operator-signed account token. User-level creds omit it by default
   * (the server then resolves the account token by other means, like static
   * configuration); a bundle embeds it.
   */
  accountToken: string;
  /** The account-signed user token; empty in account-level creds. */
  userToken: string;
  /**
   * Signs requests as the creds' subject: the account seed in account-level
   * creds, the user seed in user-level ones. Empty in bearer creds.
   */
  seed: string;
}

/** Key pair from the creds seed; undefined for bearer creds. */
export async function signerOf(creds: Creds): Promise<nkeys.KeyPair | undefined> {
  if (creds.seed === "") return undefined;
  try {
    return await nkeys.fromSeed(creds.seed);
  } catch (err) {
    throw new ValissError(`valiss: creds seed: ${(err as Error).message}`);
  }
}

/**
 * Render the creds file content: the version line, then any present sections
 * separated by a single blank line, in the order account token, user token,
 * seed, with a human-readable warning after the seed (spec §4.5).
 */
export function formatCreds(creds: Partial<Creds>): string {
  let out = `${CREDS_VERSION_MARKER} ${CREDS_VERSION}\n\n`;
  if (creds.accountToken) {
    out += `${ACCOUNT_TOKEN_BEGIN}\n${creds.accountToken.trim()}\n${ACCOUNT_TOKEN_END}\n`;
  }
  if (creds.userToken) {
    if (creds.accountToken) out += "\n";
    out += `${USER_TOKEN_BEGIN}\n${creds.userToken.trim()}\n${USER_TOKEN_END}\n`;
  }
  if (creds.seed) {
    out += `\n${SEED_BEGIN}\n${creds.seed.trim()}\n${SEED_END}\n`;
    out +=
      "\n************************* IMPORTANT *************************\n" +
      "Seed lets anyone sign as this identity. Keep it secret.\n";
  }
  return out;
}

/**
 * Extract the creds from a file's contents. The version line, if present, is
 * checked before the payload. Every section is optional on its own, but at
 * least one token must be present.
 */
export function parseCreds(contents: string): Creds {
  checkVersion(contents);
  const accountToken = between(contents, ACCOUNT_TOKEN_BEGIN, ACCOUNT_TOKEN_END, "creds token");
  const userToken = between(contents, USER_TOKEN_BEGIN, USER_TOKEN_END, "creds user token");
  if (accountToken === "" && userToken === "") {
    throw new ValissError("valiss: creds: no token markers found", Reason.MISSING);
  }
  const seed = between(contents, SEED_BEGIN, SEED_END, "creds seed");
  return { accountToken, userToken, seed };
}

/**
 * Read the creds-format version header and reject a version this parser does
 * not implement. An absent header is read as the current version. It is
 * checked before the payload, so an incompatible file is rejected cleanly
 * rather than mis-parsed.
 */
function checkVersion(contents: string): void {
  for (const line of contents.split("\n")) {
    const rest = line.trim();
    if (!rest.startsWith(CREDS_VERSION_MARKER)) continue;
    const value = rest.slice(CREDS_VERSION_MARKER.length).trim();
    // Go parses the value with strconv.Atoi: ASCII digits with an optional
    // sign only. Reject separators and Unicode digits that Number() would
    // otherwise accept.
    if (!VERSION_VALUE.test(value)) {
      throw new ValissError(`valiss: creds: malformed version "${value}"`, Reason.MALFORMED);
    }
    if (Number.parseInt(value, 10) !== CREDS_VERSION) {
      throw new ValissError(
        `valiss: creds: unsupported version ${value}`,
        Reason.UNSUPPORTED_VERSION,
      );
    }
    return;
  }
}

/**
 * Single non-empty line strictly between a begin and end marker; "" when the
 * begin marker is absent. A present section is strict: it must hold exactly
 * one payload line followed by the end marker. An empty, unclosed, or
 * multi-line section is an error, so a truncated or mangled creds file fails
 * here rather than downstream as a confusing cryptographic error.
 */
function between(contents: string, begin: string, end: string, what: string): string {
  let inside = false;
  let payload = "";
  for (const raw of contents.split("\n")) {
    const line = raw.trim();
    if (line === begin) {
      inside = true;
    } else if (!inside) {
      continue;
    } else if (line === end) {
      if (payload === "") {
        throw new ValissError(`valiss: ${what}: no content before "${end}"`, Reason.MALFORMED);
      }
      return payload;
    } else if (line === "") {
      continue;
    } else if (payload === "") {
      payload = line;
    } else {
      throw new ValissError(
        `valiss: ${what}: unexpected content in "${begin}" section`,
        Reason.MALFORMED,
      );
    }
  }
  if (inside) {
    throw new ValissError(`valiss: ${what}: marker "${begin}" not closed`, Reason.MALFORMED);
  }
  return "";
}
