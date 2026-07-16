/**
 * Conformance runner for the language-neutral valiss spec-1 vectors.
 *
 * Loads the frozen vectors (`test/vectors/*.json`, a verbatim copy of the
 * `valiss-dev/spec` vectors — see that directory's README) and asserts the
 * runner contract from the spec's `vectors/README.md`: for each case, invoke
 * the library entrypoint named by `op` with `input` + `args`; on `expect.ok`
 * the operation MUST succeed and every field in `expect.claims` MUST match;
 * otherwise it MUST fail and the error MUST map to the spec §7
 * `expect.reason` code (exposed as `ValissError.reason`).
 *
 * Set `VALISS_VECTORS_DIR` to run against a different copy (e.g. a live
 * checkout of the spec vectors) instead of the vendored one.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { parseCreds } from "../src/creds.js";
import { ValissError } from "../src/errors.js";
import { verifyMessage, type VerifyMessageOptions } from "../src/message.js";
import { verifySignature } from "../src/sign.js";
import { verifyAccount, verifyOperator, verifyUser } from "../src/token.js";

const VECTORS_DIR =
  process.env["VALISS_VECTORS_DIR"] ?? join(import.meta.dirname, "vectors");

const CATEGORY_FILES = ["tokens.json", "signatures.json", "creds.json", "messages.json"];

interface Case {
  id: string;
  desc: string;
  op: string;
  input: Record<string, string>;
  args?: Record<string, unknown>;
  expect: { ok: boolean; reason?: string; claims?: Record<string, unknown> };
}

// Go time.Duration units, in milliseconds. "ms"/"us"/"ns" must be matched
// before "s"/"m".
const DURATION_UNITS: Record<string, number> = {
  ns: 1e-6,
  us: 1e-3,
  "µs": 1e-3,
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
};
const DURATION_TERM = /(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g;
const DURATION = /^([+-]?)((?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+)$/;

/**
 * Parse a Go time.ParseDuration string (e.g. `2m`, `1h30m`, `300ms`, `-5s`)
 * into milliseconds, so a vector's `skew` maps to the exact window Go used
 * regardless of the unit it was emitted with.
 */
function parseGoDurationMs(s: string): number {
  const m = DURATION.exec(s);
  if (m === null) throw new Error(`unparsable duration "${s}"`);
  let total = 0;
  for (const [, value, unit] of m[2]!.matchAll(DURATION_TERM)) {
    total += Number.parseFloat(value!) * DURATION_UNITS[unit!]!;
  }
  return m[1] === "-" ? -total : total;
}

function loadCases(): Case[] {
  const cases: Case[] = [];
  for (const name of CATEGORY_FILES) {
    const data = JSON.parse(readFileSync(join(VECTORS_DIR, name), "utf8")) as {
      spec: number;
      cases: Case[];
    };
    if (data.spec !== 1) throw new Error(`${name}: unexpected spec version ${data.spec}`);
    cases.push(...data.cases);
  }
  return cases;
}

const CASES = loadCases();

/**
 * Dispatch a case to its library entrypoint, returning the exposed claims (on
 * success) or throwing ValissError (on failure).
 */
async function invoke(c: Case): Promise<Record<string, unknown>> {
  const input = c.input;
  const args = (c.args ?? {}) as Record<string, string>;

  switch (c.op) {
    case "verify_operator": {
      const claims = await verifyOperator(input["token"]!, args["operator_pub"]!);
      return { subject: claims.subject, name: claims.name, epoch: claims.epoch };
    }
    case "verify_account": {
      const claims = await verifyAccount(input["token"]!, args["operator_pub"]!);
      return { subject: claims.subject, name: claims.name, epoch: claims.epoch };
    }
    case "verify_user": {
      const claims = await verifyUser(input["token"]!, args["account_pub"]!);
      return {
        subject: claims.subject,
        name: claims.name,
        epoch: claims.epoch,
        bearer: claims.bearer,
      };
    }
    case "verify_message": {
      const opts: VerifyMessageOptions = {};
      if (args["now"] !== undefined) opts.now = new Date(args["now"]);
      if (args["skew"] !== undefined) opts.skewMs = parseGoDurationMs(args["skew"]);
      if (args["audience"] !== undefined) opts.audience = args["audience"];
      if (args["require_checksum"]) opts.requireChecksum = true;
      if (args["payload"] !== undefined) opts.payload = args["payload"];
      if (args["chain_account"] !== undefined && args["chain_user"] !== undefined) {
        opts.chain = { account: args["chain_account"], user: args["chain_user"] };
      }
      if (args["operator_token"] !== undefined) opts.operatorToken = args["operator_token"];
      const claims = await verifyMessage(input["token"]!, args["operator_pub"]!, opts);
      return {
        subject: claims.subject,
        audience: claims.audience,
        checksum: claims.checksum,
        epoch: claims.epoch,
      };
    }
    case "verify_signature": {
      await verifySignature(
        args["subject_pub"]!,
        input["timestamp"]!,
        input["signature"]!,
        args["context"] ?? "",
        new Date(args["now"]!),
        parseGoDurationMs(args["skew"]!),
      );
      return {};
    }
    case "parse_creds": {
      const creds = parseCreds(input["creds"]!);
      return {
        has_account: creds.accountToken !== "",
        has_user: creds.userToken !== "",
        has_seed: creds.seed !== "",
      };
    }
    default:
      throw new Error(`unknown op "${c.op}"`);
  }
}

describe("conformance", () => {
  it("finds the vendored vectors", () => {
    // A misconfigured path must fail loudly instead of silently passing zero
    // cases.
    expect(CASES.length).toBeGreaterThan(0);
  });

  for (const c of CASES) {
    it(c.id, async () => {
      if (c.expect.ok) {
        const claims = await invoke(c);
        for (const [key, want] of Object.entries(c.expect.claims ?? {})) {
          expect(claims, `claim "${key}" not exposed`).toHaveProperty(key);
          expect(claims[key], `claim "${key}"`).toEqual(want);
        }
      } else {
        let reason: string | undefined;
        try {
          await invoke(c);
        } catch (err) {
          expect(err, "failure must be a ValissError").toBeInstanceOf(ValissError);
          reason = (err as ValissError).reason;
        }
        expect(reason, "must fail with the spec §7 reason").toBe(c.expect.reason);
      }
    });
  }
});
