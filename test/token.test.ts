import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { base32Encode, base64UrlDecode, sha256, utf8Decode } from "../src/encoding.js";
import { Reason, ValissError } from "../src/errors.js";
import * as nkeys from "../src/nkeys.js";
import {
  decode,
  goJsonBytes,
  issueAccount,
  issueOperator,
  issuerOf,
  issueUser,
  verifyAccount,
  verifyOperator,
  verifyUser,
} from "../src/token.js";

const VECTORS_DIR = join(import.meta.dirname, "vectors");

const KEYS = (
  JSON.parse(readFileSync(join(VECTORS_DIR, "keys.json"), "utf8")) as {
    keys: Record<string, { pub: string; seed: string }>;
  }
).keys;

const OPERATOR = KEYS["operator"]!;
const ACCOUNT = KEYS["account"]!;
const USER = KEYS["user"]!;

// A token minted by the Go reference implementation (valiss-go v0.13.0) from
// the frozen operator seed, with claims chosen to exercise every Go
// encoding/json behavior the jti derivation depends on: HTML escaping of
// < > & and of U+2028/U+2029, omit-when-empty
// field handling, and sorted map keys at every depth of the ext payload.
// Ed25519 is deterministic, so an identical mint reproduces the whole token.
const GOLDEN_TOKEN =
  "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkiLCJ2ZXIiOjF9.eyJqdGkiOiJEUTRaVzMyQVpLRFdRWFdYRFVIV0Y3QTJaQTI0NzRHWktEUk1CM1RHWTNZUzdZNERWV1hBIiwiaWF0IjoxNzg0MjIwOTYxLCJpc3MiOiJPQ1VRQU5ZNDNGTVNKRDdFNTJWSlEzR0FUT0RZVkEyWUpONk5UR0lHMzZIS1NPMlFJRFFRUllUTSIsIm5hbWUiOiJhY21lIFx1MDAzY1dpZGdldHMgXHUwMDI2IENvXHUwMDNlIFx1MjAyOHNlcFx1MjAyOSBkb25lIiwic3ViIjoiQUNGU0RHM1pNN05HNTJQU0o2UURSWVg2UllTTENLRFY1VURaV0hTRENFRDZRTFdGWVpINEVHWFQiLCJleHAiOjIwNTEyMjI0MDAsIm5iZiI6MTc2NzIyNTYwMCwidmFsaXNzIjp7InR5cGUiOiJhY2NvdW50IiwiZXBvY2giOjQyLCJleHQiOnsiY29uZm9ybWFuY2UtZXh0Ijp7ImFscGhhIjp7ImEiOiJcdTAwM2NcdTAwMjZcdTAwM2UiLCJiIjp0cnVlfSwiemV0YSI6MX19fX0._IJZzFz9ggRptJHg7QVUgH8GVXwYLRuuKF0mkSFqgPNIEDXAlaO0RGqMwtKdaacNl_6fwjycUVtIcoVWqrwIDw";

async function jtiOf(payload: Record<string, unknown>): Promise<string> {
  const { jti: _jti, ...rest } = payload;
  return base32Encode(await sha256(goJsonBytes(rest)));
}

describe("jti byte-exactness against the Go reference", () => {
  it("reproduces the Go-minted golden token byte for byte", async () => {
    const operator = await nkeys.fromSeed(OPERATOR.seed);
    const minted = await issueAccount(
      operator,
      "acme <Widgets & Co> \u2028sep\u2029 done",
      ACCOUNT.pub,
      {
        epoch: 42,
        expiresAt: new Date(2051222400 * 1000),
        notBefore: new Date(1767225600 * 1000),
        // Insertion order deliberately differs from the sorted wire order.
        extensions: { "conformance-ext": { zeta: 1, alpha: { b: true, a: "<&>" } } },
        now: new Date(1784220961 * 1000),
      },
    );
    expect(minted).toBe(GOLDEN_TOKEN);
  });

  it("re-derives the jti of the golden token from its own claims", async () => {
    const payload = JSON.parse(
      utf8Decode(base64UrlDecode(GOLDEN_TOKEN.split(".")[1]!)),
    ) as Record<string, unknown>;
    expect(await jtiOf(payload)).toBe(payload["jti"]);
  });

  it("re-serializes vector payloads byte-identically", async () => {
    // Every frozen token vector's payload must survive a parse → goJson
    // round-trip, proving the serializer emits Go's exact bytes for the
    // claims the spec defines.
    const data = JSON.parse(readFileSync(join(VECTORS_DIR, "tokens.json"), "utf8")) as {
      cases: { id: string; input: { token: string }; expect: { ok: boolean } }[];
    };
    for (const c of data.cases.filter((c) => c.expect.ok)) {
      const part = c.input.token.split(".")[1]!;
      const wire = utf8Decode(base64UrlDecode(part));
      const payload = JSON.parse(wire) as Record<string, unknown>;
      expect(utf8Decode(goJsonBytes(payload)), c.id).toBe(wire);
      expect(await jtiOf(payload), c.id).toBe(payload["jti"]);
    }
  });
});

describe("token mint and verify", () => {
  it("round-trips an operator token", async () => {
    const operator = await nkeys.fromSeed(OPERATOR.seed);
    const token = await issueOperator(operator, { name: "acme-trust", epoch: 7 });
    const claims = await verifyOperator(token, OPERATOR.pub);
    expect(claims.name).toBe("acme-trust");
    expect(claims.epoch).toBe(7);
    expect(claims.subject).toBe(OPERATOR.pub);
    expect(claims.issuer).toBe(OPERATOR.pub);
    expect(claims.expiresAt).toBeUndefined();
  });

  it("round-trips an account token with validity window and extensions", async () => {
    const operator = await nkeys.fromSeed(OPERATOR.seed);
    const now = new Date("2030-01-01T00:00:00Z");
    const token = await issueAccount(operator, "acme", ACCOUNT.pub, {
      ttlMs: 3_600_000,
      notBefore: now,
      epoch: 7,
      extensions: { scopes: { paths: ["/v1/*"] } },
      now,
    });
    const claims = await verifyAccount(token, OPERATOR.pub);
    expect(claims.name).toBe("acme");
    expect(claims.subject).toBe(ACCOUNT.pub);
    expect(claims.epoch).toBe(7);
    expect(claims.expiresAt).toEqual(new Date("2030-01-01T01:00:00Z"));
    expect(claims.notBefore).toEqual(now);
    expect(claims.issuedAt).toEqual(now);
    expect(claims.ext).toEqual({ scopes: { paths: ["/v1/*"] } });
    expect(claims.id).toBe((await decode(token)).id);
    expect(claims.id.length).toBe(52);
  });

  it("round-trips a bearer user token", async () => {
    const account = await nkeys.fromSeed(ACCOUNT.seed);
    const token = await issueUser(account, "kiosk", USER.pub, { bearer: true });
    const claims = await verifyUser(token, ACCOUNT.pub);
    expect(claims.name).toBe("kiosk");
    expect(claims.bearer).toBe(true);
    expect(claims.subject).toBe(USER.pub);
  });

  it("falls back to the subject key when unnamed", async () => {
    const operator = await nkeys.fromSeed(OPERATOR.seed);
    const token = await issueAccount(operator, "", ACCOUNT.pub);
    const claims = await verifyAccount(token, OPERATOR.pub);
    expect(claims.name).toBe(ACCOUNT.pub);
  });

  it("shares a jti between tokens with identical claims", async () => {
    const operator = await nkeys.fromSeed(OPERATOR.seed);
    const now = new Date("2030-01-01T00:00:00Z");
    const a = await issueAccount(operator, "acme", ACCOUNT.pub, { now });
    const b = await issueAccount(operator, "acme", ACCOUNT.pub, { now });
    expect(a).toBe(b);
  });

  it("rejects minting with a wrong-role key", async () => {
    const operator = await nkeys.fromSeed(OPERATOR.seed);
    const account = await nkeys.fromSeed(ACCOUNT.seed);
    await expect(issueOperator(account)).rejects.toThrow(ValissError);
    await expect(issueAccount(account, "x", ACCOUNT.pub)).rejects.toThrow(ValissError);
    await expect(issueAccount(operator, "x", USER.pub)).rejects.toThrow(ValissError);
    await expect(issueUser(operator, "x", USER.pub)).rejects.toThrow(ValissError);
    await expect(issueUser(await nkeys.fromSeed(ACCOUNT.seed), "x", ACCOUNT.pub)).rejects.toThrow(
      ValissError,
    );
  });

  it("rejects mutually exclusive validity options", async () => {
    const operator = await nkeys.fromSeed(OPERATOR.seed);
    await expect(
      issueAccount(operator, "acme", ACCOUNT.pub, { ttlMs: 1000, expiresAt: new Date() }),
    ).rejects.toThrow(ValissError);
    await expect(issueAccount(operator, "acme", ACCOUNT.pub, { ttlMs: 0 })).rejects.toThrow(
      ValissError,
    );
  });

  it("rejects an empty extension name", async () => {
    const operator = await nkeys.fromSeed(OPERATOR.seed);
    await expect(
      issueAccount(operator, "acme", ACCOUNT.pub, { extensions: { "": {} } }),
    ).rejects.toThrow(ValissError);
  });

  it("exposes the issuer via issuerOf after checking the self-signature", async () => {
    const account = await nkeys.fromSeed(ACCOUNT.seed);
    const token = await issueUser(account, "alice", USER.pub);
    expect(await issuerOf(token)).toBe(ACCOUNT.pub);
    const [h, p] = token.split(".");
    await expect(issuerOf(`${h}.${p}.AAAA`)).rejects.toMatchObject({
      reason: Reason.BAD_SIGNATURE,
    });
  });
});
