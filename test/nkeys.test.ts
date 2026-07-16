import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { utf8Encode } from "../src/encoding.js";
import { ValissError } from "../src/errors.js";
import * as nkeys from "../src/nkeys.js";

const KEYS = (
  JSON.parse(readFileSync(join(import.meta.dirname, "vectors", "keys.json"), "utf8")) as {
    keys: Record<string, { pub: string; seed: string }>;
  }
).keys;

describe("nkeys", () => {
  it("derives the frozen public keys from the frozen seeds", async () => {
    // Cross-implementation anchor: every seed/public pair in the conformance
    // key material must reproduce byte-for-byte.
    for (const [name, { pub, seed }] of Object.entries(KEYS)) {
      const kp = await nkeys.fromSeed(seed);
      expect(kp.publicKey, name).toBe(pub);
      expect(kp.seed, name).toBe(seed);
    }
  });

  it("round-trips public keys through decode/encode", () => {
    for (const { pub } of Object.values(KEYS)) {
      const { prefix, key } = nkeys.decodePublic(pub);
      expect(nkeys.encodePublic(prefix, key)).toBe(pub);
    }
  });

  it("rejects a corrupted checksum", () => {
    const pub = KEYS["operator"]!.pub;
    const corrupted = pub.slice(0, -1) + (pub.endsWith("A") ? "B" : "A");
    expect(() => nkeys.decodePublic(corrupted)).toThrow(ValissError);
  });

  it("rejects lowercase and non-alphabet input", () => {
    expect(() => nkeys.decodePublic("not-an-nkey")).toThrow(ValissError);
    expect(() => nkeys.decodePublic(KEYS["operator"]!.pub.toLowerCase())).toThrow(ValissError);
  });

  it("validates role-specific public keys", () => {
    expect(nkeys.isValidPublicOperatorKey(KEYS["operator"]!.pub)).toBe(true);
    expect(nkeys.isValidPublicAccountKey(KEYS["account"]!.pub)).toBe(true);
    expect(nkeys.isValidPublicUserKey(KEYS["user"]!.pub)).toBe(true);
    expect(nkeys.isValidPublicOperatorKey(KEYS["account"]!.pub)).toBe(false);
    expect(nkeys.isValidPublicAccountKey(KEYS["user"]!.pub)).toBe(false);
    expect(nkeys.isValidPublicUserKey(KEYS["operator"]!.pub)).toBe(false);
    expect(nkeys.isValidPublicUserKey(KEYS["user"]!.seed)).toBe(false);
  });

  it("signs and verifies", async () => {
    const kp = await nkeys.fromSeed(KEYS["user"]!.seed);
    const data = utf8Encode("payload");
    const signature = await kp.sign(data);
    expect(signature.length).toBe(64);
    await expect(kp.verify(data, signature)).resolves.toBeUndefined();
    const verifier = nkeys.fromPublicKey(KEYS["user"]!.pub);
    await expect(verifier.verify(data, signature)).resolves.toBeUndefined();
  });

  it("rejects a wrong signature and a wrong key", async () => {
    const kp = await nkeys.fromSeed(KEYS["user"]!.seed);
    const data = utf8Encode("payload");
    const signature = await kp.sign(data);
    signature[0]! ^= 0xff;
    await expect(kp.verify(data, signature)).rejects.toThrow(ValissError);
    signature[0]! ^= 0xff;
    const other = nkeys.fromPublicKey(KEYS["user2"]!.pub);
    await expect(other.verify(data, signature)).rejects.toThrow(ValissError);
  });

  it("verify-only pairs cannot sign and hold no seed", async () => {
    const verifier = nkeys.fromPublicKey(KEYS["user"]!.pub);
    await expect(verifier.sign(utf8Encode("x"))).rejects.toThrow(ValissError);
    expect(() => verifier.seed).toThrow(ValissError);
  });

  it("generates fresh key pairs of each role", async () => {
    const operator = await nkeys.createOperator();
    const account = await nkeys.createAccount();
    const user = await nkeys.createUser();
    expect(nkeys.isValidPublicOperatorKey(operator.publicKey)).toBe(true);
    expect(nkeys.isValidPublicAccountKey(account.publicKey)).toBe(true);
    expect(nkeys.isValidPublicUserKey(user.publicKey)).toBe(true);
    expect(operator.seed.startsWith("SO")).toBe(true);
    expect(account.seed.startsWith("SA")).toBe(true);
    expect(user.seed.startsWith("SU")).toBe(true);
    // The seed round-trips into the same pair.
    const again = await nkeys.fromSeed(user.seed);
    expect(again.publicKey).toBe(user.publicKey);
  });
});
