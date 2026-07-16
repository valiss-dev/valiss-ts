import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { Reason, ValissError } from "../src/errors.js";
import { checksum, issueMessage, verifyMessage } from "../src/message.js";
import * as nkeys from "../src/nkeys.js";
import { issueAccount, issueOperator, issueUser } from "../src/token.js";

const KEYS = (
  JSON.parse(readFileSync(join(import.meta.dirname, "vectors", "keys.json"), "utf8")) as {
    keys: Record<string, { pub: string; seed: string }>;
  }
).keys;

const OPERATOR = KEYS["operator"]!;
const ACCOUNT = KEYS["account"]!;
const USER = KEYS["user"]!;

const NOW = new Date("2030-01-01T00:00:00Z");
const AUDIENCE = "https://api.example.com/ingest";

async function mintChain(epoch = 0) {
  const operator = await nkeys.fromSeed(OPERATOR.seed);
  const account = await nkeys.fromSeed(ACCOUNT.seed);
  const opts = epoch !== 0 ? { epoch, now: NOW } : { now: NOW };
  return {
    account: await issueAccount(operator, "acme", ACCOUNT.pub, opts),
    user: await issueUser(account, "alice", USER.pub, opts),
  };
}

describe("message tokens", () => {
  it("round-trips a full chain with audience and checksum bindings", async () => {
    const user = await nkeys.fromSeed(USER.seed);
    const chain = await mintChain();
    const payload = "hello world";
    const token = await issueMessage(user, {
      audience: AUDIENCE,
      checksum: await checksum(payload),
      chain,
      ttlMs: 30_000,
      now: NOW,
    });
    const claims = await verifyMessage(token, OPERATOR.pub, {
      now: NOW,
      audience: AUDIENCE,
      payload,
    });
    expect(claims.subject).toBe(USER.pub);
    expect(claims.audience).toBe(AUDIENCE);
    expect(claims.account.name).toBe("acme");
    expect(claims.user.name).toBe("alice");
    expect(claims.operator).toBeUndefined();
  });

  it("verifies a chainless token with a chain supplied out of band", async () => {
    const user = await nkeys.fromSeed(USER.seed);
    const chain = await mintChain();
    const token = await issueMessage(user, { ttlMs: 30_000, now: NOW });
    const claims = await verifyMessage(token, OPERATOR.pub, { now: NOW, chain });
    expect(claims.subject).toBe(USER.pub);
    await expect(verifyMessage(token, OPERATOR.pub, { now: NOW })).rejects.toMatchObject({
      reason: Reason.NO_CHAIN,
    });
  });

  it("enforces operator policy: epoch agreement and validity window", async () => {
    const operator = await nkeys.fromSeed(OPERATOR.seed);
    const user = await nkeys.fromSeed(USER.seed);
    const chain = await mintChain(7);
    const operatorToken = await issueOperator(operator, {
      name: "acme-trust",
      epoch: 7,
      now: NOW,
    });
    const token = await issueMessage(user, { epoch: 7, chain, ttlMs: 30_000, now: NOW });
    const claims = await verifyMessage(token, OPERATOR.pub, { now: NOW, operatorToken });
    expect(claims.epoch).toBe(7);
    expect(claims.operator?.epoch).toBe(7);

    // A message minted in another epoch is rejected against the same chain.
    const stale = await issueMessage(user, { epoch: 6, chain, ttlMs: 30_000, now: NOW });
    await expect(verifyMessage(stale, OPERATOR.pub, { now: NOW, operatorToken })).rejects.toMatchObject(
      { reason: Reason.EPOCH_MISMATCH },
    );

    // An expired operator token closes the trust domain.
    const closed = await issueOperator(operator, {
      name: "acme-trust",
      epoch: 7,
      ttlMs: 1000,
      now: new Date("2020-01-01T00:00:00Z"),
    });
    await expect(
      verifyMessage(token, OPERATOR.pub, { now: NOW, operatorToken: closed }),
    ).rejects.toMatchObject({ reason: Reason.EXPIRED });
  });

  it("rejects an expired message at the verification instant", async () => {
    const user = await nkeys.fromSeed(USER.seed);
    const chain = await mintChain();
    const token = await issueMessage(user, { chain, ttlMs: 30_000, now: NOW });
    await expect(
      verifyMessage(token, OPERATOR.pub, { now: new Date("2030-01-01T01:00:00Z") }),
    ).rejects.toMatchObject({ reason: Reason.EXPIRED });
  });

  it("requires an expiry and a well-formed checksum at mint time", async () => {
    const user = await nkeys.fromSeed(USER.seed);
    await expect(issueMessage(user, { now: NOW })).rejects.toThrow(ValissError);
    await expect(
      issueMessage(user, { checksum: "NOT-HEX", ttlMs: 1000, now: NOW }),
    ).rejects.toThrow(ValissError);
  });

  it("rejects minting with a non-user key or a chain for another user", async () => {
    const account = await nkeys.fromSeed(ACCOUNT.seed);
    await expect(issueMessage(account, { ttlMs: 1000, now: NOW })).rejects.toThrow(ValissError);

    const operator = await nkeys.fromSeed(OPERATOR.seed);
    const otherUser = KEYS["user2"]!;
    const chain = {
      account: await issueAccount(operator, "acme", ACCOUNT.pub, { now: NOW }),
      user: await issueUser(account, "bob", otherUser.pub, { now: NOW }),
    };
    const user = await nkeys.fromSeed(USER.seed);
    await expect(issueMessage(user, { chain, ttlMs: 1000, now: NOW })).rejects.toThrow(
      ValissError,
    );
  });

  it("binds the audience and checksum on verification", async () => {
    const user = await nkeys.fromSeed(USER.seed);
    const chain = await mintChain();
    const token = await issueMessage(user, {
      audience: AUDIENCE,
      checksum: await checksum("hello world"),
      chain,
      ttlMs: 30_000,
      now: NOW,
    });
    await expect(
      verifyMessage(token, OPERATOR.pub, { now: NOW, audience: "https://evil.example.com" }),
    ).rejects.toMatchObject({ reason: Reason.WRONG_AUDIENCE });
    await expect(
      verifyMessage(token, OPERATOR.pub, { now: NOW, payload: "different payload" }),
    ).rejects.toMatchObject({ reason: Reason.CHECKSUM_MISMATCH });

    const unbound = await issueMessage(user, { chain, ttlMs: 30_000, now: NOW });
    await expect(
      verifyMessage(unbound, OPERATOR.pub, { now: NOW, requireChecksum: true }),
    ).rejects.toMatchObject({ reason: Reason.CHECKSUM_MISSING });
  });

  it("computes the reference checksum", async () => {
    expect(await checksum("hello world")).toBe(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    );
  });
});
