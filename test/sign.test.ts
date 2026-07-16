import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { hexEncode, sha256, utf8Encode } from "../src/encoding.js";
import { Reason } from "../src/errors.js";
import * as nkeys from "../src/nkeys.js";
import { base64StdEncode } from "../src/encoding.js";
import { newNonce, signRequest, verifySignature } from "../src/sign.js";

const KEYS = (
  JSON.parse(readFileSync(join(import.meta.dirname, "vectors", "keys.json"), "utf8")) as {
    keys: Record<string, { pub: string; seed: string }>;
  }
).keys;

const USER = KEYS["user"]!;

describe("request signatures", () => {
  it("round-trips a signed request", async () => {
    const subject = await nkeys.fromSeed(USER.seed);
    const context = "http\nGET\napi.example.com\n/v1/widgets\n";
    const now = new Date("2030-01-01T00:00:00Z");
    const { timestamp, signature } = await signRequest(subject, context, now);
    expect(timestamp).toBe("2030-01-01T00:00:00Z");
    await expect(
      verifySignature(USER.pub, timestamp, signature, context, now),
    ).resolves.toBeUndefined();
  });

  it("renders the timestamp like Go RFC3339Nano: fraction trimmed of zeros", async () => {
    const subject = await nkeys.fromSeed(USER.seed);
    const cases: [string, string][] = [
      ["2030-01-01T00:00:00.120Z", "2030-01-01T00:00:00.12Z"],
      ["2030-01-01T00:00:00.001Z", "2030-01-01T00:00:00.001Z"],
      ["2030-01-01T00:00:00.000Z", "2030-01-01T00:00:00Z"],
    ];
    for (const [input, want] of cases) {
      const { timestamp } = await signRequest(subject, "", new Date(input));
      expect(timestamp).toBe(want);
    }
  });

  it("verifies against the timestamp string exactly as received", async () => {
    // Nanosecond and non-trimmed fractions cannot round-trip through a JS
    // Date, so the verifier must hash the received string, not a re-rendering
    // (spec §5.4). Build the signed bytes by hand around such a timestamp.
    const subject = await nkeys.fromSeed(USER.seed);
    const timestamp = "2030-01-01T00:00:00.123456789Z";
    const context = utf8Encode("ctx");
    const payload = utf8Encode(
      `valiss-req-v1\n${timestamp}\n${hexEncode(await sha256(context))}`,
    );
    const signature = base64StdEncode(await subject.sign(payload));
    await expect(
      verifySignature(USER.pub, timestamp, signature, context, new Date("2030-01-01T00:00:01Z")),
    ).resolves.toBeUndefined();
  });

  it("rejects a timestamp outside the skew window, symmetrically", async () => {
    const subject = await nkeys.fromSeed(USER.seed);
    const now = new Date("2030-01-01T00:00:00Z");
    const { timestamp, signature } = await signRequest(subject, "", now);
    for (const at of ["2030-01-01T00:02:01Z", "2029-12-31T23:57:59Z"]) {
      await expect(
        verifySignature(USER.pub, timestamp, signature, "", new Date(at)),
      ).rejects.toMatchObject({ reason: Reason.SKEW });
    }
    // Inside the window both ways.
    for (const at of ["2030-01-01T00:01:59Z", "2029-12-31T23:58:01Z"]) {
      await expect(
        verifySignature(USER.pub, timestamp, signature, "", new Date(at)),
      ).resolves.toBeUndefined();
    }
  });

  it("rejects timestamps Go time.RFC3339Nano would reject", async () => {
    const subject = await nkeys.fromSeed(USER.seed);
    const now = new Date("2030-01-01T00:00:00Z");
    const { timestamp, signature } = await signRequest(subject, "", now);
    for (const bad of [
      "2030-01-01 00:00:00Z", // space separator
      "2030-01-01t00:00:00Z", // lowercase t
      "2030-01-01T00:00:00", // no zone
      "2030-01-01T00:00:00+0000", // no colon in offset
      timestamp + " ",
    ]) {
      await expect(verifySignature(USER.pub, bad, signature, "", now)).rejects.toMatchObject({
        reason: Reason.SKEW,
      });
    }
  });

  it("rejects a signature over a different context", async () => {
    const subject = await nkeys.fromSeed(USER.seed);
    const now = new Date("2030-01-01T00:00:00Z");
    const { timestamp, signature } = await signRequest(subject, "context-a", now);
    await expect(
      verifySignature(USER.pub, timestamp, signature, "context-b", now),
    ).rejects.toMatchObject({ reason: Reason.BAD_REQUEST_SIGNATURE });
  });

  it("rejects a non-base64std signature", async () => {
    const now = new Date("2030-01-01T00:00:00Z");
    await expect(
      verifySignature(USER.pub, "2030-01-01T00:00:00Z", "***", "", now),
    ).rejects.toMatchObject({ reason: Reason.BAD_SIGNATURE_ENCODING });
    // base64url-flavored input is not base64std.
    await expect(
      verifySignature(USER.pub, "2030-01-01T00:00:00Z", "ab-_", "", now),
    ).rejects.toMatchObject({ reason: Reason.BAD_SIGNATURE_ENCODING });
  });

  it("generates unique 128-bit hex nonces", () => {
    const a = newNonce();
    const b = newNonce();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });
});
