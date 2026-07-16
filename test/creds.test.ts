import { describe, expect, it } from "vitest";

import { formatCreds, parseCreds, signerOf } from "../src/creds.js";
import { Reason, ValissError } from "../src/errors.js";

const ACCOUNT_TOKEN = "account.token.payload";
const USER_TOKEN = "user.token.payload";
const SEED = "SAAOQP3V6WPJHPL55RZYGMFV54RLRTD4W3TLEZ4BOGPEGIGUUCARECGMY4";

describe("creds files", () => {
  it("round-trips every creds shape", () => {
    const shapes = [
      { accountToken: ACCOUNT_TOKEN, userToken: "", seed: SEED }, // account-level
      { accountToken: "", userToken: USER_TOKEN, seed: SEED }, // user-level
      { accountToken: ACCOUNT_TOKEN, userToken: USER_TOKEN, seed: SEED }, // bundle
      { accountToken: ACCOUNT_TOKEN, userToken: USER_TOKEN, seed: "" }, // bearer
    ];
    for (const creds of shapes) {
      expect(parseCreds(formatCreds(creds))).toEqual(creds);
    }
  });

  it("emits the version line and the asymmetric five/six-dash markers", () => {
    const out = formatCreds({ accountToken: ACCOUNT_TOKEN, seed: SEED });
    expect(out.startsWith("VALISS-CREDS-VERSION: 1\n")).toBe(true);
    expect(out).toContain("-----BEGIN VALISS ACCOUNT TOKEN-----\n");
    expect(out).toContain("------END VALISS ACCOUNT TOKEN------\n");
    expect(out).toContain("-----BEGIN VALISS SEED-----\n");
    expect(out).toContain("------END VALISS SEED------\n");
    expect(out).toContain("Keep it secret");
  });

  it("builds a signer from the seed, or none for bearer creds", async () => {
    const signer = await signerOf(parseCreds(formatCreds({ accountToken: ACCOUNT_TOKEN, seed: SEED })));
    expect(signer?.publicKey).toBe("ACFSDG3ZM7NG52PSJ6QDRYX6RYSLCKDV5UDZWHSDCED6QLWFYZH4EGXT");
    const bearer = await signerOf(parseCreds(formatCreds({ accountToken: ACCOUNT_TOKEN })));
    expect(bearer).toBeUndefined();
    await expect(
      signerOf({ accountToken: ACCOUNT_TOKEN, userToken: "", seed: "garbage" }),
    ).rejects.toThrow(ValissError);
  });

  it("ignores notes outside sections and blank lines inside", () => {
    const creds = parseCreds(
      "some notes\n\n-----BEGIN VALISS ACCOUNT TOKEN-----\n\n" +
        `  ${ACCOUNT_TOKEN}  \n\n------END VALISS ACCOUNT TOKEN------\ntrailing notes\n`,
    );
    expect(creds.accountToken).toBe(ACCOUNT_TOKEN);
  });

  it("rejects a version rendered with non-ASCII or malformed digits", () => {
    expect(() => parseCreds(`VALISS-CREDS-VERSION: x\n${formatCreds({ accountToken: "t" }).slice(26)}`))
      .toThrowError(expect.objectContaining({ reason: Reason.MALFORMED }));
  });

  it("maps the failure modes to the spec reasons", () => {
    expect(() => parseCreds("no markers")).toThrowError(
      expect.objectContaining({ reason: Reason.MISSING }),
    );
    expect(() =>
      parseCreds(`VALISS-CREDS-VERSION: 2\n\n-----BEGIN VALISS ACCOUNT TOKEN-----\nx\n------END VALISS ACCOUNT TOKEN------\n`),
    ).toThrowError(expect.objectContaining({ reason: Reason.UNSUPPORTED_VERSION }));
    expect(() =>
      parseCreds("-----BEGIN VALISS ACCOUNT TOKEN-----\nx\n"),
    ).toThrowError(expect.objectContaining({ reason: Reason.MALFORMED }));
  });
});
