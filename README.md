# valiss-ts

TypeScript/JavaScript implementation of the **valiss** authentication scheme:
offline-verifiable delegated tenant authentication over Ed25519 nkeys.

This library implements **wire spec 1** (`SPEC-1`) of the valiss scheme. The
Go implementation (`valiss-go`) is the reference; this port is wire-compatible
with it byte for byte, including the content-derived `jti` (which requires
reproducing Go `encoding/json` serialization exactly) and the nkey text
format.

## Status

Foundation: the core wire layer.

- **nkeys** — operator/account/user Ed25519 key pairs in the NATS nkey text
  format (base32 + CRC-16), seed and public-key interchange with the Go and
  Python implementations.
- **Tokens** — mint and verify operator, account, user, and message tokens
  (nkey-signed JWTs, `ed25519-nkey`), with version dispatch before payload
  parse and mandatory signature verification (ADR 0009).
- **Credentials files** — `VALISS-CREDS-VERSION` container format/parse.
- **Request signatures** — `valiss-req-v1` signed bytes, RFC 3339 nanosecond
  UTC timestamps, symmetric skew window.
- **Message verification** — the full chain walk of SPEC-1 §6.12: self-signed
  check, embedded/supplied chain, epoch agreement, validity windows, audience
  and checksum bindings.

Failures throw `ValissError`; its `reason` property carries the stable SPEC-1
§7 reason code.

Not yet here (planned, additive): the full request verifier (allowlist,
keyring, resolver, replay cache) and transport/framework adapters, which will
ship as subpath exports (for example `valiss/express`, `valiss/fetch`).

## Conformance

The frozen spec-1 conformance vectors are vendored under `test/vectors/`
(verbatim copy of `valiss-dev/spec` `vectors/` at commit
`06958028e198181cec25dac38193ec100e929192`). The runner in
`test/conformance.test.ts` enforces the vectors' runner contract; **all 54
cases pass**. `npm test` runs them together with the unit suite, which also
locks the mint path to a token minted by the Go reference, byte for byte.

## Requirements

Node.js >= 20, or any runtime with WebCrypto Ed25519
(`globalThis.crypto.subtle`): modern browsers, Deno, Bun. There are no runtime
dependencies.

## Usage

```ts
import {
  nkeys,
  issueAccount,
  issueUser,
  verifyUser,
  signRequest,
  verifySignature,
} from "valiss";

// Operator signs a tenant an account token; the tenant delegates to a user.
const operator = await nkeys.fromSeed(process.env.OPERATOR_SEED!);
const account = await nkeys.createAccount();
const accountToken = await issueAccount(operator, "acme", account.publicKey, {
  ttlMs: 30 * 24 * 3600 * 1000,
});

const user = await nkeys.createUser();
const userToken = await issueUser(account, "alice", user.publicKey);

// The user proves possession per request.
const context = "http\nGET\napi.example.com\n/v1/widgets\n";
const { timestamp, signature } = await signRequest(user, context);

// The server side (given the delegating account key).
const claims = await verifyUser(userToken, account.publicKey);
await verifySignature(claims.subject, timestamp, signature, context);
```

## Development

```sh
npm install
npm test        # unit tests + the 54 conformance vectors
npm run typecheck
npm run build   # emits ESM + d.ts to dist/
```

## Known deviations

Both are edge cases outside anything the spec's claims can produce today, and
both fail closed:

- `epoch` is a `uint64` on the wire; values above `Number.MAX_SAFE_INTEGER`
  (2^53 - 1) cannot round-trip through a JS number, so such a token is
  rejected as `malformed` rather than silently mangled.
- Go escapes `\b`/`\f` in JSON strings as `\u0008`/`\u000c` while
  `JSON.stringify` uses `\b`/`\f`. A *name* containing those control
  characters would derive a different `jti` here than in Go (the Python port
  shares this divergence). Signature verification is unaffected: it always
  runs over the received bytes.

## License

MIT
