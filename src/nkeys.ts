/**
 * Minimal Ed25519 nkeys, wire-compatible with github.com/nats-io/nkeys.
 *
 * Implements the subset valiss needs: operator (`SO...`/`O...`), account
 * (`SA...`/`A...`), and user (`SU...`/`U...`) key pairs; base32 encoding with
 * the CRC-16 checksum; signing and verification. Seeds and public keys
 * interchange byte-for-byte with the Go library.
 *
 * Crypto is WebCrypto (`globalThis.crypto.subtle`) Ed25519, available on
 * Node >= 20, modern browsers, Deno, and Bun; there are no runtime
 * dependencies. WebCrypto has no raw private-key import, so a 32-byte seed is
 * wrapped in the fixed PKCS#8 prefix for an Ed25519 private key (RFC 5958 +
 * RFC 8410) before import.
 */

import { base32Decode, base32Encode, base64UrlDecode } from "./encoding.js";
import { ValissError } from "./errors.js";

/** nkey public-prefix byte for operator keys (renders with a leading `O`). */
export const PREFIX_OPERATOR = 14 << 3; // 112
/** nkey public-prefix byte for account keys (renders with a leading `A`). */
export const PREFIX_ACCOUNT = 0;
/** nkey public-prefix byte for user keys (renders with a leading `U`). */
export const PREFIX_USER = 20 << 3; // 160
const PREFIX_SEED = 18 << 3; // 144, renders with a leading 'S'

const PUBLIC_PREFIXES: readonly number[] = [PREFIX_OPERATOR, PREFIX_ACCOUNT, PREFIX_USER];

// PKCS#8 PrivateKeyInfo prefix for a raw 32-byte Ed25519 private key:
// SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING (32 bytes) } }.
const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

const ED25519 = "Ed25519";

/** CRC-16 CCITT/XMODEM (polynomial 0x1021, init 0x0000), the nkeys checksum. */
function crc16(data: Uint8Array): number {
  let crc = 0;
  for (const byte of data) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = (crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1) & 0xffff;
    }
  }
  return crc;
}

function withChecksum(raw: Uint8Array): string {
  const out = new Uint8Array(raw.length + 2);
  out.set(raw);
  const crc = crc16(raw);
  out[raw.length] = crc & 0xff;
  out[raw.length + 1] = crc >>> 8;
  return base32Encode(out);
}

function checkedDecode(encoded: string): Uint8Array {
  let raw: Uint8Array;
  try {
    raw = base32Decode(encoded);
  } catch (err) {
    throw new ValissError(`valiss: invalid nkey encoding: ${(err as Error).message}`);
  }
  if (raw.length < 4) throw new ValissError("valiss: invalid nkey: too short");
  const data = raw.subarray(0, raw.length - 2);
  const crc = raw[raw.length - 2]! | (raw[raw.length - 1]! << 8);
  if (crc16(data) !== crc) throw new ValissError("valiss: invalid nkey: checksum mismatch");
  return data;
}

/** Render a 32-byte Ed25519 public key as an nkey public-key string. */
export function encodePublic(prefix: number, rawKey: Uint8Array): string {
  if (!PUBLIC_PREFIXES.includes(prefix)) {
    throw new ValissError("valiss: invalid nkey public prefix");
  }
  if (rawKey.length !== 32) throw new ValissError("valiss: invalid nkey public key length");
  const raw = new Uint8Array(33);
  raw[0] = prefix;
  raw.set(rawKey, 1);
  return withChecksum(raw);
}

/** Render a 32-byte Ed25519 seed as an nkey seed string (`S...`). */
export function encodeSeed(publicPrefix: number, rawSeed: Uint8Array): string {
  if (!PUBLIC_PREFIXES.includes(publicPrefix)) {
    throw new ValissError("valiss: invalid nkey public prefix");
  }
  if (rawSeed.length !== 32) throw new ValissError("valiss: invalid nkey seed length");
  const raw = new Uint8Array(34);
  raw[0] = PREFIX_SEED | (publicPrefix >>> 5);
  raw[1] = (publicPrefix & 31) << 3;
  raw.set(rawSeed, 2);
  return withChecksum(raw);
}

/**
 * Decode an nkey public-key string into its prefix byte and 32-byte Ed25519
 * public key: base32-decode to exactly 35 bytes, verify the trailing CRC-16
 * over the first 33, and require a public-role prefix (spec §3.6).
 */
export function decodePublic(encoded: string): { prefix: number; key: Uint8Array } {
  const data = checkedDecode(encoded);
  if (data.length !== 33) throw new ValissError("valiss: invalid nkey public key length");
  const prefix = data[0]!;
  if (!PUBLIC_PREFIXES.includes(prefix)) throw new ValissError("valiss: not a public nkey");
  return { prefix, key: data.subarray(1) };
}

/**
 * Decode an nkey seed string into the public prefix byte it derives keys for
 * and the raw 32-byte Ed25519 seed.
 */
export function decodeSeed(encoded: string): { prefix: number; seed: Uint8Array } {
  const data = checkedDecode(encoded);
  if (data.length < 4) throw new ValissError("valiss: invalid nkey seed: too short");
  if ((data[0]! & 0xf8) !== PREFIX_SEED) throw new ValissError("valiss: not an nkey seed");
  const prefix = ((data[0]! & 7) << 5) | ((data[1]! & 0xf8) >>> 3);
  if (!PUBLIC_PREFIXES.includes(prefix)) {
    throw new ValissError("valiss: invalid nkey seed prefix");
  }
  if (data.length - 2 !== 32) throw new ValissError("valiss: invalid nkey seed length");
  return { prefix, seed: data.subarray(2) };
}

function isValidPublic(encoded: string, prefix: number): boolean {
  try {
    return decodePublic(encoded).prefix === prefix;
  } catch {
    return false;
  }
}

/** Whether a string is a well-formed operator public nkey (`O...`). */
export function isValidPublicOperatorKey(encoded: string): boolean {
  return isValidPublic(encoded, PREFIX_OPERATOR);
}

/** Whether a string is a well-formed account public nkey (`A...`). */
export function isValidPublicAccountKey(encoded: string): boolean {
  return isValidPublic(encoded, PREFIX_ACCOUNT);
}

/** Whether a string is a well-formed user public nkey (`U...`). */
export function isValidPublicUserKey(encoded: string): boolean {
  return isValidPublic(encoded, PREFIX_USER);
}

/** An nkey pair. Verify-only when built from a public key. */
export class KeyPair {
  readonly #prefix: number;
  readonly #publicRaw: Uint8Array;
  readonly #privateKey: CryptoKey | undefined;
  readonly #seedRaw: Uint8Array | undefined;
  #verifyKey: Promise<CryptoKey> | undefined;

  /** @internal use {@link fromSeed}, {@link fromPublicKey}, or the create functions. */
  constructor(
    prefix: number,
    publicRaw: Uint8Array,
    privateKey?: CryptoKey,
    seedRaw?: Uint8Array,
  ) {
    this.#prefix = prefix;
    this.#publicRaw = publicRaw;
    this.#privateKey = privateKey;
    this.#seedRaw = seedRaw;
  }

  /** The nkey-encoded public key (`O...`, `A...`, or `U...`). */
  get publicKey(): string {
    return encodePublic(this.#prefix, this.#publicRaw);
  }

  /** The raw 32-byte Ed25519 public key. */
  get publicRaw(): Uint8Array {
    return this.#publicRaw.slice();
  }

  /** The nkey-encoded seed (`SO...`, `SA...`, or `SU...`); throws for verify-only pairs. */
  get seed(): string {
    if (this.#seedRaw === undefined) {
      throw new ValissError("valiss: key pair holds no seed");
    }
    return encodeSeed(this.#prefix, this.#seedRaw);
  }

  /** Raw 64-byte Ed25519 signature of `data`; throws for verify-only pairs. */
  async sign(data: Uint8Array): Promise<Uint8Array> {
    if (this.#privateKey === undefined) {
      throw new ValissError("valiss: key pair cannot sign: no seed");
    }
    return new Uint8Array(
      await crypto.subtle.sign(ED25519, this.#privateKey, data as BufferSource),
    );
  }

  /** Verify a raw Ed25519 signature over `data`; throws {@link ValissError} on failure. */
  async verify(data: Uint8Array, signature: Uint8Array): Promise<void> {
    let ok: boolean;
    try {
      this.#verifyKey ??= crypto.subtle.importKey(
        "raw",
        this.#publicRaw as BufferSource,
        ED25519,
        false,
        ["verify"],
      );
      ok = await crypto.subtle.verify(
        ED25519,
        await this.#verifyKey,
        signature as BufferSource,
        data as BufferSource,
      );
    } catch {
      ok = false;
    }
    if (!ok) throw new ValissError("valiss: signature verification failed");
  }
}

async function pairOf(prefix: number, seedRaw: Uint8Array): Promise<KeyPair> {
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
  pkcs8.set(PKCS8_ED25519_PREFIX);
  pkcs8.set(seedRaw, PKCS8_ED25519_PREFIX.length);
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8 as BufferSource,
    ED25519,
    true,
    ["sign"],
  );
  // WebCrypto exposes the derived public key only through JWK export (x).
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  if (typeof jwk.x !== "string") {
    throw new ValissError("valiss: Ed25519 public key derivation failed");
  }
  return new KeyPair(prefix, base64UrlDecode(jwk.x), privateKey, seedRaw);
}

/** Build a signing key pair from an nkey seed string. */
export async function fromSeed(seed: string): Promise<KeyPair> {
  const decoded = decodeSeed(seed.trim());
  return pairOf(decoded.prefix, decoded.seed);
}

/** Build a verify-only key pair from an nkey public-key string. */
export function fromPublicKey(encoded: string): KeyPair {
  const decoded = decodePublic(encoded);
  return new KeyPair(decoded.prefix, decoded.key);
}

function create(prefix: number): Promise<KeyPair> {
  const seedRaw = crypto.getRandomValues(new Uint8Array(32));
  return pairOf(prefix, seedRaw);
}

/** Generate a fresh operator key pair. */
export function createOperator(): Promise<KeyPair> {
  return create(PREFIX_OPERATOR);
}

/** Generate a fresh account key pair. */
export function createAccount(): Promise<KeyPair> {
  return create(PREFIX_ACCOUNT);
}

/** Generate a fresh user key pair. */
export function createUser(): Promise<KeyPair> {
  return create(PREFIX_USER);
}
