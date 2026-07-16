/**
 * Byte-level encodings of the valiss wire formats: RFC 4648 base32 (uppercase
 * alphabet, no padding) for nkeys and jti, base64url (no padding) for token
 * parts, base64std (padded) for request signatures, and lowercase hex for
 * digests. Decoders are hand-rolled so they are exactly as strict as the Go
 * reference (`encoding/base32`, `encoding/base64`): a character outside the
 * alphabet, misplaced padding, or an impossible length rejects. Runs on any
 * runtime with WebCrypto (`globalThis.crypto.subtle`): Node >= 20, modern
 * browsers, Deno, Bun.
 */

import { ValissError } from "./errors.js";

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B64_STD_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function reverse(alphabet: string): Int16Array {
  const rev = new Int16Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i++) rev[alphabet.charCodeAt(i)] = i;
  return rev;
}

const B32_REV = reverse(B32_ALPHABET);
const B64_STD_REV = reverse(B64_STD_ALPHABET);
const B64_URL_REV = reverse(B64_URL_ALPHABET);

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

/** UTF-8 bytes of a string. */
export function utf8Encode(s: string): Uint8Array {
  return utf8Encoder.encode(s);
}

/** String of UTF-8 bytes; invalid UTF-8 throws. */
export function utf8Decode(data: Uint8Array): string {
  return utf8Decoder.decode(data);
}

/** RFC 4648 base32, uppercase alphabet, no padding. */
export function base32Encode(data: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of data) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(buffer << (5 - bits)) & 31];
  return out;
}

/** Strict RFC 4648 base32 decode: uppercase alphabet only, no padding. */
export function base32Decode(encoded: string): Uint8Array {
  const out = new Uint8Array(Math.floor((encoded.length * 5) / 8));
  let buffer = 0;
  let bits = 0;
  let n = 0;
  for (let i = 0; i < encoded.length; i++) {
    const c = encoded.charCodeAt(i);
    const v = c < 128 ? (B32_REV[c] as number) : -1;
    if (v < 0) throw new ValissError("valiss: invalid base32 encoding");
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out[n++] = (buffer >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return out;
}

function b64Decode(body: string, rev: Int16Array): Uint8Array {
  if (body.length % 4 === 1) throw new ValissError("valiss: invalid base64 length");
  const out = new Uint8Array(Math.floor((body.length * 6) / 8));
  let buffer = 0;
  let bits = 0;
  let n = 0;
  for (let i = 0; i < body.length; i++) {
    const c = body.charCodeAt(i);
    const v = c < 128 ? (rev[c] as number) : -1;
    if (v < 0) throw new ValissError("valiss: invalid base64 encoding");
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      out[n++] = (buffer >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return out;
}

function b64Encode(data: Uint8Array, alphabet: string, pad: boolean): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of data) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      out += alphabet[(buffer >>> (bits - 6)) & 63];
      bits -= 6;
    }
  }
  if (bits > 0) out += alphabet[(buffer << (6 - bits)) & 63];
  if (pad) while (out.length % 4 !== 0) out += "=";
  return out;
}

/** RFC 4648 base64 with the URL-safe alphabet, no padding (Go RawURLEncoding). */
export function base64UrlEncode(data: Uint8Array): string {
  return b64Encode(data, B64_URL_ALPHABET, false);
}

/**
 * Strict base64url (no padding) decode, matching Go `base64.RawURLEncoding`:
 * a character outside the base64url alphabet (including the standard alphabet
 * `+`/`/` and any `=` padding) or an impossible length rejects.
 */
export function base64UrlDecode(encoded: string): Uint8Array {
  return b64Decode(encoded, B64_URL_REV);
}

/** RFC 4648 base64 with the standard alphabet and padding (Go StdEncoding). */
export function base64StdEncode(data: Uint8Array): string {
  return b64Encode(data, B64_STD_ALPHABET, true);
}

/**
 * Strict base64std (padded) decode, matching Go `base64.StdEncoding`: the
 * length must be a multiple of four with `=` padding only at the end.
 */
export function base64StdDecode(encoded: string): Uint8Array {
  if (encoded.length % 4 !== 0) {
    throw new ValissError("valiss: invalid base64 length");
  }
  let body = encoded;
  let pad = 0;
  while (pad < 2 && body.length > 0 && body.endsWith("=")) {
    body = body.slice(0, -1);
    pad++;
  }
  if (body.includes("=")) throw new ValissError("valiss: invalid base64 padding");
  return b64Decode(body, B64_STD_REV);
}

const HEX = "0123456789abcdef";

/** Lowercase hexadecimal rendering of bytes. */
export function hexEncode(data: Uint8Array): string {
  let out = "";
  for (const byte of data) out += HEX[byte >>> 4]! + HEX[byte & 15]!;
  return out;
}

/** SHA-256 digest (FIPS 180-4) via WebCrypto. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}
