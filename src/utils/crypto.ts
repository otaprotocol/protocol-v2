import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { hkdf } from "@noble/hashes/hkdf.js";

function toBytes(input: Uint8Array | string): Uint8Array {
  if (typeof input === "string") return new TextEncoder().encode(input);
  return input;
}

export function sha256(data: Uint8Array | string): Uint8Array {
  return nobleSha256(toBytes(data));
}

export function hmacSha256(
  key: Uint8Array | string,
  data: Uint8Array | string
): Uint8Array {
  return hmac(nobleSha256, toBytes(key), toBytes(data));
}

// HKDF implementation using @noble/hashes
export function hkdfSha256(
  ikm: Uint8Array | string,
  length: number,
  {
    salt,
    info,
  }: { salt?: Uint8Array | string; info?: Uint8Array | string } = {}
): Uint8Array {
  const saltBuf = salt ? toBytes(salt) : new Uint8Array(32);
  const ikmBuf = toBytes(ikm);
  const infoBuf = info ? toBytes(info) : new Uint8Array(0);

  return hkdf(nobleSha256, ikmBuf, saltBuf, infoBuf, length);
}

// Crockford Base32 without lookalikes (I L O U mapped) – output uppercase
const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function base32EncodeCrockford(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (let i = 0; i < data.length; i++) {
    value = (value << 8) | data[i]!;
    bits += 8;
    while (bits >= 5) {
      output += CROCKFORD_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += CROCKFORD_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function truncateBits(input: Uint8Array, totalBits: number): Uint8Array {
  const totalBytes = Math.ceil(totalBits / 8);
  const out = new Uint8Array(totalBytes);
  const copyBytes = Math.min(totalBytes, input.length);
  out.set(input.subarray(0, copyBytes));
  // If not byte-aligned, mask the last byte
  const extraBits = totalBytes * 8 - totalBits;
  if (extraBits > 0) {
    const mask = 0xff << extraBits;
    out[totalBytes - 1] = out[totalBytes - 1]! & mask;
  }
  return out;
}

// Derive digits-only code from a digest using modulo bias-reduction (HOTP-style per-digit)
export function digestToDigits(digest: Uint8Array, length: number): string {
  if (digest.length === 0) throw new Error("digestToDigits: empty digest");
  // HOTP-like dynamic truncation for unbiased decimal extraction
  // Process 4 bytes windows to produce digits
  let out = "";
  const offset = digest[digest.length - 1]! & 0x0f;
  for (let i = 0; out.length < length; i++) {
    const idx = (offset + i * 4) % Math.max(1, digest.length - 4);
    const p =
      ((digest[idx]! & 0x7f) << 24) |
      (digest[idx + 1]! << 16) |
      (digest[idx + 2]! << 8) |
      digest[idx + 3]!;
    const num = p % 1000000000; // up to 9 digits
    const chunk = num.toString().padStart(9, "0");
    out += chunk;
  }
  return out.slice(0, length);
}

// Generate a SHA256 hash of a code string for use as a unique identifier
export function codeHash(code: string): string {
  const hash = sha256(code);
  return Array.from(hash)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Generate a cryptographically secure random secret
export function generateRandomSecret(): string {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  return btoa(String.fromCharCode(...randomBytes));
}
