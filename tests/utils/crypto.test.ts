import {
  sha256,
  hmacSha256,
  hkdfSha256,
  base32EncodeCrockford,
  truncateBits,
  digestToDigits,
  codeHash,
} from "../../src/utils/crypto";

function hexToBytes(hex: string): Uint8Array {
  const h = hex.replace(/^0x/, "");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

describe("crypto utils", () => {
  test("sha256 known vector", () => {
    const out = sha256("abc");
    expect(bytesToHex(out)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  });

  test("hmacSha256 known vector", () => {
    // RFC 4231 test case 1: key=0x0b*20, data="Hi There"
    const key = new Uint8Array(20).fill(0x0b);
    const data = new TextEncoder().encode("Hi There");
    const mac = hmacSha256(key, data);
    expect(bytesToHex(mac)).toBe(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
  });

  test("hmacSha256 RFC4231 test case 2", () => {
    // key = "Jefe", data = "what do ya want for nothing?"
    const key = new TextEncoder().encode("Jefe");
    const data = new TextEncoder().encode("what do ya want for nothing?");
    const mac = hmacSha256(key, data);
    expect(bytesToHex(mac)).toBe(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
  });

  test("hkdfSha256 RFC5869 test case 1", () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = hexToBytes("000102030405060708090a0b0c");
    const info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
    const okm = hkdfSha256(ikm, 42, { salt, info });
    expect(bytesToHex(okm)).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
  });

  test("hkdfSha256 basic functionality", () => {
    // Simple test to verify HKDF works correctly with @noble/hashes
    const ikm = new TextEncoder().encode("input keying material");
    const salt = new TextEncoder().encode("salt");
    const info = new TextEncoder().encode("info");
    const okm = hkdfSha256(ikm, 32, { salt, info });
    
    expect(okm).toBeInstanceOf(Uint8Array);
    expect(okm.length).toBe(32);
    
    // Deterministic - same inputs should produce same output
    const okm2 = hkdfSha256(ikm, 32, { salt, info });
    expect(bytesToHex(okm)).toBe(bytesToHex(okm2));
  });

  test("base32EncodeCrockford uses allowed alphabet and deterministic", () => {
    const data = sha256("hello");
    const a = base32EncodeCrockford(data);
    const b = base32EncodeCrockford(data);
    expect(a).toBe(b);
    expect(/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]+$/.test(a)).toBe(true);
  });

  test("base32EncodeCrockford length matches ceil(bits/5)", () => {
    const data = Uint8Array.from({ length: 7 }, (_, i) => i + 1);
    const enc = base32EncodeCrockford(data);
    const expectedLen = Math.ceil((data.length * 8) / 5);
    expect(enc.length).toBe(expectedLen);
  });

  test("truncateBits masks correctly", () => {
    const input = Uint8Array.from([0xff, 0xff]);
    const out = truncateBits(input, 9);
    expect(out.length).toBe(2);
    expect(out[1]! & 0x7f).toBe(0); // only highest bit may remain after mask 0x80
  });

  test("truncateBits grows output when requesting more bits than input", () => {
    const input = Uint8Array.from([0xaa]); // 8 bits
    const out = truncateBits(input, 12); // 12 bits => 2 bytes
    expect(out.length).toBe(2);
    expect(out[0]).toBe(0xaa);
  });

  test("digestToDigits length and digits-only", () => {
    const digest = sha256("test-digest");
    const code = digestToDigits(digest, 12);
    expect(code).toHaveLength(12);
    expect(/^[0-9]+$/.test(code)).toBe(true);
    // Deterministic
    expect(digestToDigits(digest, 12)).toBe(code);
  });

  test("digestToDigits prefix stability with longer lengths", () => {
    const d = sha256("prefix-stability");
    const a = digestToDigits(d, 8);
    const b = digestToDigits(d, 12);
    expect(b.startsWith(a)).toBe(true);
  });

  test("digestToDigits changes when digest changes", () => {
    const d1 = sha256("x");
    const d2 = sha256("y");
    expect(digestToDigits(d1, 10)).not.toBe(digestToDigits(d2, 10));
  });

  test("sha256 string vs bytes equivalence", () => {
    const s = "hello";
    const bytes = new TextEncoder().encode(s);
    expect(bytesToHex(sha256(s))).toBe(bytesToHex(sha256(bytes)));
  });

  test("hmacSha256 string vs bytes equivalence", () => {
    const keyS = "key";
    const dataS = "data";
    const keyB = new TextEncoder().encode(keyS);
    const dataB = new TextEncoder().encode(dataS);
    expect(bytesToHex(hmacSha256(keyS, dataS))).toBe(bytesToHex(hmacSha256(keyB, dataB)));
  });

  test("hkdfSha256 throws when length too large", () => {
    expect(() => hkdfSha256("ikm", 32 * 256, {})).toThrow();
  });

  test("digestToDigits throws on empty digest", () => {
    expect(() => digestToDigits(new Uint8Array(), 6)).toThrow();
  });

  test("codeHash produces consistent hex output", () => {
    const testCodes = [
      "12345678",
      "87654321", 
      "00000000",
      "99999999",
      "12345678901234567890",
      "short",
      "very-long-code-string-that-might-be-used",
    ];

    for (const code of testCodes) {
      const hash1 = codeHash(code);
      const hash2 = codeHash(code);
      
      // Should be deterministic
      expect(hash1).toBe(hash2);
      
      // Should be hex string
      expect(hash1).toMatch(/^[0-9a-f]+$/);
      
      // Should be 64 characters (SHA256 = 32 bytes = 64 hex chars)
      expect(hash1).toHaveLength(64);
    }
  });

  test("codeHash produces different hashes for different codes", () => {
    const codes = ["12345678", "87654321", "00000000", "99999999"];
    const hashes = codes.map(code => codeHash(code));
    
    // All hashes should be different
    const uniqueHashes = new Set(hashes);
    expect(uniqueHashes.size).toBe(hashes.length);
  });

  test("codeHash matches direct SHA256 implementation", () => {
    const testCodes = ["12345678", "test-code", "another-code"];
    
    for (const code of testCodes) {
      const codeHashResult = codeHash(code);
      const directSha256 = sha256(code);
      const directHex = Array.from(directSha256).map(b => b.toString(16).padStart(2, '0')).join('');
      
      expect(codeHashResult).toBe(directHex);
    }
  });

  test("codeHash handles edge cases", () => {
    const edgeCases = [
      "", // Empty string
      "a", // Single character
      "0", // Single digit
      "!@#$%^&*()", // Special characters
      "with\nnewlines", // Newlines
      "with\ttabs", // Tabs
      "with spaces", // Spaces
      "café", // Unicode
      "naïve", // Unicode with diacritics
    ];

    for (const code of edgeCases) {
      const hash = codeHash(code);
      expect(hash).toMatch(/^[0-9a-f]+$/);
      expect(hash).toHaveLength(64);
    }
  });
});
