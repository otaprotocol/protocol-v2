import { serializeCanonical } from "../../src/utils/canonical";
import type { CanonicalMessageParts } from "../../src/types";

// Helper function to convert Uint8Array to string for comparison
function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// Helper function to convert string to hex for debugging
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("canonical utils", () => {
  test("serializeCanonical basic functionality", () => {
    const parts: CanonicalMessageParts = {
      pubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      windowStart: 1695800000000,
    };

    const result = serializeCanonical(parts);
    
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBeGreaterThan(0);
    
    const jsonString = bytesToString(result);
    expect(jsonString).toContain('"pubkey":"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"');
    expect(jsonString).toContain('"windowStart":1695800000000');
  });

  test("serializeCanonical deterministic output", () => {
    const parts: CanonicalMessageParts = {
      pubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      windowStart: 1695800000000,
    };

    const result1 = serializeCanonical(parts);
    const result2 = serializeCanonical(parts);
    
    expect(result1).toEqual(result2);
    expect(bytesToHex(result1)).toBe(bytesToHex(result2));
  });

  test("serializeCanonical different inputs produce different outputs", () => {
    const parts1: CanonicalMessageParts = {
      pubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      windowStart: 1695800000000,
    };

    const parts2: CanonicalMessageParts = {
      pubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      windowStart: 1695800000001, // Different timestamp
    };

    const parts3: CanonicalMessageParts = {
      pubkey: "DifferentPubkey123456789012345678901234567890",
      windowStart: 1695800000000,
    };

    const result1 = serializeCanonical(parts1);
    const result2 = serializeCanonical(parts2);
    const result3 = serializeCanonical(parts3);

    expect(result1).not.toEqual(result2);
    expect(result1).not.toEqual(result3);
    expect(result2).not.toEqual(result3);
  });

  test("serializeCanonical handles different pubkey formats", () => {
    const testCases = [
      "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", // Base58
      "0x1234567890abcdef1234567890abcdef12345678", // Hex
      "user@example.com", // Email-like
      "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", // DID
    ];

    const results = testCases.map((pubkey) => {
      const parts: CanonicalMessageParts = {
        pubkey,
        windowStart: 1695800000000,
      };
      return serializeCanonical(parts);
    });

    // All should be different
    for (let i = 0; i < results.length; i++) {
      for (let j = i + 1; j < results.length; j++) {
        expect(results[i]).not.toEqual(results[j]);
      }
    }
  });

  test("serializeCanonical handles different timestamps", () => {
    const timestamps = [
      0, // Epoch
      1000000000000, // 2001
      1600000000000, // 2020
      1695800000000, // 2023
      2000000000000, // 2033
      Number.MAX_SAFE_INTEGER, // Max safe integer
    ];

    const results = timestamps.map((windowStart) => {
      const parts: CanonicalMessageParts = {
        pubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        windowStart,
      };
      return serializeCanonical(parts);
    });

    // All should be different
    for (let i = 0; i < results.length; i++) {
      for (let j = i + 1; j < results.length; j++) {
        expect(results[i]).not.toEqual(results[j]);
      }
    }
  });

  test("serializeCanonical produces valid JSON", () => {
    const parts: CanonicalMessageParts = {
      pubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      windowStart: 1695800000000,
    };

    const result = serializeCanonical(parts);
    const jsonString = bytesToString(result);
    
    // Should be valid JSON
    expect(() => JSON.parse(jsonString)).not.toThrow();
    
    const parsed = JSON.parse(jsonString);
    expect(parsed).toEqual({
      pubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      windowStart: 1695800000000,
      id: 'actioncodes',
      ver: 1,
    });
  });

  test("serializeCanonical handles edge cases", () => {
    const edgeCases = [
      {
        pubkey: "", // Empty string
        windowStart: 0,
      },
      {
        pubkey: "a", // Single character
        windowStart: 1,
      },
      {
        pubkey: "🚀", // Unicode emoji
        windowStart: 1695800000000,
      },
      {
        pubkey: "a".repeat(1000), // Very long string
        windowStart: 1695800000000,
      },
    ];

    edgeCases.forEach((parts, index) => {
      expect(() => {
        const result = serializeCanonical(parts);
        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBeGreaterThan(0);
        
        // Should produce valid JSON
        const jsonString = bytesToString(result);
        const parsed = JSON.parse(jsonString);
        expect(parsed.pubkey).toBe(parts.pubkey);
        expect(parsed.windowStart).toBe(parts.windowStart);
      }).not.toThrow(`Edge case ${index} should not throw`);
    });
  });

  test("serializeCanonical maintains field order", () => {
    const parts: CanonicalMessageParts = {
      pubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      windowStart: 1695800000000,
    };

    const result = serializeCanonical(parts);
    const jsonString = bytesToString(result);
    
    // Should maintain consistent field order (pubkey first, then windowStart)
    const pubkeyIndex = jsonString.indexOf('"pubkey"');
    const windowStartIndex = jsonString.indexOf('"windowStart"');
    
    expect(pubkeyIndex).toBeLessThan(windowStartIndex);
  });

  test("serializeCanonical handles special characters in pubkey", () => {
    const specialPubkeys = [
      "key with spaces",
      "key-with-dashes",
      "key_with_underscores",
      "key.with.dots",
      "key/with/slashes",
      "key\\with\\backslashes",
      "key\"with\"quotes",
      "key'with'apostrophes",
      "key\nwith\nnewlines",
      "key\twith\ttabs",
    ];

    specialPubkeys.forEach((pubkey) => {
      const parts: CanonicalMessageParts = {
        pubkey,
        windowStart: 1695800000000,
      };
      
      expect(() => {
        const result = serializeCanonical(parts);
        expect(result).toBeInstanceOf(Uint8Array);
        
        // Should produce valid JSON
        const jsonString = bytesToString(result);
        const parsed = JSON.parse(jsonString);
        expect(parsed.pubkey).toBe(pubkey);
      }).not.toThrow(`Special pubkey "${pubkey}" should not throw`);
    });
  });

  test("serializeCanonical produces consistent byte length for same input", () => {
    const parts: CanonicalMessageParts = {
      pubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      windowStart: 1695800000000,
    };

    const results = Array.from({ length: 10 }, () => serializeCanonical(parts));
    
    // All results should have the same length
    const lengths = results.map(r => r.length);
    const uniqueLengths = new Set(lengths);
    expect(uniqueLengths.size).toBe(1);
    
    // All results should be identical
    results.forEach((result, index) => {
      if (index > 0) {
        expect(result).toEqual(results[0]);
      }
    });
  });
});
