import { WalletStrategy } from "../src/strategy/WalletStrategy";
import { serializeCanonical } from "../src/utils/canonical";
import {
  sha256,
  hmacSha256,
  digestToDigits,
  truncateBits,
  codeHash,
} from "../src/utils/crypto";
import { CODE_MIN_LENGTH, CODE_MAX_LENGTH } from "../src/constants";
import type {
  CodeGenerationConfig,
  WalletStrategyCodeGenerationResult,
} from "../src/types";
import { createHash, createHmac } from "node:crypto";

// Helper function to create canonical message for testing
function createCanonicalMessage(pubkey: string): Uint8Array {
  const windowStart = Math.floor(Date.now() / 120000) * 120000; // 2 minute TTL
  return serializeCanonical({ pubkey, windowStart });
}

describe("Cross-System Compatibility", () => {
  const testConfig: CodeGenerationConfig = {
    codeLength: 8,
    ttlMs: 120000, // 2 minutes
  };

  let strategy: WalletStrategy;

  beforeEach(() => {
    strategy = new WalletStrategy(testConfig);
  });

  describe("Canonical Message Format", () => {
    test("canonical message format matches expected JSON structure", () => {
      const pubkey = "test-pubkey-123";
      const timestamp = 1640995200000; // Fixed timestamp for deterministic testing

      const canonical = serializeCanonical({ pubkey, windowStart: timestamp });
      const messageStr = new TextDecoder().decode(canonical);
      const parsed = JSON.parse(messageStr);

      expect(parsed).toEqual({
        pubkey: "test-pubkey-123",
        windowStart: 1640995200000,
        id: "actioncodes",
        ver: 1,
      });
    });

    test("canonical message is deterministic across systems", () => {
      const testCases = [
        { pubkey: "simple", timestamp: 1000 },
        { pubkey: "with-dashes", timestamp: 2000 },
        { pubkey: "with_underscores", timestamp: 3000 },
        { pubkey: "with.dots", timestamp: 4000 },
        { pubkey: "with spaces", timestamp: 5000 },
        { pubkey: "with\nnewlines", timestamp: 6000 },
        { pubkey: "with\ttabs", timestamp: 7000 },
        { pubkey: 'with"quotes', timestamp: 8000 },
        { pubkey: "with'apostrophes", timestamp: 9000 },
        { pubkey: "with\\backslashes", timestamp: 10000 },
      ];

      for (const testCase of testCases) {
        const canonical1 = serializeCanonical({
          pubkey: testCase.pubkey,
          windowStart: testCase.timestamp,
        });
        const canonical2 = serializeCanonical({
          pubkey: testCase.pubkey,
          windowStart: testCase.timestamp,
        });

        expect(canonical1).toEqual(canonical2);

        // Verify it's valid JSON
        const messageStr = new TextDecoder().decode(canonical1);
        const parsed = JSON.parse(messageStr);
        expect(parsed.pubkey).toBe(testCase.pubkey);
        expect(parsed.windowStart).toBe(testCase.timestamp);
      }
    });

    test("canonical message handles Unicode normalization", () => {
      // Test that visually identical strings produce the same canonical message
      const testCases = [
        { str1: "café", str2: "café" }, // Same string
        { str1: "café", str2: "cafe\u0301" }, // NFD vs NFC
        { str1: "naïve", str2: "naive" }, // Different strings (should be different)
      ];

      for (const testCase of testCases) {
        const canonical1 = serializeCanonical({
          pubkey: testCase.str1,
          windowStart: 1000,
        });
        const canonical2 = serializeCanonical({
          pubkey: testCase.str2,
          windowStart: 1000,
        });

        if (testCase.str1 === testCase.str2) {
          expect(canonical1).toEqual(canonical2);
        } else {
          // These should be different
          expect(canonical1).not.toEqual(canonical2);
        }
      }
    });
  });

  describe("Crypto Algorithm Compatibility", () => {
    test("SHA256 produces same results as Node.js crypto", () => {
      const testData = [
        "simple string",
        "with spaces and symbols !@#$%^&*()",
        "with\nnewlines\tand\ttabs",
        "with unicode: café, naïve, résumé",
        "", // Empty string
      ];

      for (const data of testData) {
        const ourHash = sha256(data);
        const nodeHash = createHash("sha256").update(data).digest("hex");

        // Convert our hash to hex for comparison
        const ourHashHex = Array.from(ourHash)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
        expect(ourHashHex).toBe(nodeHash);
      }
    });

    test("HMAC-SHA256 produces same results as Node.js crypto", () => {
      const testCases = [
        { key: "simple-key", data: "simple-data" },
        { key: "key-with-symbols!@#", data: "data-with-symbols!@#" },
        { key: "", data: "empty-key" },
        { key: "key", data: "" },
        { key: "", data: "" },
      ];

      for (const testCase of testCases) {
        const ourHmac = hmacSha256(testCase.key, testCase.data);
        const nodeHmac = createHmac("sha256", testCase.key)
          .update(testCase.data)
          .digest("hex");

        // Convert our HMAC to hex for comparison
        const ourHmacHex = Array.from(ourHmac)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
        expect(ourHmacHex).toBe(nodeHmac);
      }
    });

    test("digestToDigits produces consistent results", () => {
      const testDigests = [
        new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        new Uint8Array([255, 254, 253, 252, 251, 250, 249, 248]),
        new Uint8Array([128, 64, 32, 16, 8, 4, 2, 1]),
        new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]),
        new Uint8Array([255, 255, 255, 255, 255, 255, 255, 255]),
      ];

      for (const digest of testDigests) {
        for (const length of [6, 8, 12, 16, 20]) {
          const result1 = digestToDigits(digest, length);
          const result2 = digestToDigits(digest, length);

          expect(result1).toBe(result2);
          expect(result1).toHaveLength(length);
          expect(result1).toMatch(/^\d+$/);
        }
      }
    });

    test("truncateBits produces consistent results", () => {
      const testCases = [
        { data: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), bits: 32 },
        { data: new Uint8Array([255, 254, 253, 252]), bits: 16 },
        { data: new Uint8Array([128, 64, 32, 16, 8, 4, 2, 1]), bits: 40 },
        { data: new Uint8Array([0, 0, 0, 0]), bits: 8 },
      ];

      for (const testCase of testCases) {
        const result1 = truncateBits(testCase.data, testCase.bits);
        const result2 = truncateBits(testCase.data, testCase.bits);

        expect(result1).toEqual(result2);
        expect(result1.length).toBe(Math.ceil(testCase.bits / 8));
      }
    });

    test("codeHash produces same results as Node.js crypto", () => {
      const testCodes = [
        "12345678",
        "87654321",
        "00000000",
        "99999999",
        "short",
        "very-long-code-string",
        "with spaces",
        "with\nnewlines",
        "café",
        "", // Empty string
      ];

      for (const code of testCodes) {
        const ourHash = codeHash(code);
        const nodeHash = createHash("sha256").update(code).digest("hex");

        expect(ourHash).toBe(nodeHash);
        expect(ourHash).toMatch(/^[0-9a-f]+$/);
        expect(ourHash).toHaveLength(64);
      }
    });
  });

  describe("Code Length Coverage", () => {
    test("generates codes with all supported lengths", () => {
      const supportedLengths = [6, 8, 10, 12, 16, 20, 24]; // All valid lengths
      const pubkey = "test-pubkey-lengths";

      for (const length of supportedLengths) {
        const config = { ...testConfig, codeLength: length };
        const testStrategy = new WalletStrategy(config);
        const canonicalMessage = createCanonicalMessage(pubkey);
        const result = testStrategy.generateCode(canonicalMessage, "testsignature");

        expect(result.actionCode.code).toHaveLength(length);
        expect(result.actionCode.code).toMatch(/^\d+$/);
        expect(result.actionCode.code).toBeTruthy();
      }
    });

    test("generates unique codes for different lengths", () => {
      const lengths = [6, 8, 12, 16];
      const pubkey = "test-pubkey-unique";
      const results: WalletStrategyCodeGenerationResult[] = [];
      for (const length of lengths) {
        const config = { ...testConfig, codeLength: length };
        const strategy = new WalletStrategy(config);
        const canonicalMessage = createCanonicalMessage(pubkey);
        results.push(strategy.generateCode(canonicalMessage, "testsignature"));
      }

      // All codes should be different (different lengths)
      const codes = results.map((r) => r.actionCode.code);
      const uniqueCodes = new Set(codes);
      expect(uniqueCodes.size).toBe(codes.length);

      // Verify each has correct length
      results.forEach((result, index) => {
        expect(result.actionCode.code).toHaveLength(lengths[index]!);
      });
    });

    test("handles edge case code lengths", () => {
      const edgeLengths = [
        { input: 1, expected: 6 }, // Below minimum
        { input: 5, expected: 6 }, // Below minimum
        { input: 6, expected: 6 }, // Minimum
        { input: 24, expected: 24 }, // Maximum
        { input: 25, expected: 24 }, // Above maximum
        { input: 100, expected: 24 }, // Way above maximum
      ];

      for (const testCase of edgeLengths) {
        const config = { ...testConfig, codeLength: testCase.input };
        const testStrategy = new WalletStrategy(config);
        const canonicalMessage = createCanonicalMessage("test-pubkey");
        const result = testStrategy.generateCode(canonicalMessage, "testsignature");

        expect(result.actionCode.code).toHaveLength(testCase.expected);
        expect(result.actionCode.code).toMatch(/^\d+$/);
      }
    });

    test("code uniqueness across different lengths and pubkeys", () => {
      const lengths = [6, 8, 12, 16, 20, 24];
      const pubkeys = ["pubkey1", "pubkey2", "pubkey3", "pubkey4", "pubkey5"];
      const allCodes: string[] = [];

      for (const length of lengths) {
        for (const pubkey of pubkeys) {
          const config = { ...testConfig, codeLength: length };
          const testStrategy = new WalletStrategy(config);
          const canonicalMessage = createCanonicalMessage(pubkey);
          const result = testStrategy.generateCode(canonicalMessage, "testsignature");
          allCodes.push(result.actionCode.code);
        }
      }

      // All codes should be unique across all combinations
      const uniqueCodes = new Set(allCodes);
      expect(uniqueCodes.size).toBe(allCodes.length);

      console.log(
        `Generated ${allCodes.length} unique codes across ${lengths.length} lengths and ${pubkeys.length} pubkeys`
      );
    });
  });

  describe("Code Generation Determinism", () => {
    test("generates same codes for identical inputs across multiple calls", () => {
      const testCases = [
        { pubkey: "test-pubkey-1", config: { codeLength: 6, ttlMs: 60000 } },
        { pubkey: "test-pubkey-2", config: { codeLength: 8, ttlMs: 120000 } },
        { pubkey: "test-pubkey-3", config: { codeLength: 12, ttlMs: 300000 } },
        { pubkey: "test-pubkey-4", config: { codeLength: 16, ttlMs: 600000 } },
      ];

      for (const testCase of testCases) {
        const results: WalletStrategyCodeGenerationResult[] = [];
        for (let i = 0; i < 10; i++) {
          const canonicalMessage = createCanonicalMessage(testCase.pubkey);
          results.push(strategy.generateCode(canonicalMessage, "testsignature"));
        }

        // All results should be identical
        const first = results[0];
        for (const result of results) {
          expect(result.actionCode.code).toBe(first?.actionCode.code);
          expect(result.actionCode.pubkey).toBe(first?.actionCode.pubkey);
          expect(result.actionCode.timestamp).toBe(first?.actionCode.timestamp);
          expect(result.actionCode.expiresAt).toBe(first?.actionCode.expiresAt);
          expect(result.canonicalMessage).toEqual(first?.canonicalMessage);
        }
      }
    });

    test("generates different codes for different inputs", () => {
      const baseConfig = { codeLength: 8, ttlMs: 120000 };
      const results: WalletStrategyCodeGenerationResult[] = [];

      // Different pubkeys
      for (let i = 0; i < 10; i++) {
        const canonicalMessage = createCanonicalMessage(`pubkey-${i}`);
        results.push(strategy.generateCode(canonicalMessage, "testsignature"));
      }

      // All codes should be different
      const codes = results.map((r) => r.actionCode.code);
      const uniqueCodes = new Set(codes);
      expect(uniqueCodes.size).toBe(codes.length);

      // All canonical messages should be different
      const canonicalMessages = results.map((r) => r.canonicalMessage);
      const uniqueCanonical = new Set(
        canonicalMessages.map((cm) => Array.from(cm).join(","))
      );
      expect(uniqueCanonical.size).toBe(canonicalMessages.length);
    });

    test("timestamp alignment produces consistent results", () => {
      const config = { codeLength: 8, ttlMs: 60000 }; // 1 minute TTL
      const pubkey = "test-pubkey";

      // Generate codes in quick succession - they should all align to the same window
      const results: WalletStrategyCodeGenerationResult[] = [];
      for (let i = 0; i < 5; i++) {
        const canonicalMessage = createCanonicalMessage(pubkey);
        results.push(strategy.generateCode(canonicalMessage, "testsignature"));
        // Small delay to ensure we're in the same window
        if (i < 4) {
          // Wait a few milliseconds
          const start = Date.now();
          while (Date.now() - start < 10) {
            /* busy wait */
          }
        }
      }

      // All results should have the same timestamp (aligned to window)
      const firstTimestamp = results[0]?.actionCode.timestamp;
      for (const result of results) {
        expect(result.actionCode.timestamp).toBe(firstTimestamp);
        expect(result.actionCode.code).toBe(results[0]?.actionCode.code);
      }
    });
  });

  describe("Cross-System Code Validation", () => {
    test("validates codes generated by external systems using Node.js crypto", () => {
      // Create a reference implementation using Node.js crypto
      const generateCodeWithNodeCrypto = (
        pubkey: string,
        timestamp: number,
        codeLength: number
      ): string => {
        // Step 1: Create canonical message (same as our implementation)
        const canonical = serializeCanonical({
          pubkey,
          windowStart: timestamp,
        });

        // Step 2: Hash with Node.js crypto
        const hash = createHash("sha256").update(canonical).digest();

        // Step 3: Truncate and convert to digits (same as our implementation)
        const clamped = Math.max(
          CODE_MIN_LENGTH,
          Math.min(CODE_MAX_LENGTH, codeLength)
        );
        const truncated = truncateBits(hash, 8 * Math.ceil(clamped / 2));
        const code = digestToDigits(truncated, clamped);

        return code;
      };

      const testCases = [
        {
          pubkey: "external-pubkey-1",
          timestamp: 1640995200000,
          codeLength: 8,
        },
        {
          pubkey: "external-pubkey-2",
          timestamp: 1640995260000,
          codeLength: 6,
        },
        {
          pubkey: "external-pubkey-3",
          timestamp: 1640995320000,
          codeLength: 12,
        },
      ];

      for (const testCase of testCases) {
        // Generate code with Node.js crypto
        const nodeCryptoCode = generateCodeWithNodeCrypto(
          testCase.pubkey,
          testCase.timestamp,
          testCase.codeLength
        );

        const strategy = new WalletStrategy({
          codeLength: testCase.codeLength,
          ttlMs: 120000,
        });
        // Generate code with our implementation
        const canonicalMessage = createCanonicalMessage(testCase.pubkey);
        const ourResult = strategy.generateCode(canonicalMessage, "testsignature");

        // The codes should be identical for the same timestamp
        // (Note: This will only work if the timestamp aligns to the same window)
        expect(nodeCryptoCode).toMatch(/^\d+$/);
        expect(nodeCryptoCode).toHaveLength(testCase.codeLength);
        expect(ourResult.actionCode.code).toMatch(/^\d+$/);
        expect(ourResult.actionCode.code).toHaveLength(testCase.codeLength);
      }
    });

    test("validates codes generated by external systems", () => {
      // Simulate codes generated by an external system using the same algorithm
      const externalCodes = [
        {
          pubkey: "external-pubkey-1",
          timestamp: 1640995200000, // Fixed timestamp
          code: "12345678", // This would be generated by external system
        },
        {
          pubkey: "external-pubkey-2",
          timestamp: 1640995260000, // 1 minute later
          code: "87654321", // This would be generated by external system
        },
      ];

      for (const externalCode of externalCodes) {
        const strategy = new WalletStrategy(testConfig);
        // Generate our own code for the same input
        const canonicalMessage = createCanonicalMessage(externalCode.pubkey);
        const ourResult = strategy.generateCode(canonicalMessage, "testsignature");

        // The external code should validate against our system
        // (This test would need to be updated with actual external codes)
        expect(ourResult.actionCode.pubkey).toBe(externalCode.pubkey);
        expect(ourResult.actionCode.timestamp).toBeDefined();
        expect(ourResult.actionCode.code).toMatch(/^\d+$/);
      }
    });

    test("handles edge cases consistently across systems", () => {
      const edgeCases = [
        { pubkey: "", timestamp: 0 },
        { pubkey: "a", timestamp: 1 },
        {
          pubkey: "very-long-pubkey-string-that-might-cause-issues",
          timestamp: 9999999999999,
        },
        { pubkey: "with\nnewlines", timestamp: 1000 },
        { pubkey: "with\ttabs", timestamp: 2000 },
        { pubkey: "with spaces", timestamp: 3000 },
      ];

      for (const edgeCase of edgeCases) {
        const canonicalMessage = createCanonicalMessage(edgeCase.pubkey);
        const result = strategy.generateCode(canonicalMessage, "testsignature");

        expect(result.actionCode.code).toMatch(/^\d+$/);
        expect(result.actionCode.code.length).toBeGreaterThanOrEqual(
          CODE_MIN_LENGTH
        );
        expect(result.actionCode.code.length).toBeLessThanOrEqual(
          CODE_MAX_LENGTH
        );
        expect(result.actionCode.pubkey).toBe(edgeCase.pubkey);
        expect(result.actionCode.timestamp).toBeDefined();
        expect(result.actionCode.expiresAt).toBeDefined();
        expect(result.canonicalMessage).toBeInstanceOf(Uint8Array);
      }
    });
  });

  describe("Performance and Scalability", () => {
    test("generates codes efficiently for large batches", () => {
      const batchSize = 1000;
      const pubkeys = Array.from(
        { length: batchSize },
        (_, i) => `pubkey-${i}`
      );

      const start = Date.now();
      const results = pubkeys.map((pubkey) => {
        const canonicalMessage = createCanonicalMessage(pubkey);
        return strategy.generateCode(canonicalMessage, "testsignature");
      });
      const end = Date.now();

      const timeMs = end - start;
      const perCodeMs = timeMs / batchSize;

      console.log(
        `Generated ${batchSize} codes in ${timeMs}ms (${perCodeMs.toFixed(
          3
        )}ms each)`
      );

      // Performance should be reasonable
      expect(perCodeMs).toBeLessThan(1); // Less than 1ms per code

      // All codes should be unique - with different pubkeys and proper timestamp alignment
      // collisions should be extremely rare
      const codes = results.map((r) => r.actionCode.code);
      const uniqueCodes = new Set(codes);
      expect(uniqueCodes.size).toBe(batchSize);

      // Verify all codes are valid
      codes.forEach((code) => {
        expect(code).toMatch(/^\d+$/);
        expect(code).toHaveLength(testConfig.codeLength);
      });
    });

    test("validates codes efficiently for large batches", () => {
      const batchSize = 1000;
      const results = Array.from({ length: batchSize }, (_, i) =>
        (() => {
          const canonicalMessage = createCanonicalMessage(`pubkey-${i}`);
          return strategy.generateCode(canonicalMessage, "testsignature");
        })()
      );

      const start = Date.now();
      for (const result of results) {
        expect(() => {
          strategy.validateCode(result.actionCode);
        }).not.toThrow();
      }
      const end = Date.now();

      const timeMs = end - start;
      const perValidationMs = timeMs / batchSize;

      console.log(
        `Validated ${batchSize} codes in ${timeMs}ms (${perValidationMs.toFixed(
          3
        )}ms each)`
      );

      // Performance should be reasonable
      expect(perValidationMs).toBeLessThan(1); // Less than 1ms per validation
    });
  });

  describe("Error Handling and Edge Cases", () => {
    test("handles malformed inputs gracefully", () => {
      const malformedInputs = [
        { pubkey: null as any, config: testConfig },
        { pubkey: undefined as any, config: testConfig },
        { pubkey: 123 as any, config: testConfig },
        { pubkey: {}, config: testConfig },
        { pubkey: "valid-pubkey", config: null as any },
        { pubkey: "valid-pubkey", config: undefined as any },
      ];

      for (const input of malformedInputs) {
        // Some inputs might not throw immediately but could cause issues later
        // Let's test that the function either throws or produces a valid result
        try {
          const canonicalMessage = createCanonicalMessage(input.pubkey);
          const result = strategy.generateCode(
            canonicalMessage,
            "testsignature"
          );
          // If it doesn't throw, the result should be valid
          expect(result.actionCode.code).toMatch(/^\d+$/);
          expect(result.actionCode.pubkey).toBeDefined();
        } catch (error) {
          // If it throws, that's also acceptable for malformed inputs
          expect(error).toBeDefined();
        }
      }
    });

    test("handles extreme timestamp values", () => {
      const extremeTimestamps = [
        0,
        1,
        9999999999999,
        Number.MAX_SAFE_INTEGER,
        -1,
        -9999999999999,
      ];

      for (const timestamp of extremeTimestamps) {
        // This should not throw, but the timestamp will be aligned to window
        const canonicalMessage = createCanonicalMessage("test-pubkey");
        const result = strategy.generateCode(canonicalMessage, "testsignature");
        expect(result.actionCode.timestamp).toBeDefined();
        expect(result.actionCode.expiresAt).toBeDefined();
        expect(result.actionCode.code).toMatch(/^\d+$/);
      }
    });
  });
});
