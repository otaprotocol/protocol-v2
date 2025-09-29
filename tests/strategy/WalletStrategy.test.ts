import { WalletStrategy } from "../../src/strategy/WalletStrategy";
import type { ActionCode, CodeGenerationConfig } from "../../src/types";
import { ExpiredCodeError, InvalidCodeFormatError } from "../../src/errors";
import { serializeCanonical } from "../../src/utils/canonical";
import { sha256, truncateBits, digestToDigits } from "../../src/utils/crypto";
import { CODE_MIN_LENGTH, CODE_MAX_LENGTH } from "../../src/constants";

describe("WalletStrategy", () => {
  const defaultConfig: CodeGenerationConfig = {
    codeLength: 8,
    ttlMs: 120000, // 2 minutes
  };

  describe("generateCode", () => {
    test("generates valid action code with correct structure", async () => {
      const pubkey = "test-pubkey-123";
      const result = await WalletStrategy.generateCode(pubkey, defaultConfig);

      expect(result.actionCode).toMatchObject({
        code: expect.any(String),
        pubkey,
        timestamp: expect.any(Number),
        expiresAt: expect.any(Number),
      });

      expect(result.canonicalMessage).toBeInstanceOf(Uint8Array);
      expect(result.canonicalMessage.length).toBeGreaterThan(0);
    });

    test("generates deterministic codes for same input", async () => {
      const pubkey = "test-pubkey-456";
      const config = { ...defaultConfig, codeLength: 6 };

      const result1 = await WalletStrategy.generateCode(pubkey, config);
      const result2 = await WalletStrategy.generateCode(pubkey, config);

      expect(result1.actionCode.code).toBe(result2.actionCode.code);
      expect(result1.actionCode.pubkey).toBe(result2.actionCode.pubkey);
      expect(result1.actionCode.timestamp).toBe(result2.actionCode.timestamp);
      expect(result1.actionCode.expiresAt).toBe(result2.actionCode.expiresAt);
    });

    test("generates different codes for different pubkeys", async () => {
      const result1 = await WalletStrategy.generateCode(
        "pubkey1",
        defaultConfig
      );
      const result2 = await WalletStrategy.generateCode(
        "pubkey2",
        defaultConfig
      );

      expect(result1.actionCode.code).not.toBe(result2.actionCode.code);
      expect(result1.actionCode.pubkey).not.toBe(result2.actionCode.pubkey);
    });

    test("respects code length configuration", async () => {
      const testLengths = [6, 8, 12, 16, 20];

      for (const length of testLengths) {
        const config = { ...defaultConfig, codeLength: length };
        const result = await WalletStrategy.generateCode("test-pubkey", config);

        expect(result.actionCode.code).toHaveLength(length);
        expect(result.actionCode.code).toMatch(/^\d+$/); // Only digits
      }
    });

    test("clamps code length to valid range", async () => {
      const tooShortConfig = { ...defaultConfig, codeLength: 3 };
      const tooLongConfig = { ...defaultConfig, codeLength: 30 };

      const shortResult = WalletStrategy.generateCode(
        "test",
        tooShortConfig
      );
      const longResult = WalletStrategy.generateCode(
        "test",
        tooLongConfig
      );

      expect(shortResult.actionCode.code).toHaveLength(6); // CODE_MIN_LENGTH
      expect(longResult.actionCode.code).toHaveLength(24); // CODE_MAX_LENGTH
    });

    test("generates codes with correct expiration time", async () => {
      const ttlMs = 300000; // 5 minutes
      const config = { ...defaultConfig, ttlMs };

      const result = WalletStrategy.generateCode("test-pubkey", config);

      expect(result.actionCode.expiresAt).toBe(
        result.actionCode.timestamp + ttlMs
      );
      expect(result.actionCode.timestamp).toBeLessThanOrEqual(Date.now());
    });

    test("aligns timestamp to TTL window", async () => {
      const ttlMs = 60000; // 1 minute
      const config = { ...defaultConfig, ttlMs };

      const result = await WalletStrategy.generateCode("test-pubkey", config);

      // Timestamp should be aligned to TTL window
      expect(result.actionCode.timestamp % ttlMs).toBe(0);
    });

    test("canonical message is deterministic for same input", async () => {
      const pubkey = "test-pubkey";
      const config = { ...defaultConfig, codeLength: 8 };

      const result1 = await WalletStrategy.generateCode(pubkey, config);
      const result2 = await WalletStrategy.generateCode(pubkey, config);

      expect(result1.canonicalMessage).toEqual(result2.canonicalMessage);
    });

    test("canonical message contains expected fields", async () => {
      const pubkey = "test-pubkey-789";
      const result = await WalletStrategy.generateCode(pubkey, defaultConfig);

      const messageStr = new TextDecoder().decode(result.canonicalMessage);
      const parsed = JSON.parse(messageStr);

      expect(parsed).toMatchObject({
        pubkey,
        windowStart: result.actionCode.timestamp,
      });
    });
  });

  describe("validateCode", () => {
    test("validates correct action code", async () => {
      const pubkey = "test-pubkey-valid";
      const result = await WalletStrategy.generateCode(pubkey, defaultConfig);

      // Debug: log the generated code and current time
      console.log("Generated code:", result.actionCode.code);
      console.log("Current time:", Date.now());
      console.log("Code timestamp:", result.actionCode.timestamp);
      console.log("Code expires at:", result.actionCode.expiresAt);

      // Try validation and catch the error to see what's happening
      try {
        WalletStrategy.validateCode(result.actionCode, defaultConfig);
        console.log("Validation passed!");
      } catch (error) {
        console.log("Validation failed with error:", (error as Error).message);
        console.log("Error details:", error);
        throw error;
      }

      // Should not throw
      expect(() => {
        WalletStrategy.validateCode(result.actionCode, defaultConfig);
      }).not.toThrow();
    });

    test("throws ExpiredCodeError for expired code", () => {
      const expiredActionCode: ActionCode = {
        code: "12345678",
        pubkey: "test-pubkey",
        timestamp: Date.now() - 200000, // 200 seconds ago
        expiresAt: Date.now() - 100000, // 100 seconds ago (expired)
      };

      expect(() => {
        WalletStrategy.validateCode(expiredActionCode, defaultConfig);
      }).toThrow(ExpiredCodeError);
    });

    test("respects clock skew tolerance", async () => {
      const config = { ...defaultConfig, clockSkewMs: 5000 }; // 5 second tolerance
      
      // Generate a valid code first
      const result = await WalletStrategy.generateCode("test-pubkey", config);
      
      // Create an action code that's slightly expired but within skew tolerance
      const actionCode: ActionCode = {
        ...result.actionCode,
        expiresAt: Date.now() - 2000, // 2 seconds ago, but within skew tolerance
      };

      // Should not throw due to clock skew tolerance
      expect(() => {
        WalletStrategy.validateCode(actionCode, config);
      }).not.toThrow();
    });

    test("throws InvalidCodeFormatError for incorrect code", async () => {
      const pubkey = "test-pubkey";
      const result = await WalletStrategy.generateCode(pubkey, defaultConfig);
      
      // Modify the code to make it invalid
      const invalidActionCode: ActionCode = {
        ...result.actionCode,
        code: "99999999", // Wrong code
      };

      expect(() => {
        WalletStrategy.validateCode(invalidActionCode, defaultConfig);
      }).toThrow(InvalidCodeFormatError);
    });

    test("validates code with different lengths", async () => {
      const testLengths = [6, 8, 12, 16];
      
      for (const length of testLengths) {
        const config = { ...defaultConfig, codeLength: length };
        const result = await WalletStrategy.generateCode("test-pubkey", config);
        
        // Should not throw for valid code
        expect(() => {
          WalletStrategy.validateCode(result.actionCode, config);
        }).not.toThrow();
      }
    });

    test("validates code with different pubkeys", async () => {
      const pubkeys = [
        "pubkey1",
        "pubkey2",
        "very-long-pubkey-string",
        "short",
      ];

      for (const pubkey of pubkeys) {
        const result = await WalletStrategy.generateCode(pubkey, defaultConfig);

        // Should not throw for valid code
        expect(() => {
          WalletStrategy.validateCode(result.actionCode, defaultConfig);
        }).not.toThrow();
      }
    });

    test("handles edge case timestamps", async () => {
      const edgeTimestamps = [0, 1, 1000000000000, Date.now()];
      
      for (const timestamp of edgeTimestamps) {
        // Generate a valid code for this specific timestamp
        // We need to manually create the canonical message and code for the specific timestamp
        const canonical = serializeCanonical({ pubkey: "test-pubkey", windowStart: timestamp });
        const digest = sha256(canonical);
        const clamped = Math.max(
          CODE_MIN_LENGTH,
          Math.min(CODE_MAX_LENGTH, defaultConfig.codeLength)
        );
        const truncated = truncateBits(digest, 8 * Math.ceil(clamped / 2));
        const code = digestToDigits(truncated, clamped);
        
        const actionCode: ActionCode = {
          code,
          pubkey: "test-pubkey",
          timestamp,
          expiresAt: timestamp + defaultConfig.ttlMs,
        };

        // Should not throw for valid timestamp (if not expired)
        if (timestamp + defaultConfig.ttlMs > Date.now()) {
          expect(() => {
            WalletStrategy.validateCode(actionCode, defaultConfig);
          }).not.toThrow();
        }
      }
    });

    test("validates with different TTL values", async () => {
      const ttlValues = [60000, 120000, 300000, 600000]; // 1min, 2min, 5min, 10min

      for (const ttlMs of ttlValues) {
        const config = { ...defaultConfig, ttlMs };
        const result = await WalletStrategy.generateCode("test-pubkey", config);

        // Should not throw for valid code
        expect(() => {
          WalletStrategy.validateCode(result.actionCode, config);
        }).not.toThrow();
      }
    });
  });

  describe("integration tests", () => {
    test("full workflow: generate and validate code", async () => {
      const pubkey = "integration-test-pubkey";
      const config = { ...defaultConfig, codeLength: 10 };

      // Generate code
      const result = await WalletStrategy.generateCode(pubkey, config);

      // Validate immediately (should not be expired)
      expect(() => {
        WalletStrategy.validateCode(result.actionCode, config);
      }).not.toThrow();

      // Verify the code matches what we generated
      expect(result.actionCode.code).toMatch(/^\d{10}$/);
      expect(result.actionCode.pubkey).toBe(pubkey);
    });

    test("code generation is consistent across multiple calls", async () => {
      const pubkey = "consistency-test-pubkey";
      const config = { ...defaultConfig, codeLength: 8 };

      const results = await Promise.all([
        WalletStrategy.generateCode(pubkey, config),
        WalletStrategy.generateCode(pubkey, config),
        WalletStrategy.generateCode(pubkey, config),
      ]);

      // All results should be identical
      const first = results[0];
      for (const result of results) {
        expect(result.actionCode.code).toBe(first.actionCode.code);
        expect(result.actionCode.timestamp).toBe(first.actionCode.timestamp);
        expect(result.canonicalMessage).toEqual(first.canonicalMessage);
      }
    });

    test("performance test: multiple code generations", async () => {
      const config = { ...defaultConfig, codeLength: 8 };
      const pubkeys = Array.from({ length: 100 }, (_, i) => `pubkey-${i}`);

      const start = Date.now();
      const results = await Promise.all(
        pubkeys.map((pubkey) => WalletStrategy.generateCode(pubkey, config))
      );
      const end = Date.now();

      const timeMs = end - start;
      const perGenerationMs = timeMs / pubkeys.length;

      console.log(
        `Generated ${
          pubkeys.length
        } codes in ${timeMs}ms (${perGenerationMs.toFixed(2)}ms each)`
      );

      // All codes should be unique
      const codes = results.map((r) => r.actionCode.code);
      const uniqueCodes = new Set(codes);
      expect(uniqueCodes.size).toBe(codes.length);

      // Performance should be reasonable
      expect(perGenerationMs).toBeLessThan(10); // 10ms per generation
    });
  });

  describe("error handling", () => {
    test("handles malformed action code gracefully", async () => {
      const malformedActionCode = {
        code: "123",
        pubkey: "",
        timestamp: NaN,
        expiresAt: Infinity,
      } as any; // eslint-disable-line @typescript-eslint/no-explicit-any

      expect(() => {
        WalletStrategy.validateCode(malformedActionCode, defaultConfig);
      }).toThrow();
    });

    test("handles missing required fields", async () => {
      const incompleteActionCode = {
        code: "12345678",
        // missing pubkey, timestamp, expiresAt
      } as any; // eslint-disable-line @typescript-eslint/no-explicit-any

      expect(() => {
        WalletStrategy.validateCode(incompleteActionCode, defaultConfig);
      }).toThrow();
    });
  });
});
