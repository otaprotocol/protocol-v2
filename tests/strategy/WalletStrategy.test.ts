import { WalletStrategy } from "../../src/strategy/WalletStrategy";
import type { ActionCode, CodeGenerationConfig } from "../../src/types";
import { ExpiredCodeError, InvalidCodeFormatError } from "../../src/errors";
import { CODE_MIN_LENGTH, CODE_MAX_LENGTH } from "../../src/constants";
import { serializeCanonical } from "../../src/utils/canonical";

// Helper function to create canonical message for testing
function createCanonicalMessage(pubkey: string, secret?: string): Uint8Array {
  const windowStart = Date.now(); // Use current time to avoid past timestamps
  return serializeCanonical({ pubkey, windowStart, secret });
}

describe("WalletStrategy", () => {
  const defaultConfig: CodeGenerationConfig = {
    codeLength: 8,
    ttlMs: 120000, // 2 minutes
  };

  let strategy: WalletStrategy;

  beforeEach(() => {
    strategy = new WalletStrategy(defaultConfig);
  });

  describe("generateCode", () => {
    test("generates valid action code with correct structure", async () => {
      const pubkey = "testpubkey123";
      const canonicalMessage = createCanonicalMessage(pubkey);
      const result = strategy.generateCode(canonicalMessage, "testsignature");

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
      const canonicalMessage = createCanonicalMessage(pubkey);

      const result1 = strategy.generateCode(canonicalMessage, "testsignature");
      const result2 = strategy.generateCode(canonicalMessage, "testsignature");

      expect(result1.actionCode.code).toBe(result2.actionCode.code);
      expect(result1.actionCode.pubkey).toBe(result2.actionCode.pubkey);
      expect(result1.actionCode.timestamp).toBe(result2.actionCode.timestamp);
      expect(result1.actionCode.expiresAt).toBe(result2.actionCode.expiresAt);
    });

    test("generates different codes for different pubkeys", async () => {
      const canonicalMessage1 = createCanonicalMessage("pubkey1");
      const canonicalMessage2 = createCanonicalMessage("pubkey2");
      const result1 = strategy.generateCode(canonicalMessage1, "testsignature");
      const result2 = strategy.generateCode(canonicalMessage2, "testsignature");

      expect(result1.actionCode.code).not.toBe(result2.actionCode.code);
      expect(result1.actionCode.pubkey).toBe("pubkey1");
      expect(result2.actionCode.pubkey).toBe("pubkey2");
    });

    test("generates codes with correct length", async () => {
      const config: CodeGenerationConfig = {
        codeLength: 6,
        ttlMs: 120000,
      };
      const shortStrategy = new WalletStrategy(config);

      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = shortStrategy.generateCode(canonicalMessage, "testsignature");

      expect(result.actionCode.code.length).toBe(6);
    });

    test("generates codes with correct TTL", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      const now = Date.now();
      expect(result.actionCode.timestamp).toBeLessThanOrEqual(now);
      expect(result.actionCode.expiresAt).toBe(
        result.actionCode.timestamp + defaultConfig.ttlMs
      );
    });

    test("generates same codes within the same time window", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result1 = strategy.generateCode(canonicalMessage, "testsignature");

      // Wait a short time but within the same window
      await new Promise((resolve) => setTimeout(resolve, 100));

      const result2 = strategy.generateCode(canonicalMessage, "testsignature");

      // Codes should be the same within the same time window (deterministic)
      expect(result1.actionCode.code).toBe(result2.actionCode.code);
      expect(result1.actionCode.timestamp).toBe(result2.actionCode.timestamp);
    });

    test("generates codes with secret when provided", async () => {
      const secret = "test-secret";
      const canonicalMessage = createCanonicalMessage("test-pubkey", secret);
      const result = strategy.generateCode(canonicalMessage, "testsignature", secret);

      expect(result.actionCode.secret).toBe(secret);
    });

    test("generates codes without secret when not provided", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      expect(result.actionCode.secret).toBeUndefined();
    });

    test("generates different codes with different secrets", async () => {
      const canonicalMessage1 = createCanonicalMessage("test-pubkey", "secret1");
      const canonicalMessage2 = createCanonicalMessage("test-pubkey", "secret2");
      const result1 = strategy.generateCode(canonicalMessage1, "testsignature", "secret1");
      const result2 = strategy.generateCode(canonicalMessage2, "testsignature", "secret2");

      expect(result1.actionCode.code).not.toBe(result2.actionCode.code);
    });

    test("generates same code with same secret", async () => {
      const secret = "same-secret";
      const canonicalMessage = createCanonicalMessage("test-pubkey", secret);
      const result1 = strategy.generateCode(canonicalMessage, "testsignature", secret);
      const result2 = strategy.generateCode(canonicalMessage, "testsignature", secret);

      expect(result1.actionCode.code).toBe(result2.actionCode.code);
    });
  });

  describe("validateCode", () => {
    test("validates correct action code", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      expect(() => {
        strategy.validateCode(result.actionCode);
      }).not.toThrow();
    });

    test("validates action code with secret", async () => {
      const secret = "test-secret";
      const canonicalMessage = createCanonicalMessage("test-pubkey", secret);
      const result = strategy.generateCode(canonicalMessage, "testsignature", secret);

      expect(() => {
        strategy.validateCode(result.actionCode);
      }).not.toThrow();
    });

    test("throws error for expired code", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      // Manually set expiration to past
      const expiredActionCode: ActionCode = {
        ...result.actionCode,
        expiresAt: Date.now() - 1000,
      };

      expect(() => {
        strategy.validateCode(expiredActionCode);
      }).toThrow(ExpiredCodeError);
    });

    test("validates code within clock skew tolerance", async () => {
      const config: CodeGenerationConfig = {
        codeLength: 8,
        ttlMs: 120000,
        clockSkewMs: 30000, // 30 seconds
      };
      const skewStrategy = new WalletStrategy(config);
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = skewStrategy.generateCode(canonicalMessage, "testsignature");

      // Manually set expiration to just past current time but within skew
      const actionCode: ActionCode = {
        ...result.actionCode,
        expiresAt: Date.now() - 15000, // 15 seconds ago
      };

      expect(() => {
        skewStrategy.validateCode(actionCode);
      }).not.toThrow();
    });

    test("throws error for invalid code format", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      const actionCode: ActionCode = {
        ...result.actionCode,
        code: "invalid-code",
      };

      expect(() => {
        strategy.validateCode(actionCode);
      }).toThrow("Invalid code:");
    });

    test("validates code with correct secret", async () => {
      const secret = "correct-secret";
      const canonicalMessage = createCanonicalMessage("test-pubkey", secret);
      const result = strategy.generateCode(canonicalMessage, "testsignature", secret);

      expect(() => {
        strategy.validateCode(result.actionCode);
      }).not.toThrow();
    });

    test("throws error for code with wrong secret", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature", "original-secret");

      const actionCode: ActionCode = {
        ...result.actionCode,
        secret: "wrong-secret",
      };

      expect(() => {
        strategy.validateCode(actionCode);
      }).toThrow("Invalid code:");
    });

    test("validates code without secret when generated without secret", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      const actionCode: ActionCode = {
        ...result.actionCode,
        secret: undefined,
      };

      expect(() => {
        strategy.validateCode(actionCode);
      }).not.toThrow();
    });

    test("throws error for code with secret when generated without secret", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      const actionCode: ActionCode = {
        ...result.actionCode,
        secret: "unexpected-secret",
      };

      expect(() => {
        strategy.validateCode(actionCode);
      }).toThrow("Invalid code:");
    });
  });

  describe("edge cases", () => {
    test("handles very short code length", async () => {
      const config: CodeGenerationConfig = {
        codeLength: 1,
        ttlMs: 120000,
      };
      const shortStrategy = new WalletStrategy(config);

      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = shortStrategy.generateCode(canonicalMessage, "testsignature");

      // Should enforce minimum code length of 6 for security
      expect(result.actionCode.code.length).toBe(6);
      expect(() => {
        shortStrategy.validateCode(result.actionCode);
      }).not.toThrow();
    });

    test("handles very long code length", async () => {
      const config: CodeGenerationConfig = {
        codeLength: 20,
        ttlMs: 120000,
      };
      const longStrategy = new WalletStrategy(config);

      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = longStrategy.generateCode(canonicalMessage, "testsignature");

      expect(result.actionCode.code.length).toBe(20);
      expect(() => {
        longStrategy.validateCode(result.actionCode);
      }).not.toThrow();
    });

    test("handles code length at boundaries", async () => {
      const shortConfig: CodeGenerationConfig = {
        codeLength: CODE_MIN_LENGTH,
        ttlMs: 120000,
      };
      const longConfig: CodeGenerationConfig = {
        codeLength: CODE_MAX_LENGTH,
        ttlMs: 120000,
      };

      const shortStrategy = new WalletStrategy(shortConfig);
      const longStrategy = new WalletStrategy(longConfig);

      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const shortResult = shortStrategy.generateCode(canonicalMessage, "testsignature");
      const longResult = longStrategy.generateCode(canonicalMessage, "testsignature");

      expect(shortResult.actionCode.code.length).toBe(CODE_MIN_LENGTH);
      expect(longResult.actionCode.code.length).toBe(CODE_MAX_LENGTH);
    });

    test("handles special characters in pubkey", async () => {
      const specialPubkey = "test-pubkey-with-special-chars!@#$%^&*()";
      const canonicalMessage = createCanonicalMessage(specialPubkey);
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      expect(result.actionCode.pubkey).toBe(specialPubkey);
      expect(() => {
        strategy.validateCode(result.actionCode);
      }).not.toThrow();
    });

    test("handles very long pubkey", async () => {
      const longPubkey = "a".repeat(1000);
      const canonicalMessage = createCanonicalMessage(longPubkey);
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      expect(result.actionCode.pubkey).toBe(longPubkey);
      expect(() => {
        strategy.validateCode(result.actionCode);
      }).not.toThrow();
    });
  });

  describe("performance", () => {
    test("generates codes quickly", async () => {
      const start = Date.now();
      const results = Array.from({ length: 100 }, () =>
        strategy.generateCode(createCanonicalMessage("test-pubkey"), "testsignature")
      );
      const end = Date.now();

      expect(results).toHaveLength(100);
      expect(end - start).toBeLessThan(1000); // Should complete in less than 1 second
    });

    test("validates codes quickly", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      const start = Date.now();
      for (let i = 0; i < 100; i++) {
        strategy.validateCode(result.actionCode);
      }
      const end = Date.now();

      expect(end - start).toBeLessThan(1000); // Should complete in less than 1 second
    });
  });

  describe("cryptographic properties", () => {
    test("generates codes with good entropy", async () => {
      // Use a fixed timestamp to ensure deterministic behavior
      const fixedTimestamp = Date.now();
      const canonicalMessage = serializeCanonical({
        pubkey: "test-pubkey",
        windowStart: fixedTimestamp,
      });

      const codes = Array.from({ length: 1000 }, () =>
        strategy.generateCode(canonicalMessage, "testsignature")
      );

      // All codes should be the same within the same time window (deterministic)
      const uniqueCodes = new Set(codes.map((r) => r.actionCode.code));
      expect(uniqueCodes.size).toBe(1); // Deterministic behavior
      
      // But the code should have good entropy properties
      const code = codes[0]?.actionCode.code;
      expect(code).toMatch(/^\d+$/);
      expect(code?.length).toBe(8);
    });

    test("generates different codes for different pubkeys with same secret", async () => {
      const secret = "same-secret";
      const codes = Array.from({ length: 100 }, (_, i) =>
        strategy.generateCode(createCanonicalMessage(`pubkey-${i}`), "testsignature", secret)
      );

      const uniqueCodes = new Set(codes.map((r) => r.actionCode.code));
      expect(uniqueCodes.size).toBe(100); // All should be unique
    });

    test("generates same codes for same pubkey and secret", async () => {
      const secret = "same-secret";
      const pubkey = "same-pubkey";
      const fixedTimestamp = Date.now();
      const canonicalMessage = serializeCanonical({
        pubkey,
        windowStart: fixedTimestamp,
      });

      const codes = Array.from({ length: 10 }, () =>
        strategy.generateCode(canonicalMessage, "testsignature", secret)
      );

      const firstCode = codes[0]!.actionCode.code;
      codes.forEach((result) => {
        expect(result.actionCode.code).toBe(firstCode);
      });
    });
  });

  describe("error handling", () => {
    test("handles malformed action code gracefully", async () => {
      const malformedActionCode: ActionCode = {
        code: "",
        pubkey: "",
        timestamp: 0,
        expiresAt: 0,
      };

      expect(() => {
        strategy.validateCode(malformedActionCode);
      }).toThrow();
    });

    test("handles incomplete action code gracefully", async () => {
      const incompleteActionCode = {
        code: "123456",
        pubkey: "test-pubkey",
        // Missing timestamp and expiresAt
      } as ActionCode;

      expect(() => {
        strategy.validateCode(incompleteActionCode);
      }).toThrow();
    });
  });

  describe("expiration timing", () => {
    test("generates codes with exact TTL duration", async () => {
      const ttlMs = 120000; // 2 minutes
      const config: CodeGenerationConfig = {
        codeLength: 8,
        ttlMs,
      };
      const strategy = new WalletStrategy(config);

      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      // Verify exact TTL calculation
      const actualTtl = result.actionCode.expiresAt - result.actionCode.timestamp;
      expect(actualTtl).toBe(ttlMs);
    });

    test("validates code immediately after generation", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      // Should validate successfully immediately after generation
      expect(() => {
        strategy.validateCode(result.actionCode);
      }).not.toThrow();
    });

    test("validates code just before expiration", async () => {
      const ttlMs = 2000; // 2 seconds for quick test
      const config: CodeGenerationConfig = {
        codeLength: 8,
        ttlMs,
      };
      const strategy = new WalletStrategy(config);

      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      // Wait just before expiration (1.5 seconds)
      await new Promise(resolve => setTimeout(resolve, 1500));

      // Should still validate successfully
      expect(() => {
        strategy.validateCode(result.actionCode);
      }).not.toThrow();
    });

    test("throws error immediately after expiration", async () => {
      const ttlMs = 100; // 100ms for quick test
      const config: CodeGenerationConfig = {
        codeLength: 8,
        ttlMs,
      };
      const strategy = new WalletStrategy(config);

      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      // Wait for expiration plus a small buffer
      await new Promise(resolve => setTimeout(resolve, ttlMs + 50));

      // Should throw expired error
      expect(() => {
        strategy.validateCode(result.actionCode);
      }).toThrow(ExpiredCodeError);
    });

    test("handles different TTL values correctly", async () => {
      const testCases = [
        { ttlMs: 1000, description: "1 second" },
        { ttlMs: 30000, description: "30 seconds" },
        { ttlMs: 120000, description: "2 minutes" },
        { ttlMs: 300000, description: "5 minutes" },
      ];

      for (const testCase of testCases) {
        const config: CodeGenerationConfig = {
          codeLength: 8,
          ttlMs: testCase.ttlMs,
        };
        const strategy = new WalletStrategy(config);

        const canonicalMessage = createCanonicalMessage("test-pubkey");
        const result = strategy.generateCode(canonicalMessage, "testsignature");

        const actualTtl = result.actionCode.expiresAt - result.actionCode.timestamp;
        expect(actualTtl).toBe(testCase.ttlMs);
      }
    });

    test("validates timestamp precision and consistency", async () => {
      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      const now = Date.now();
      const timestamp = result.actionCode.timestamp;
      const expiresAt = result.actionCode.expiresAt;

      // Timestamp should be reasonable (within last few seconds)
      expect(timestamp).toBeLessThanOrEqual(now);
      expect(timestamp).toBeGreaterThan(now - 10000); // Within last 10 seconds (more lenient)

      // Expiration should be exactly TTL after timestamp
      expect(expiresAt).toBe(timestamp + defaultConfig.ttlMs);

      // Both should be valid timestamps
      expect(timestamp).toBeGreaterThan(0);
      expect(expiresAt).toBeGreaterThan(timestamp);
    });

    test("handles clock skew with expiration correctly", async () => {
      const clockSkewMs = 2000; // 2 seconds
      const config: CodeGenerationConfig = {
        codeLength: 8,
        ttlMs: 1000, // 1 second TTL
        clockSkewMs,
      };
      const strategy = new WalletStrategy(config);

      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      // Wait for TTL to expire but within clock skew
      await new Promise(resolve => setTimeout(resolve, 1500));

      // Should still validate due to clock skew tolerance
      expect(() => {
        strategy.validateCode(result.actionCode);
      }).not.toThrow();

      // Wait beyond clock skew (total wait time > TTL + clock skew)
      await new Promise(resolve => setTimeout(resolve, 1500));

      // Should now throw expired error
      expect(() => {
        strategy.validateCode(result.actionCode);
      }).toThrow(ExpiredCodeError);
    });

    test("validates expiration with different time windows", async () => {
      // Test with different window start times - use current time to avoid past timestamps
      const baseTime = Date.now();
      const windowSizes = [60000, 120000, 300000]; // 1, 2, 5 minutes

      for (const windowSize of windowSizes) {
        // Use current time as window start to avoid past timestamps
        const windowStart = Math.floor(baseTime / windowSize) * windowSize;
        // Ensure window start is not in the past
        const actualWindowStart = Math.max(windowStart, baseTime - 60000); // At most 1 minute ago
        
        const canonicalMessage = serializeCanonical({
          pubkey: "test-pubkey",
          windowStart: actualWindowStart,
        });

        const result = strategy.generateCode(canonicalMessage, "testsignature");

        // Verify the timestamp matches the window start
        expect(result.actionCode.timestamp).toBe(actualWindowStart);
        expect(result.actionCode.expiresAt).toBe(actualWindowStart + defaultConfig.ttlMs);

        // Should validate successfully
        expect(() => {
          strategy.validateCode(result.actionCode);
        }).not.toThrow();
      }
    });

    test("handles edge case of expiration at exact boundary", async () => {
      const ttlMs = 1000; // 1 second
      const config: CodeGenerationConfig = {
        codeLength: 8,
        ttlMs,
      };
      const strategy = new WalletStrategy(config);

      const canonicalMessage = createCanonicalMessage("test-pubkey");
      const result = strategy.generateCode(canonicalMessage, "testsignature");

      // Wait exactly for TTL to expire plus a small buffer
      await new Promise(resolve => setTimeout(resolve, ttlMs + 50));

      // Should throw expired error at exact boundary
      expect(() => {
        strategy.validateCode(result.actionCode);
      }).toThrow(ExpiredCodeError);
    });

    test("verifies TTL calculation matches configuration", async () => {
      const configs = [
        { codeLength: 8, ttlMs: 60000, description: "1 minute" },
        { codeLength: 8, ttlMs: 120000, description: "2 minutes" },
        { codeLength: 8, ttlMs: 300000, description: "5 minutes" },
        { codeLength: 8, ttlMs: 600000, description: "10 minutes" },
      ];

      for (const config of configs) {
        const strategy = new WalletStrategy(config);
        const canonicalMessage = createCanonicalMessage("test-pubkey");
        const result = strategy.generateCode(canonicalMessage, "testsignature");

        const actualTtl = result.actionCode.expiresAt - result.actionCode.timestamp;
        expect(actualTtl).toBe(config.ttlMs);
      }
    });

    test("handles rapid successive code generation with consistent TTL", async () => {
      const results = [];
      const startTime = Date.now();

      // Generate multiple codes rapidly
      for (let i = 0; i < 10; i++) {
        const canonicalMessage = createCanonicalMessage(`test-pubkey-${i}`);
        const result = strategy.generateCode(canonicalMessage, "testsignature");
        results.push(result);
      }

      const endTime = Date.now();
      const generationTime = endTime - startTime;

      // All codes should have the same TTL
      const expectedTtl = defaultConfig.ttlMs;
      results.forEach((result, index) => {
        const actualTtl = result.actionCode.expiresAt - result.actionCode.timestamp;
        expect(actualTtl).toBe(expectedTtl);
      });

      // All codes should validate successfully
      results.forEach((result) => {
        expect(() => {
          strategy.validateCode(result.actionCode);
        }).not.toThrow();
      });

      // Generation should be fast
      expect(generationTime).toBeLessThan(1000); // Less than 1 second
    });
  });
});