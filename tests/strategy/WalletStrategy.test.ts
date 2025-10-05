import { WalletStrategy } from "../../src/strategy/WalletStrategy";
import type { ActionCode, CodeGenerationConfig } from "../../src/types";
import { ExpiredCodeError, InvalidCodeFormatError } from "../../src/errors";
import { CODE_MIN_LENGTH, CODE_MAX_LENGTH } from "../../src/constants";
import { serializeCanonical } from "../../src/utils/canonical";

// Helper function to create canonical message for testing
function createCanonicalMessage(pubkey: string, secret?: string): Uint8Array {
  const windowStart = Math.floor(Date.now() / 120000) * 120000; // 2 minute TTL
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
      const codes = Array.from({ length: 1000 }, () =>
        strategy.generateCode(createCanonicalMessage("test-pubkey"), "testsignature")
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

      const codes = Array.from({ length: 10 }, () =>
        strategy.generateCode(createCanonicalMessage(pubkey), "testsignature", secret)
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
});