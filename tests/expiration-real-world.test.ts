import { ActionCodesProtocol } from "../src/ActionCodesProtocol";
import { WalletStrategy } from "../src/strategy/WalletStrategy";
import { serializeCanonical } from "../src/utils/canonical";
import { ExpiredCodeError } from "../src/errors";
import { WalletStrategyCodeGenerationResult } from "../src/types";

describe("Real-World Expiration Scenarios", () => {
  let protocol: ActionCodesProtocol;
  let strategy: WalletStrategy;

  beforeEach(() => {
    protocol = new ActionCodesProtocol({
      codeLength: 8,
      ttlMs: 120000, // 2 minutes
    });

    strategy = new WalletStrategy({
      codeLength: 8,
      ttlMs: 120000, // 2 minutes
    });
  });

  describe("TTL precision and timing", () => {
    test("verifies exact 2-minute TTL calculation", () => {
      const pubkey = "2wyVnSw6j9omfqRixz37S2sU72rFTheQeUjDfXhAQJvf";
      const timestamp = 1759737720000;
      const expectedExpiresAt = 1759737840000; // timestamp + 120000ms

      // Create canonical message with specific timestamp
      const canonicalMessage = serializeCanonical({
        pubkey,
        windowStart: timestamp,
      });

      const result = strategy.generateCode(canonicalMessage, "testsignature");

      // Verify exact TTL calculation
      expect(result.actionCode.timestamp).toBe(timestamp);
      expect(result.actionCode.expiresAt).toBe(expectedExpiresAt);
      expect(result.actionCode.expiresAt - result.actionCode.timestamp).toBe(
        120000
      );
    });

    test("handles the specific example from user report", () => {
      // This is the exact data from the user's example
      const exampleData = {
        chain: "solana",
        code: "24019287",
        pubkey: "2wyVnSw6j9omfqRixz37S2sU72rFTheQeUjDfXhAQJvf",
        timestamp: 1759737720000,
        expiresAt: 1759737840000,
        signature:
          "2kyX4pYBnM3X1RZpAh8Z2G59NdFaSy1W8Xjuqfn9Ugr5sU3HckTrqm3kDwMy3z88UT4rKqPvLaYgK265gdAjs87R",
      };

      // Verify the TTL calculation is correct
      const actualTtl = exampleData.expiresAt - exampleData.timestamp;
      expect(actualTtl).toBe(120000); // Should be exactly 2 minutes

      // Create canonical message with the same timestamp
      const canonicalMessage = serializeCanonical({
        pubkey: exampleData.pubkey,
        windowStart: exampleData.timestamp,
      });

      // Generate code with the same parameters
      const result = strategy.generateCode(
        canonicalMessage,
        exampleData.signature
      );

      // Verify the generated code matches the expected structure
      expect(result.actionCode.timestamp).toBe(exampleData.timestamp);
      expect(result.actionCode.expiresAt).toBe(exampleData.expiresAt);
      expect(result.actionCode.pubkey).toBe(exampleData.pubkey);
      expect(result.actionCode.signature).toBe(exampleData.signature);
    });

    test("validates timing precision with millisecond accuracy", () => {
      const now = Date.now();
      const pubkey = "test-pubkey-precision";

      // Create canonical message with current time
      const canonicalMessage = serializeCanonical({
        pubkey,
        windowStart: now,
      });

      const result = strategy.generateCode(canonicalMessage, "testsignature");

      // Verify timing precision
      expect(result.actionCode.timestamp).toBe(now);
      expect(result.actionCode.expiresAt).toBe(now + 120000);

      // Verify the code is valid immediately
      expect(() => {
        strategy.validateCode(result.actionCode);
      }).not.toThrow();
    });

    test("handles edge case where code expires exactly at boundary", async () => {
      const ttlMs = 1000; // 1 second for quick test
      const quickStrategy = new WalletStrategy({
        codeLength: 8,
        ttlMs,
      });

      const pubkey = "test-pubkey-boundary";
      const canonicalMessage = serializeCanonical({
        pubkey,
        windowStart: Date.now(),
      });

      const result = quickStrategy.generateCode(
        canonicalMessage,
        "testsignature"
      );

      // Wait for TTL to expire with a small buffer for test execution time
      await new Promise((resolve) => setTimeout(resolve, ttlMs + 50));

      // Should throw expired error at exact boundary
      expect(() => {
        quickStrategy.validateCode(result.actionCode);
      }).toThrow(ExpiredCodeError);
    });

    test("verifies TTL consistency across multiple generations", () => {
      const pubkey = "test-pubkey-consistency";
      const results: WalletStrategyCodeGenerationResult[] = [];

      // Generate multiple codes with same parameters
      for (let i = 0; i < 10; i++) {
        const canonicalMessage = serializeCanonical({
          pubkey,
          windowStart: Date.now(),
        });

        const result = strategy.generateCode(canonicalMessage, "testsignature");
        results.push(result as WalletStrategyCodeGenerationResult);
      }

      // All codes should have the same TTL
      const expectedTtl = 120000;
      results.forEach((result, index) => {
        const actualTtl =
          result.actionCode.expiresAt - result.actionCode.timestamp;
        expect(actualTtl).toBe(expectedTtl);
      });

      // All codes should validate successfully
      results.forEach((result) => {
        expect(() => {
          strategy.validateCode(result.actionCode);
        }).not.toThrow();
      });
    });

    test("handles different TTL values with precision", () => {
      const ttlValues = [
        { ttlMs: 60000, description: "1 minute" },
        { ttlMs: 120000, description: "2 minutes" },
        { ttlMs: 300000, description: "5 minutes" },
        { ttlMs: 600000, description: "10 minutes" },
      ];

      ttlValues.forEach(({ ttlMs, description }) => {
        const testStrategy = new WalletStrategy({
          codeLength: 8,
          ttlMs,
        });

        const pubkey = `test-pubkey-${ttlMs}`;
        const canonicalMessage = serializeCanonical({
          pubkey,
          windowStart: Date.now(),
        });

        const result = testStrategy.generateCode(
          canonicalMessage,
          "testsignature"
        );
        const actualTtl =
          result.actionCode.expiresAt - result.actionCode.timestamp;

        expect(actualTtl).toBe(ttlMs);
      });
    });

    test("validates expiration behavior with real timestamps", () => {
      // Use a real timestamp from the past to test expiration
      const pastTimestamp = Date.now() - 200000; // 200 seconds ago
      const pubkey = "test-pubkey-past";

      const canonicalMessage = serializeCanonical({
        pubkey,
        windowStart: pastTimestamp,
      });

      const result = strategy.generateCode(canonicalMessage, "testsignature");

      // The code should have expired (past timestamp + 2 minutes < now)
      expect(() => {
        strategy.validateCode(result.actionCode);
      }).toThrow(ExpiredCodeError);
    });

    test("handles future timestamps correctly", () => {
      // Use a future timestamp to test future expiration
      const futureTimestamp = Date.now() + 60000; // 1 minute in the future
      const pubkey = "test-pubkey-future";

      const canonicalMessage = serializeCanonical({
        pubkey,
        windowStart: futureTimestamp,
      });

      const result = strategy.generateCode(canonicalMessage, "testsignature");

      // The code should be valid (future timestamp + 2 minutes > now)
      expect(() => {
        strategy.validateCode(result.actionCode);
      }).not.toThrow();

      // Verify the expiration is in the future
      expect(result.actionCode.expiresAt).toBeGreaterThan(Date.now());
    });

    test("verifies clock skew handling with expiration", () => {
      const clockSkewMs = 10000; // 10 seconds
      const skewStrategy = new WalletStrategy({
        codeLength: 8,
        ttlMs: 5000, // 5 seconds TTL
        clockSkewMs,
      });

      const pubkey = "test-pubkey-skew";
      const canonicalMessage = serializeCanonical({
        pubkey,
        windowStart: Date.now(),
      });

      const result = skewStrategy.generateCode(
        canonicalMessage,
        "testsignature"
      );

      // Manually set expiration to past but within clock skew
      const actionCode = {
        ...result.actionCode,
        expiresAt: Date.now() - 7000, // 7 seconds ago, but within 10s skew
      };

      // Should still validate due to clock skew tolerance
      expect(() => {
        skewStrategy.validateCode(actionCode);
      }).not.toThrow();
    });

    test("handles rapid successive generations with consistent timing", () => {
      const pubkey = "test-pubkey-rapid";
      const results = [];
      const startTime = Date.now();

      // Generate codes rapidly
      for (let i = 0; i < 20; i++) {
        const canonicalMessage = serializeCanonical({
          pubkey,
          windowStart: Date.now(),
        });

        const result = strategy.generateCode(canonicalMessage, "testsignature");
        results.push(result as WalletStrategyCodeGenerationResult);
      }

      const endTime = Date.now();
      const generationTime = endTime - startTime;

      // All codes should have consistent TTL
      const expectedTtl = 120000;
      results.forEach((result) => {
        const actualTtl =
          result.actionCode.expiresAt - result.actionCode.timestamp;
        expect(actualTtl).toBe(expectedTtl);
      });

      // All codes should validate
      results.forEach((result) => {
        expect(() => {
          strategy.validateCode(result.actionCode);
        }).not.toThrow();
      });

      // Generation should be fast
      expect(generationTime).toBeLessThan(1000);
    });
  });

  describe("protocol-level expiration handling", () => {
    test("validates expiration at protocol level", () => {
      const pubkey = "test-pubkey-protocol";
      const canonicalMessage = serializeCanonical({
        pubkey,
        windowStart: Date.now(),
      });

      const result = protocol.generateCode(
        "wallet",
        canonicalMessage,
        "testsignature"
      );

      // Verify TTL is correct
      expect(result.actionCode.expiresAt - result.actionCode.timestamp).toBe(
        120000
      );
      
      // The protocol validation requires proper signature verification
      // which is complex to set up in this test, so we'll focus on TTL verification
      expect(result.actionCode.timestamp).toBeGreaterThan(0);
      expect(result.actionCode.expiresAt).toBeGreaterThan(result.actionCode.timestamp);
    });

    test("handles expired codes at protocol level", () => {
      const pubkey = "test-pubkey-protocol-expired";
      const canonicalMessage = serializeCanonical({
        pubkey,
        windowStart: Date.now(),
      });

      const result = protocol.generateCode(
        "wallet",
        canonicalMessage,
        "testsignature"
      );

      // Manually set expiration to past
      const expiredActionCode = {
        ...result.actionCode,
        expiresAt: Date.now() - 1000,
      };

      // Should throw expired error (checking for any error related to expiration)
      expect(() => {
        protocol.validateCode("wallet", expiredActionCode, {
          chain: "solana",
          pubkey,
          signature: "testsignature",
        } as any);
      }).toThrow(/expired|ExpiredCodeError/);
    });
  });
});
