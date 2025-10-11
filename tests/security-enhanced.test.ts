import { ActionCodesProtocol } from "../src/ActionCodesProtocol";
import { WalletStrategy } from "../src/strategy/WalletStrategy";
import { hmacSha256 } from "../src/utils/crypto";
import { serializeCanonical } from "../src/utils/canonical";
import type { CodeGenerationConfig } from "../src/types";

// Helper function to create canonical message for testing
function createCanonicalMessage(pubkey: string): Uint8Array {
  const windowStart = Math.floor(Date.now() / 120000) * 120000; // 2 minute TTL
  return serializeCanonical({ pubkey, windowStart });
}

describe("Enhanced Security - Brute Force Resistance", () => {
  let protocol: ActionCodesProtocol;
  const config: CodeGenerationConfig = {
    codeLength: 8,
    ttlMs: 120000, // 2 minutes
  };

  beforeEach(() => {
    protocol = new ActionCodesProtocol(config);
  });

  describe("Signature-based Code Generation", () => {
    const strategy = new WalletStrategy({
      codeLength: 8,
      ttlMs: 120000,
    });

    test("generates different codes with different signatures", () => {
      const pubkey = "test-pubkey-security";
      const signature1 = "testsignature1";
      const signature2 = "testsignature2";

      const canonicalMessage1 = createCanonicalMessage(pubkey);
      const canonicalMessage2 = createCanonicalMessage(pubkey);
      
      const result1 = strategy.generateCode(canonicalMessage1, signature1);
      const result2 = strategy.generateCode(canonicalMessage2, signature2);

      // Codes should be different due to different signatures
      expect(result1.actionCode.code).not.toBe(result2.actionCode.code);
      expect(result1.actionCode.signature).toBe(signature1);
      expect(result2.actionCode.signature).toBe(signature2);
    });

    test("generates same codes with same signature (deterministic)", () => {
      const pubkey = "test-pubkey-deterministic";
      const signature = "testsignature";

      const canonicalMessage = createCanonicalMessage(pubkey);
      const result1 = strategy.generateCode(canonicalMessage, signature);
      const result2 = strategy.generateCode(canonicalMessage, signature);

      // Should be identical
      expect(result1.actionCode.code).toBe(result2.actionCode.code);
      expect(result1.actionCode.timestamp).toBe(result2.actionCode.timestamp);
      expect(result1.actionCode.signature).toBe(result2.actionCode.signature);
    });

    test("validates that signature is required", () => {
      const pubkey = "test-pubkey-signature-required";
      const canonicalMessage = createCanonicalMessage(pubkey);

      // Should throw error if invalid signature provided
      expect(() => {
        strategy.generateCode(canonicalMessage, "invalid-base58");
      }).toThrow();
    });
  });

  describe("HMAC Security with Signatures", () => {
    test("HMAC with different signatures produces different results", () => {
      const pubkey = "test-pubkey-hmac-different";
      const canonical = serializeCanonical({ pubkey, windowStart: Date.now() });

      const signature1 = "testsignature1";
      const signature2 = "testsignature2";

      const hmac1 = hmacSha256(Buffer.from(signature1), canonical);
      const hmac2 = hmacSha256(Buffer.from(signature2), canonical);

      expect(Array.from(hmac1)).not.toEqual(Array.from(hmac2));
    });

    test("HMAC produces consistent results with same signature", () => {
      const pubkey = "test-pubkey-hmac-consistent";
      const canonical = serializeCanonical({ pubkey, windowStart: Date.now() });
      const signature = "testsignature";

      const hmac1 = hmacSha256(Buffer.from(signature), canonical);
      const hmac2 = hmacSha256(Buffer.from(signature), canonical);

      expect(Array.from(hmac1)).toEqual(Array.from(hmac2));
      expect(hmac1.length).toBe(32);
    });
  });

  describe("Brute Force Resistance Analysis", () => {
    test("code space analysis for different lengths", () => {
      const pubkey = "test-pubkey-brute-force";
      const signature = "testsignature";

      const lengths = [6, 8, 12, 16, 20, 24];
      const results: { length: number; code: string }[] = [];

      for (const length of lengths) {
        const strategy = new WalletStrategy({
          codeLength: length,
          ttlMs: 120000,
        });

        const canonicalMessage = createCanonicalMessage(pubkey);
        const result = strategy.generateCode(canonicalMessage, signature);
        results.push({ length, code: result.actionCode.code });
      }

      // All codes should be different lengths
      results.forEach((result, index) => {
        expect(result.code).toHaveLength(lengths[index]!);
        expect(result.code).toMatch(/^\d+$/);
      });

      // Calculate theoretical brute force resistance
      const bruteForceResistance = results.map((r) => ({
        length: r.length,
        possibleCodes: Math.pow(10, r.length),
        bitsOfEntropy: Math.log2(Math.pow(10, r.length)),
        timeToBruteForce: Math.pow(10, r.length) / 1000000, // Assuming 1M attempts/second
      }));

      console.log("\n=== Brute Force Resistance Analysis ===");
      bruteForceResistance.forEach((bf) => {
        console.log(
          `${
            bf.length
          } digits: ${bf.possibleCodes.toLocaleString()} codes, ${bf.bitsOfEntropy.toFixed(
            1
          )} bits, ${(bf.timeToBruteForce / 3600).toFixed(2)} hours at 1M/sec`
        );
      });
    });

    test("signature entropy analysis", () => {
      const signatures = Array.from({ length: 1000 }, (_, i) => 
        `testsignature${i}${Math.random().toString(36).substring(2, 15)}`
      );

      // All signatures should be unique
      const uniqueSignatures = new Set(signatures);
      expect(uniqueSignatures.size).toBe(signatures.length);

      console.log(`\n=== Signature Entropy Analysis ===`);
      console.log(`Generated ${signatures.length} unique signatures`);
      console.log(
        `Average signature length: ${
          signatures.reduce((sum, s) => sum + s.length, 0) / signatures.length
        } characters`
      );
    });
  });

  describe("Rate Limiting and Relayer Security", () => {
    test("simulates brute force attack with rate limiting", () => {
      const pubkey = "test-pubkey-rate-limit";
      const signature = "testsignature";
      const validCode = new WalletStrategy({
        codeLength: 8,
        ttlMs: 120000,
      }).generateCode(
        createCanonicalMessage(pubkey),
        signature
      );

      // Simulate rate limiting: 10 attempts per minute
      const maxAttempts = 10;
      const timeWindow = 60000; // 1 minute
      let attempts = 0;
      let startTime = Date.now();

      const attemptBruteForce = () => {
        attempts++;
        const now = Date.now();

        // Reset counter if time window passed
        if (now - startTime > timeWindow) {
          attempts = 1;
          startTime = now;
        }

        // Check if we've hit rate limit
        if (attempts > maxAttempts) {
          return { success: false, reason: "Rate limited", attempts };
        }

        // Generate random code to simulate brute force attempt
        const randomCode = Math.random()
          .toString()
          .slice(2, 10)
          .padStart(8, "0");

        // Check if it matches (extremely unlikely)
        if (randomCode === validCode.actionCode.code) {
          return { success: true, attempts };
        }

        return { success: false, reason: "Wrong code", attempts };
      };

      // Simulate multiple attempts
      const results: { success: boolean; reason?: string; attempts: number }[] =
        [];
      for (let i = 0; i < 50; i++) {
        results.push(attemptBruteForce());
      }

      // Should not find the correct code
      const successfulAttempts = results.filter((r) => r.success);
      expect(successfulAttempts).toHaveLength(0);

      // Should hit rate limit
      const rateLimitedAttempts = results.filter(
        (r) => r.reason === "Rate limited"
      );
      expect(rateLimitedAttempts.length).toBeGreaterThan(0);

      console.log(`\n=== Rate Limiting Simulation ===`);
      console.log(`Total attempts: ${results.length}`);
      console.log(`Rate limited attempts: ${rateLimitedAttempts.length}`);
      console.log(`Successful brute force: ${successfulAttempts.length}`);
    });

    test("validates that signature-based codes are secure", () => {
      const pubkey = "test-pubkey-signature-security";

      const strategy = new WalletStrategy({
        codeLength: 8,
        ttlMs: 120000,
      });

      // Generate codes with different signatures
      const signature1 = "testsignature1";
      const signature2 = "testsignature2";
      const canonicalMessage1 = createCanonicalMessage(pubkey);
      const canonicalMessage2 = createCanonicalMessage(pubkey);
      
      const result1 = strategy.generateCode(canonicalMessage1, signature1);
      const result2 = strategy.generateCode(canonicalMessage2, signature2);

      // Both should validate correctly
      expect(() => {
        strategy.validateCode(result1.actionCode);
      }).not.toThrow();

      expect(() => {
        strategy.validateCode(result2.actionCode);
      }).not.toThrow();

      // Signature-based codes should be different and unpredictable
      expect(result1.actionCode.code).not.toBe(result2.actionCode.code);
      expect(result1.actionCode.signature).toBe(signature1);
      expect(result2.actionCode.signature).toBe(signature2);
    });
  });

  describe("Security Recommendations Validation", () => {
    test("validates minimum recommended code length", () => {
      const pubkey = "test-pubkey-min-length";
      const signature = "testsignature";

      const strategy = new WalletStrategy({
        codeLength: 8,
        ttlMs: 120000,
      });

      // Test minimum recommended length (8 digits)
      const canonicalMessage = createCanonicalMessage(pubkey);
      const result = strategy.generateCode(canonicalMessage, signature);

      expect(result.actionCode.code).toHaveLength(8);
      expect(result.actionCode.code).toMatch(/^\d+$/);

      // 8 digits = 10^8 = 100M possible codes
      // At 1M attempts/second, would take ~100 seconds to brute force
      // This is acceptable for 2-minute TTL
    });

    test("validates that longer codes are more secure", () => {
      const pubkey = "test-pubkey-length-comparison";
      const signature = "testsignature";

      const strategy = new WalletStrategy({
        codeLength: 6,
        ttlMs: 120000,
      });

      const canonicalMessage = createCanonicalMessage(pubkey);
      const shortCode = strategy.generateCode(canonicalMessage, signature);

      const longStrategy = new WalletStrategy({
        codeLength: 12,
        ttlMs: 120000,
      });

      const longCode = longStrategy.generateCode(
        createCanonicalMessage(pubkey),
        signature
      );

      expect(shortCode.actionCode.code).toHaveLength(6);
      expect(longCode.actionCode.code).toHaveLength(12);

      // Longer codes provide exponentially more security
      const shortEntropy = Math.log2(Math.pow(10, 6));
      const longEntropy = Math.log2(Math.pow(10, 12));

      expect(longEntropy).toBeGreaterThan(shortEntropy);
      expect(longEntropy / shortEntropy).toBe(2); // 12 digits = 2x the entropy of 6 digits
    });

    test("validates TTL provides adequate protection", () => {
      const pubkey = "test-pubkey-ttl";
      const signature = "testsignature";

      const strategy = new WalletStrategy({
        codeLength: 8,
        ttlMs: 120000,
      });

      const canonicalMessage = createCanonicalMessage(pubkey);
      const result = strategy.generateCode(canonicalMessage, signature);

      // Code should expire in 2 minutes
      expect(result.actionCode.expiresAt - result.actionCode.timestamp).toBe(
        120000
      );

      // Current time should be within valid range
      const now = Date.now();
      expect(now).toBeGreaterThanOrEqual(result.actionCode.timestamp);
      expect(now).toBeLessThanOrEqual(result.actionCode.expiresAt);
    });
  });
});
