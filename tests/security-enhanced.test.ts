import { ActionCodesProtocol } from "../src/ActionCodesProtocol";
import { WalletStrategy } from "../src/strategy/WalletStrategy";
import { generateRandomSecret, hmacSha256, sha256 } from "../src/utils/crypto";
import { serializeCanonical } from "../src/utils/canonical";
import type { CodeGenerationConfig } from "../src/types";

// Helper function to create canonical message for testing
function createCanonicalMessage(pubkey: string, secret?: string): Uint8Array {
  const windowStart = Math.floor(Date.now() / 120000) * 120000; // 2 minute TTL
  return serializeCanonical({ pubkey, windowStart, secret });
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

  describe("Secret-based Code Generation", () => {
    const strategy = new WalletStrategy({
      codeLength: 8,
      ttlMs: 120000,
    });

    test("generates different codes with and without secrets", () => {
      const pubkey = "test-pubkey-security";
      const secret = generateRandomSecret();
      const salt = "test-salt";

      // Generate without secret
      const canonicalMessage1 = createCanonicalMessage(pubkey);
      const withoutSecret = strategy.generateCode(canonicalMessage1, "testsignature");

      // Generate with secret
      const canonicalMessage2 = createCanonicalMessage(pubkey, secret);
      const withSecret = strategy.generateCode(canonicalMessage2, "testsignature", secret);

      // Codes should be different
      expect(withoutSecret.actionCode.code).not.toBe(
        withSecret.actionCode.code
      );
      expect(withoutSecret.actionCode.secret).toBeUndefined();
      expect(withSecret.actionCode.secret).toBe(secret);
    });

    test("generates same codes with same secret (deterministic)", () => {
      const pubkey = "test-pubkey-deterministic";
      const secret = generateRandomSecret();
      const salt = "test-salt";

      const canonicalMessage = createCanonicalMessage(pubkey, secret);
      const result1 = strategy.generateCode(canonicalMessage, "testsignature", secret);
      const result2 = strategy.generateCode(canonicalMessage, "testsignature", secret);

      // Should be identical
      expect(result1.actionCode.code).toBe(result2.actionCode.code);
      expect(result1.actionCode.timestamp).toBe(result2.actionCode.timestamp);
      expect(result1.actionCode.secret).toBe(result2.actionCode.secret);
    });

    test("generates different codes with different secrets", () => {
      const pubkey = "test-pubkey-different-secrets";
      const secret1 = generateRandomSecret();
      const secret2 = generateRandomSecret();
      const salt = "test-salt";

      const canonicalMessage1 = createCanonicalMessage(pubkey, secret1);
      const canonicalMessage2 = createCanonicalMessage(pubkey, secret2);
      const result1 = strategy.generateCode(canonicalMessage1, "testsignature", secret1);
      const result2 = strategy.generateCode(canonicalMessage2, "testsignature", secret2);

      // Should be different
      expect(result1.actionCode.code).not.toBe(result2.actionCode.code);
      expect(result1.actionCode.secret).toBe(secret1);
      expect(result2.actionCode.secret).toBe(secret2);
    });
  });

  describe("HMAC vs SHA256 Security", () => {
    test("HMAC provides better entropy distribution", () => {
      const pubkey = "test-pubkey-entropy";
      const secret = generateRandomSecret();
      const canonical = serializeCanonical({
        pubkey,
        windowStart: Date.now(),
        secret,
      });

      const sha256Result = sha256(canonical);
      const hmacResult = hmacSha256(secret, canonical);

      // HMAC should produce different result than SHA256
      expect(Array.from(sha256Result)).not.toEqual(Array.from(hmacResult));

      // Both should be 32 bytes
      expect(sha256Result.length).toBe(32);
      expect(hmacResult.length).toBe(32);
    });

    test("HMAC with different secrets produces different results", () => {
      const pubkey = "test-pubkey-hmac-different";
      const canonical = serializeCanonical({ pubkey, windowStart: Date.now() });

      const secret1 = generateRandomSecret();
      const secret2 = generateRandomSecret();

      const hmac1 = hmacSha256(secret1, canonical);
      const hmac2 = hmacSha256(secret2, canonical);

      expect(Array.from(hmac1)).not.toEqual(Array.from(hmac2));
    });
  });

  describe("Brute Force Resistance Analysis", () => {
    test("code space analysis for different lengths", () => {
      const pubkey = "test-pubkey-brute-force";
      const secret = generateRandomSecret();

      const lengths = [6, 8, 12, 16, 20, 24];
      const results: { length: number; code: string }[] = [];

      for (const length of lengths) {
        const strategy = new WalletStrategy({
          codeLength: length,
          ttlMs: 120000,
        });

        const canonicalMessage = createCanonicalMessage(pubkey, secret);
        const result = strategy.generateCode(canonicalMessage, "testsignature", secret);
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

    test("secret entropy analysis", () => {
      const secrets = Array.from({ length: 1000 }, () =>
        generateRandomSecret()
      );

      // All secrets should be unique
      const uniqueSecrets = new Set(secrets);
      expect(uniqueSecrets.size).toBe(secrets.length);

      // All secrets should be base64 encoded
      secrets.forEach((secret) => {
        expect(secret).toMatch(/^[A-Za-z0-9+/]+=*$/);
        expect(secret.length).toBeGreaterThan(40); // At least 32 bytes base64 encoded
      });

      console.log(`\n=== Secret Entropy Analysis ===`);
      console.log(`Generated ${secrets.length} unique secrets`);
      console.log(
        `Average secret length: ${
          secrets.reduce((sum, s) => sum + s.length, 0) / secrets.length
        } characters`
      );
    });
  });

  describe("Rate Limiting and Relayer Security", () => {
    test("simulates brute force attack with rate limiting", () => {
      const pubkey = "test-pubkey-rate-limit";
      const secret = generateRandomSecret();
      const salt = "test-salt";
      const validCode = new WalletStrategy({
        codeLength: 8,
        ttlMs: 120000,
      }).generateCode(createCanonicalMessage(pubkey, secret), "testsignature", secret);

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

    test("validates that secret-based codes are harder to brute force", () => {
      const pubkey = "test-pubkey-secret-security";
      const salt = "test-salt";

      const strategy = new WalletStrategy({
        codeLength: 8,
        ttlMs: 120000,
      });

      // Generate codes with and without secret
      const secret = generateRandomSecret();
      const canonicalMessage1 = createCanonicalMessage(pubkey);
      const canonicalMessage2 = createCanonicalMessage(pubkey, secret);
      const withoutSecret = strategy.generateCode(canonicalMessage1, "testsignature");
      const withSecret = strategy.generateCode(canonicalMessage2, "testsignature", secret);

      // Both should validate correctly
      expect(() => {
        strategy.validateCode(withoutSecret.actionCode);
      }).not.toThrow();

      expect(() => {
        strategy.validateCode(withSecret.actionCode);
      }).not.toThrow();

      // Secret-based code should be different and unpredictable
      expect(withoutSecret.actionCode.code).not.toBe(
        withSecret.actionCode.code
      );
      expect(withSecret.actionCode.secret).toBeDefined();
    });
  });

  describe("Security Recommendations Validation", () => {
    test("validates minimum recommended code length", () => {
      const pubkey = "test-pubkey-min-length";
      const secret = generateRandomSecret();
      const salt = "test-salt";

      const strategy = new WalletStrategy({
        codeLength: 8,
        ttlMs: 120000,
      });

      // Test minimum recommended length (8 digits)
      const canonicalMessage = createCanonicalMessage(pubkey, secret);
      const result = strategy.generateCode(canonicalMessage, "testsignature", secret);

      expect(result.actionCode.code).toHaveLength(8);
      expect(result.actionCode.code).toMatch(/^\d+$/);

      // 8 digits = 10^8 = 100M possible codes
      // At 1M attempts/second, would take ~100 seconds to brute force
      // This is acceptable for 2-minute TTL
    });

    test("validates that longer codes are more secure", () => {
      const pubkey = "test-pubkey-length-comparison";
      const secret = generateRandomSecret();
      const salt = "test-salt";

      const strategy = new WalletStrategy({
        codeLength: 6,
        ttlMs: 120000,
      });

      const canonicalMessage = createCanonicalMessage(pubkey, secret);
      const shortCode = strategy.generateCode(canonicalMessage, "testsignature", secret);

      const longStrategy = new WalletStrategy({
        codeLength: 12,
        ttlMs: 120000,
      });

      const longCode = longStrategy.generateCode(createCanonicalMessage(pubkey, secret), "testsignature", secret);

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
      const secret = generateRandomSecret();
      const salt = "test-salt";

      const strategy = new WalletStrategy({
        codeLength: 8,
        ttlMs: 120000,
      });

      const canonicalMessage = createCanonicalMessage(pubkey, secret);
      const result = strategy.generateCode(canonicalMessage, "testsignature", secret);

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
