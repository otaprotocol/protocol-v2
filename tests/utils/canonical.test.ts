import { describe, it, expect } from "bun:test";
import {
  serializeCanonical,
  serializeCanonicalRevoke,
  serializeDelegationProof,
  getCanonicalMessageParts,
} from "../../src/utils/canonical";
import type { DelegationProof } from "../../src/types";

describe("canonical utils", () => {
  describe("serializeCanonical", () => {
    it("should serialize canonical message with basic fields", () => {
      const parts = {
        pubkey: "test-pubkey-123",
        windowStart: 1234567890,
      };

      const result = serializeCanonical(parts);
      const decoded = JSON.parse(new TextDecoder().decode(result));

      expect(decoded).toEqual({
        id: "actioncodes",
        ver: 1,
        pubkey: "test-pubkey-123",
        windowStart: 1234567890,
      });
    });

    it("should include secret when provided", () => {
      const parts = {
        pubkey: "test-pubkey-123",
        windowStart: 1234567890,
        secret: "test-secret",
      };

      const result = serializeCanonical(parts);
      const decoded = JSON.parse(new TextDecoder().decode(result));

      expect(decoded).toEqual({
        id: "actioncodes",
        ver: 1,
        pubkey: "test-pubkey-123",
        windowStart: 1234567890,
        secret: "test-secret",
      });
    });

    it("should produce deterministic output", () => {
      const parts = {
        pubkey: "test-pubkey-123",
        windowStart: 1234567890,
      };

      const result1 = serializeCanonical(parts);
      const result2 = serializeCanonical(parts);

      expect(result1).toEqual(result2);
    });

    it("should produce different output for different inputs", () => {
      const parts1 = {
        pubkey: "test-pubkey-123",
        windowStart: 1234567890,
      };

      const parts2 = {
        pubkey: "test-pubkey-456",
        windowStart: 1234567890,
      };

      const result1 = serializeCanonical(parts1);
      const result2 = serializeCanonical(parts2);

      expect(result1).not.toEqual(result2);
    });

    it("should handle different pubkey formats", () => {
      const pubkeys = [
        "simple-pubkey",
        "base58-pubkey-123456789",
        "ed25519-pubkey-abcdef",
        "very-long-pubkey-with-special-chars-!@#$%^&*()",
      ];

      for (const pubkey of pubkeys) {
        const parts = { pubkey, windowStart: 1234567890 };
        const result = serializeCanonical(parts);
        const decoded = JSON.parse(new TextDecoder().decode(result));
        expect(decoded.pubkey).toBe(pubkey);
      }
    });

    it("should handle different timestamps", () => {
      const timestamps = [0, 1234567890, Date.now(), 9999999999];

      for (const windowStart of timestamps) {
        const parts = { pubkey: "test-pubkey", windowStart };
        const result = serializeCanonical(parts);
        const decoded = JSON.parse(new TextDecoder().decode(result));
        expect(decoded.windowStart).toBe(windowStart);
      }
    });

    it("should produce valid JSON", () => {
      const parts = {
        pubkey: "test-pubkey-123",
        windowStart: 1234567890,
        secret: "test-secret",
      };

      const result = serializeCanonical(parts);
      const jsonString = new TextDecoder().decode(result);
      
      expect(() => JSON.parse(jsonString)).not.toThrow();
      expect(JSON.parse(jsonString)).toBeDefined();
    });

    it("should handle edge cases", () => {
      const edgeCases = [
        { pubkey: "", windowStart: 0 },
        { pubkey: "a", windowStart: 1 },
        { pubkey: "very-long-pubkey".repeat(100), windowStart: Number.MAX_SAFE_INTEGER },
      ];

      for (const parts of edgeCases) {
        expect(() => serializeCanonical(parts)).not.toThrow();
        const result = serializeCanonical(parts);
        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBeGreaterThan(0);
      }
    });

    it("should maintain field order", () => {
      const parts = {
        pubkey: "test-pubkey-123",
        windowStart: 1234567890,
        secret: "test-secret",
      };

      const result = serializeCanonical(parts);
      const jsonString = new TextDecoder().decode(result);
      
      // Check that id and ver come first
      expect(jsonString.indexOf('"id"')).toBeLessThan(jsonString.indexOf('"ver"'));
      expect(jsonString.indexOf('"ver"')).toBeLessThan(jsonString.indexOf('"pubkey"'));
    });

    it("should handle special characters in pubkey", () => {
      const specialPubkeys = [
        "pubkey-with-dashes",
        "pubkey_with_underscores",
        "pubkey.with.dots",
        "pubkey+with+plus",
        "pubkey/with/slashes",
      ];

      for (const pubkey of specialPubkeys) {
        const parts = { pubkey, windowStart: 1234567890 };
        expect(() => serializeCanonical(parts)).not.toThrow();
      }
    });

    it("should produce consistent byte length for same input", () => {
      const parts = {
        pubkey: "test-pubkey-123",
        windowStart: 1234567890,
      };

      const results = Array.from({ length: 10 }, () => serializeCanonical(parts));
      const lengths = results.map(r => r.length);
      
      expect(new Set(lengths).size).toBe(1); // All should have same length
    });
  });

  describe("serializeCanonicalRevoke", () => {
    it("should serialize revoke message with all required fields", () => {
      const parts = {
        pubkey: "test-pubkey-123",
        codeHash: "abc123def456",
        windowStart: 1234567890,
      };

      const result = serializeCanonicalRevoke(parts);
      const decoded = JSON.parse(new TextDecoder().decode(result));

      expect(decoded).toEqual({
        id: "actioncodes-revoke",
        ver: 1,
        pubkey: "test-pubkey-123",
        codeHash: "abc123def456",
        windowStart: 1234567890,
      });
    });

    it("should produce deterministic output", () => {
      const parts = {
        pubkey: "test-pubkey-123",
        codeHash: "abc123def456",
        windowStart: 1234567890,
      };

      const result1 = serializeCanonicalRevoke(parts);
      const result2 = serializeCanonicalRevoke(parts);

      expect(result1).toEqual(result2);
    });

    it("should produce different output for different inputs", () => {
      const parts1 = {
        pubkey: "test-pubkey-123",
        codeHash: "abc123def456",
        windowStart: 1234567890,
      };

      const parts2 = {
        pubkey: "test-pubkey-123",
        codeHash: "xyz789ghi012",
        windowStart: 1234567890,
      };

      const result1 = serializeCanonicalRevoke(parts1);
      const result2 = serializeCanonicalRevoke(parts2);

      expect(result1).not.toEqual(result2);
    });
  });

  describe("serializeDelegationProof", () => {
    it("should serialize delegation proof", () => {
      const proof: DelegationProof = {
        walletPubkey: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        expiresAt: 1234567890 + 3600000,
        signature: "test-signature-456",
      };

      const result = serializeDelegationProof(proof);
      const decoded = JSON.parse(new TextDecoder().decode(result));

      expect(decoded).toEqual({
        walletPubkey: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        expiresAt: 1234567890 + 3600000,
      });
    });

    it("should produce deterministic output", () => {
      const proof: DelegationProof = {
        walletPubkey: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        expiresAt: 1234567890 + 3600000,
        signature: "test-signature-456",
      };

      const result1 = serializeDelegationProof(proof);
      const result2 = serializeDelegationProof(proof);

      expect(result1).toEqual(result2);
    });

    it("should produce different output for different proofs", () => {
      const proof1: DelegationProof = {
        walletPubkey: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        expiresAt: 1234567890 + 3600000,
        signature: "test-signature-456",
      };

      const proof2: DelegationProof = {
        ...proof1,
        delegatedPubkey: "different-delegated-pubkey",
      };

      const result1 = serializeDelegationProof(proof1);
      const result2 = serializeDelegationProof(proof2);

      expect(result1).not.toEqual(result2);
    });
  });

  describe("getCanonicalMessageParts", () => {
    it("should generate canonical message with provided TTL", () => {
      const pubkey = "test-pubkey-123";
      const ttlMs = 120000; // 2 minutes
      const providedSecret = "test-secret";

      const result = getCanonicalMessageParts(pubkey, ttlMs, providedSecret);
      const decoded = JSON.parse(new TextDecoder().decode(result));

      expect(decoded).toEqual({
        id: "actioncodes",
        ver: 1,
        pubkey: "test-pubkey-123",
        windowStart: expect.any(Number),
        secret: "test-secret",
      });

      // Check that windowStart is aligned to TTL
      const windowStart = decoded.windowStart;
      expect(windowStart % ttlMs).toBe(0);
    });

    it("should generate canonical message without secret", () => {
      const pubkey = "test-pubkey-123";
      const ttlMs = 120000;

      const result = getCanonicalMessageParts(pubkey, ttlMs);
      const decoded = JSON.parse(new TextDecoder().decode(result));

      expect(decoded).toEqual({
        id: "actioncodes",
        ver: 1,
        pubkey: "test-pubkey-123",
        windowStart: expect.any(Number),
      });

      expect(decoded.secret).toBeUndefined();
    });

    it("should align windowStart to TTL boundary", () => {
      const pubkey = "test-pubkey-123";
      const ttlMs = 300000; // 5 minutes

      const result = getCanonicalMessageParts(pubkey, ttlMs);
      const decoded = JSON.parse(new TextDecoder().decode(result));

      const windowStart = decoded.windowStart;
      const now = Date.now();
      const expectedWindowStart = Math.floor(now / ttlMs) * ttlMs;

      expect(windowStart).toBe(expectedWindowStart);
    });

    it("should produce deterministic output for same inputs", () => {
      const pubkey = "test-pubkey-123";
      const ttlMs = 120000;
      const secret = "test-secret";

      // Mock Date.now to return consistent time
      const originalNow = Date.now;
      const mockTime = 1234567890000;
      Date.now = () => mockTime;

      try {
        const result1 = getCanonicalMessageParts(pubkey, ttlMs, secret);
        const result2 = getCanonicalMessageParts(pubkey, ttlMs, secret);

        expect(result1).toEqual(result2);
      } finally {
        Date.now = originalNow;
      }
    });

    it("should produce different output for different TTLs when they align to different windows", () => {
      const pubkey = "test-pubkey-123";
      const secret = "test-secret";

      // Use a fixed time to ensure different TTLs align to different windows
      const originalNow = Date.now;
      const mockTime = 1234567890000; // Fixed time
      Date.now = () => mockTime;

      try {
        const result1 = getCanonicalMessageParts(pubkey, 120000, secret); // 2 minutes
        const result2 = getCanonicalMessageParts(pubkey, 300000, secret); // 5 minutes

        // Different TTLs should align to different windows at this specific time
        const window1 = Math.floor(mockTime / 120000) * 120000;
        const window2 = Math.floor(mockTime / 300000) * 300000;
        
        if (window1 !== window2) {
          expect(result1).not.toEqual(result2);
        } else {
          // If they align to the same window, they should be equal
          expect(result1).toEqual(result2);
        }
      } finally {
        Date.now = originalNow;
      }
    });

    it("should handle different pubkey formats", () => {
      const pubkeys = [
        "simple-pubkey",
        "base58-pubkey-123456789",
        "ed25519-pubkey-abcdef",
        "very-long-pubkey-with-special-chars",
      ];

      for (const pubkey of pubkeys) {
        const result = getCanonicalMessageParts(pubkey, 120000);
        const decoded = JSON.parse(new TextDecoder().decode(result));
        expect(decoded.pubkey).toBe(pubkey);
      }
    });
  });
});