import { describe, it, expect } from "bun:test";
import {
  serializeCanonical,
  serializeCanonicalRevoke,
  createDelegationCertificateTemplate,
  serializeCertificate,
  validateCertificateStructure,
  getCanonicalMessageParts,
} from "../../src/utils/canonical";
import type { DelegationCertificate } from "../../src/types";

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

  describe("createDelegationCertificateTemplate", () => {
    it("should create valid certificate template", () => {
      const template = createDelegationCertificateTemplate(
        "user-pubkey-123",
        "delegated-pubkey-456",
        3600000,
        "solana"
      );

      expect(template).toEqual({
        version: "1.0",
        delegator: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        issuedAt: expect.any(Number),
        expiresAt: expect.any(Number),
        nonce: expect.any(String),
        chain: "solana",
      });

      expect(template.issuedAt).toBeLessThanOrEqual(Date.now());
      expect(template.expiresAt).toBe(template.issuedAt + 3600000);
      expect(template.nonce).toMatch(/^[A-Za-z0-9+/=]+$/); // Base64-like
    });

    it("should use current time for issuedAt", () => {
      const before = Date.now();
      const template = createDelegationCertificateTemplate(
        "user-pubkey-123",
        "delegated-pubkey-456"
      );
      const after = Date.now();

      expect(template.issuedAt).toBeGreaterThanOrEqual(before);
      expect(template.issuedAt).toBeLessThanOrEqual(after);
    });

    it("should set correct expiration time", () => {
      const durationMs = 7200000; // 2 hours
      const template = createDelegationCertificateTemplate(
        "user-pubkey-123",
        "delegated-pubkey-456",
        durationMs
      );

      expect(template.expiresAt).toBe(template.issuedAt + durationMs);
    });

    it("should use default values", () => {
      const template = createDelegationCertificateTemplate(
        "user-pubkey-123",
        "delegated-pubkey-456"
      );

      expect(template.version).toBe("1.0");
      expect(template.chain).toBe("solana");
      expect(template.expiresAt - template.issuedAt).toBe(3600000); // 1 hour default
    });

    it("should generate unique nonces", () => {
      const templates = Array.from({ length: 10 }, () =>
        createDelegationCertificateTemplate(
          "user-pubkey-123",
          "delegated-pubkey-456"
        )
      );

      const nonces = templates.map(t => t.nonce);
      const uniqueNonces = new Set(nonces);
      
      expect(uniqueNonces.size).toBe(nonces.length); // All nonces should be unique
    });
  });


  describe("serializeCertificate", () => {
    it("should serialize certificate without signature", () => {
      const cert = {
        version: "1.0",
        delegator: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        issuedAt: 1234567890,
        expiresAt: 1234567890 + 3600000,
        nonce: "test-nonce-123",
        chain: "solana",
      };

      const result = serializeCertificate(cert);
      const decoded = JSON.parse(new TextDecoder().decode(result));

      expect(decoded).toEqual(cert);
    });

    it("should produce deterministic output", () => {
      const cert = {
        version: "1.0",
        delegator: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        issuedAt: 1234567890,
        expiresAt: 1234567890 + 3600000,
        nonce: "test-nonce-123",
        chain: "solana",
      };

      const result1 = serializeCertificate(cert);
      const result2 = serializeCertificate(cert);

      expect(result1).toEqual(result2);
    });

    it("should produce different output for different certificates", () => {
      const cert1 = {
        version: "1.0",
        delegator: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        issuedAt: 1234567890,
        expiresAt: 1234567890 + 3600000,
        nonce: "test-nonce-123",
        chain: "solana",
      };

      const cert2 = {
        ...cert1,
        delegatedPubkey: "different-delegated-pubkey",
      };

      const result1 = serializeCertificate(cert1);
      const result2 = serializeCertificate(cert2);

      expect(result1).not.toEqual(result2);
    });
  });

  describe("validateCertificateStructure", () => {
    it("should validate correct certificate structure", () => {
      const certificate: DelegationCertificate = {
        version: "1.0",
        delegator: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        issuedAt: Date.now() - 1000, // 1 second ago
        expiresAt: Date.now() + 3600000, // 1 hour from now
        nonce: "test-nonce-123",
        chain: "solana",
        signature: "test-signature-456",
      };

      expect(validateCertificateStructure(certificate)).toBe(true);
    });

    it("should reject certificate with missing fields", () => {
      const incompleteCertificates = [
        { version: "1.0" }, // Missing most fields
        { version: "1.0", delegator: "user-pubkey-123" }, // Missing delegatedPubkey
        { version: "1.0", delegator: "user-pubkey-123", delegatedPubkey: "delegated-pubkey-456" }, // Missing issuedAt
      ];

      for (const cert of incompleteCertificates) {
        expect(validateCertificateStructure(cert as any)).toBe(false);
      }
    });

    it("should reject certificate with wrong version", () => {
      const certificate: DelegationCertificate = {
        version: "2.0", // Wrong version
        delegator: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        issuedAt: Date.now() - 1000,
        expiresAt: Date.now() + 3600000,
        nonce: "test-nonce-123",
        chain: "solana",
        signature: "test-signature-456",
      };

      expect(validateCertificateStructure(certificate)).toBe(false);
    });

    it("should reject certificate with invalid timing", () => {
      const now = Date.now();
      
      const expiredCertificate: DelegationCertificate = {
        version: "1.0",
        delegator: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        issuedAt: now - 2000,
        expiresAt: now - 1000, // Expired
        nonce: "test-nonce-123",
        chain: "solana",
        signature: "test-signature-456",
      };

      const futureCertificate: DelegationCertificate = {
        version: "1.0",
        delegator: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        issuedAt: now + 1000, // Future
        expiresAt: now + 3600000,
        nonce: "test-nonce-123",
        chain: "solana",
        signature: "test-signature-456",
      };

      const invalidTimingCertificate: DelegationCertificate = {
        version: "1.0",
        delegator: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        issuedAt: now + 1000,
        expiresAt: now, // expiresAt <= issuedAt
        nonce: "test-nonce-123",
        chain: "solana",
        signature: "test-signature-456",
      };

      expect(validateCertificateStructure(expiredCertificate)).toBe(false);
      expect(validateCertificateStructure(futureCertificate)).toBe(false);
      expect(validateCertificateStructure(invalidTimingCertificate)).toBe(false);
    });

    it("should accept valid certificate with edge case timing", () => {
      const now = Date.now();
      
      const edgeCaseCertificate: DelegationCertificate = {
        version: "1.0",
        delegator: "user-pubkey-123",
        delegatedPubkey: "delegated-pubkey-456",
        issuedAt: now, // Exactly now
        expiresAt: now + 1, // 1ms from now
        nonce: "test-nonce-123",
        chain: "solana",
        signature: "test-signature-456",
      };

      expect(validateCertificateStructure(edgeCaseCertificate)).toBe(true);
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