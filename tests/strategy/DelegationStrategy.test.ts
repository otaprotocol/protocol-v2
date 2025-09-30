import { describe, it, expect, beforeEach } from "bun:test";
import { DelegationStrategy } from "../../src/strategy/DelegationStrategy";
import { ActionCodesProtocol } from "../../src/ActionCodesProtocol";
import { SolanaAdapter } from "../../src/adapters/SolanaAdapter";
import {
  generateNonce,
} from "../../src/utils/crypto";
import type {
  DelegationCertificate,
  DelegatedActionCode,
} from "../../src/types";
import bs58 from "bs58";

// Mock wallet for testing
class MockWallet {
  constructor(public publicKey: string, private privateKey: Uint8Array) {}

  async signMessage(message: Uint8Array): Promise<string> {
    // Create a deterministic mock signature that can be verified
    // We'll use the first 32 bytes of the message as the signature data
    const signature = new Uint8Array(64);
    const messageHash = message.slice(0, 32);
    signature.set(messageHash, 0);
    signature.set(messageHash, 32);
    
    // Convert to base58 (simulating what a real wallet would do)
    return bs58.encode(signature);
  }
}

describe("DelegationStrategy", () => {
  let strategy: DelegationStrategy;
  let mockWallet: MockWallet;
  let certificate: DelegationCertificate;

  beforeEach(async () => {
    strategy = new DelegationStrategy({
      ttlMs: 300000, // 5 minutes
      codeLength: 6,
      clockSkewMs: 30000,
    });

    // Create mock wallet
    const privateKey = new Uint8Array(32);
    crypto.getRandomValues(privateKey);
    mockWallet = new MockWallet(
      "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      privateKey
    );

    // Create a valid certificate template
    const template = DelegationStrategy.createDelegationCertificateTemplate(
      mockWallet.publicKey,
      3600000, // 1 hour
      "solana"
    );
    
    // Sign the certificate with the mock wallet
    const message = DelegationStrategy.serializeCertificate(template);
    const signature = await mockWallet.signMessage(message);
    
    certificate = {
      ...template,
      signature,
    };
  });

  describe("createDelegationCertificateTemplate", () => {
    it("should create a valid certificate template", () => {
      const template = DelegationStrategy.createDelegationCertificateTemplate(
        "test-pubkey",
        3600000,
        "solana"
      );

      expect(template.version).toBe("1.0");
      expect(template.delegator).toBe("test-pubkey");
      expect(template.chain).toBe("solana");
      expect(template.issuedAt).toBeLessThanOrEqual(Date.now());
      expect(template.expiresAt).toBe(template.issuedAt + 3600000);
      expect(template.nonce).toBeDefined();
      expect(template.nonce.length).toBeGreaterThan(0);
    });

    it("should use current time for issuedAt", () => {
      const before = Date.now();
      const template =
        DelegationStrategy.createDelegationCertificateTemplate("test-pubkey");
      const after = Date.now();

      expect(template.issuedAt).toBeGreaterThanOrEqual(before);
      expect(template.issuedAt).toBeLessThanOrEqual(after);
    });

    it("should set correct expiration time", () => {
      const template = DelegationStrategy.createDelegationCertificateTemplate(
        "test-pubkey",
        7200000 // 2 hours
      );

      expect(template.expiresAt).toBe(template.issuedAt + 7200000);
    });
  });

  describe("generateDelegatedCode", () => {
    it("should generate a valid delegated action code", () => {
      const result = strategy.generateDelegatedCode(certificate);

      expect(result.actionCode).toBeDefined();
      expect(result.actionCode.code).toBeDefined();
      expect(result.actionCode.pubkey).toBe(mockWallet.publicKey);
      expect(result.actionCode.delegationId).toBe(DelegationStrategy.hashCertificate(certificate));
      expect(result.actionCode.delegatedBy).toBe(mockWallet.publicKey);
    });

    it("should generate deterministic codes for the same certificate", () => {
      const result1 = strategy.generateDelegatedCode(certificate);
      const result2 = strategy.generateDelegatedCode(certificate);

      expect(result1.actionCode.code).toBe(result2.actionCode.code);
      expect(result1.actionCode.delegationId).toBe(
        result2.actionCode.delegationId
      );
    });

    it("should generate different codes for different certificates", async () => {
      const template2 = DelegationStrategy.createDelegationCertificateTemplate(
        mockWallet.publicKey,
        3600000,
        "solana"
      );
      
      const message2 = DelegationStrategy.serializeCertificate(template2);
      const signature2 = await mockWallet.signMessage(message2);
      
      const certificate2 = {
        ...template2,
        signature: signature2,
      };

      const result1 = strategy.generateDelegatedCode(certificate);
      const result2 = strategy.generateDelegatedCode(certificate2);

      expect(result1.actionCode.code).not.toBe(result2.actionCode.code);
      expect(result1.actionCode.delegationId).not.toBe(
        result2.actionCode.delegationId
      );
    });

    it("should throw error for expired certificate", async () => {
      const expiredTemplate =
        DelegationStrategy.createDelegationCertificateTemplate(
          mockWallet.publicKey,
          -1000 // Expired 1 second ago
        );
      
      const message = DelegationStrategy.serializeCertificate(expiredTemplate);
      const signature = await mockWallet.signMessage(message);
      
      const expiredCertificate = {
        ...expiredTemplate,
        signature,
      };

      expect(() => {
        strategy.generateDelegatedCode(expiredCertificate);
      }).toThrow("Invalid delegation certificate");
    });

    it("should throw error for future certificate", async () => {
      const futureTemplate =
        DelegationStrategy.createDelegationCertificateTemplate(
          mockWallet.publicKey,
          3600000
        );
      
      const futureTemplateWithFutureTime = {
        ...futureTemplate,
        issuedAt: Date.now() + 3600000, // Issued 1 hour in the future
      };
      
      const message = DelegationStrategy.serializeCertificate(futureTemplateWithFutureTime);
      const signature = await mockWallet.signMessage(message);
      
      const futureCertificate = {
        ...futureTemplateWithFutureTime,
        signature,
      };

      expect(() => {
        strategy.generateDelegatedCode(futureCertificate);
      }).toThrow("Invalid delegation certificate");
    });
  });

  describe("validateDelegatedCode", () => {
    it("should validate a valid delegated action code", () => {
      const result = strategy.generateDelegatedCode(certificate);

      expect(() => {
        strategy.validateDelegatedCode(result.actionCode, certificate);
      }).not.toThrow();
    });

    it("should throw error for expired certificate", () => {
      const result = strategy.generateDelegatedCode(certificate);
      const expiredCertificate = {
        ...certificate,
        expiresAt: Date.now() - 1000, // Expired
      };

      expect(() => {
        strategy.validateDelegatedCode(result.actionCode, expiredCertificate);
      }).toThrow("Delegation certificate expired or invalid");
    });

    it("should throw error for mismatched delegation ID", () => {
      const result = strategy.generateDelegatedCode(certificate);
      const differentCertificate = {
        ...certificate,
        nonce: "different-nonce",
      };

      expect(() => {
        strategy.validateDelegatedCode(result.actionCode, differentCertificate);
      }).toThrow("Action code does not match delegation certificate");
    });

    it("should throw error for mismatched delegator", () => {
      const result = strategy.generateDelegatedCode(certificate);
      const differentCertificate = {
        ...certificate,
        delegator: "different-pubkey",
      };

      expect(() => {
        strategy.validateDelegatedCode(result.actionCode, differentCertificate);
      }).toThrow("Action code does not match delegation certificate");
    });
  });

  describe("integration with ActionCodesProtocol", () => {
    it("should generate valid delegated action codes", () => {
      const result = strategy.generateDelegatedCode(certificate);

      // The generated action code should have the correct structure
      expect(result.actionCode).toBeDefined();
      expect(result.actionCode.code).toBeDefined();
      expect(result.actionCode.pubkey).toBe(mockWallet.publicKey);
      expect(result.actionCode.delegationId).toBeDefined();
      expect(result.actionCode.delegatedBy).toBe(mockWallet.publicKey);
      
      // The strategy's own validation should pass
      expect(() => {
        strategy.validateDelegatedCode(result.actionCode, certificate);
      }).not.toThrow();
    });

    it("should generate codes with correct TTL", () => {
      const result = strategy.generateDelegatedCode(certificate);

      const now = Date.now();
      expect(result.actionCode.timestamp).toBeLessThanOrEqual(now);
      expect(result.actionCode.expiresAt).toBe(
        result.actionCode.timestamp + 300000
      ); // 5 minutes
    });

    it("should generate codes with correct length", () => {
      const result = strategy.generateDelegatedCode(certificate);

      expect(result.actionCode.code.length).toBe(6);
    });
  });

  describe("deterministic generation", () => {
    it("should generate same code for same certificate across different instances", () => {
      const strategy1 = new DelegationStrategy({
        ttlMs: 300000,
        codeLength: 6,
        clockSkewMs: 30000,
      });
      const strategy2 = new DelegationStrategy({
        ttlMs: 300000,
        codeLength: 6,
        clockSkewMs: 30000,
      });

      const result1 = strategy1.generateDelegatedCode(certificate);
      const result2 = strategy2.generateDelegatedCode(certificate);

      expect(result1.actionCode.code).toBe(result2.actionCode.code);
      expect(result1.actionCode.delegationId).toBe(
        result2.actionCode.delegationId
      );
    });

    it("should generate same codes for same certificate (deterministic)", async () => {
      const result1 = strategy.generateDelegatedCode(certificate);

      // Wait a bit
      await new Promise((resolve) => setTimeout(resolve, 100));

      const result2 = strategy.generateDelegatedCode(certificate);

      // Codes should be the same because certificate-based generation is deterministic
      expect(result1.actionCode.code).toBe(result2.actionCode.code);
      expect(result1.actionCode.delegationId).toBe(result2.actionCode.delegationId);
    });
  });
});
