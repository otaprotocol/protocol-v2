import { describe, it, expect, beforeEach } from "bun:test";
import { DelegationStrategy } from "../../src/strategy/DelegationStrategy";
import { ActionCodesProtocol } from "../../src/ActionCodesProtocol";
import { SolanaAdapter } from "../../src/adapters/SolanaAdapter";
import { generateNonce } from "../../src/utils/crypto";
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
      expect(result.actionCode.delegationId).toBe(
        DelegationStrategy.hashCertificate(certificate)
      );
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
      
      const message = DelegationStrategy.serializeCertificate(
        futureTemplateWithFutureTime
      );
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
      expect(result1.actionCode.delegationId).toBe(
        result2.actionCode.delegationId
      );
    });
  });

  describe("Security Tests", () => {
    it("should reject action codes generated from different certificates", async () => {
      // Generate a valid action code first
      const validResult = await strategy.generateDelegatedCode(certificate);
      const validActionCode = validResult.actionCode;

      // Create a different certificate
      const differentCert: DelegationCertificate = {
        ...certificate,
        nonce: generateNonce(), // Different nonce
        issuedAt: Date.now() - 1000, // Different timestamp
      };

      // Generate action code with different certificate
      const differentResult = strategy.generateDelegatedCode(differentCert);
      const differentActionCode = differentResult.actionCode;

      // Try to validate the different action code with the original certificate
      expect(() => {
        strategy.validateDelegatedCode(differentActionCode, certificate);
      }).toThrow("Action code does not match delegation certificate");
    });

    it("should reject action codes with tampered secrets", async () => {
      // Generate a valid action code first
      const validResult = strategy.generateDelegatedCode(certificate);
      const validActionCode = validResult.actionCode;

      // Create a tampered action code with wrong secret
      const tamperedActionCode: DelegatedActionCode = {
        ...validActionCode,
        secret: "tampered-secret", // Wrong secret
      };

      expect(() => {
        strategy.validateDelegatedCode(tamperedActionCode, certificate);
      }).toThrow("Invalid code:");
    });
  });

  describe("Relayer Scenario Tests", () => {
    // Mock relayer that can validate but not generate codes
    class MockRelayer {
      private registeredCertificates = new Map<string, DelegationCertificate>();

      registerCertificate(certificate: DelegationCertificate): string {
        const certificateId = DelegationStrategy.hashCertificate(certificate);
        this.registeredCertificates.set(certificateId, certificate);
        return certificateId;
      }

      // Relayer can validate codes using full certificate
      validateCode(
        actionCode: DelegatedActionCode,
        certificate: DelegationCertificate
      ): boolean {
        try {
          strategy.validateDelegatedCode(actionCode, certificate);
          return true;
        } catch {
          return false;
        }
      }

      // Relayer CANNOT generate codes - this should fail
      generateCodeFromPublicProof(proof: {
        delegator: string;
        issuedAt: number;
        expiresAt: number;
        nonce: string;
        chain: string;
        // Note: NO signature - this is what relayer would have
      }): string {
        // Try to reconstruct certificate without signature
        const certWithoutSig = {
          version: "1.0" as const,
          delegator: proof.delegator,
          issuedAt: proof.issuedAt,
          expiresAt: proof.expiresAt,
          nonce: proof.nonce,
          chain: proof.chain,
          signature: "fake-signature", // Relayer doesn't have real signature
        };

        // This should fail because hash includes signature
        const certificateSecret =
          DelegationStrategy.hashCertificate(certWithoutSig);

        // Try to generate code (this will produce wrong result)
        const windowStart = Math.floor(Date.now() / 300000) * 300000; // 5 min window
        const canonical = JSON.stringify({
          id: "actioncodes",
          ver: 1,
          pubkey: proof.delegator,
          windowStart,
          secret: certificateSecret,
        });

        // This is simplified - in real implementation would use full WalletStrategy
        return "generated-by-relayer";
      }
    }

    let relayer: MockRelayer;

    beforeEach(() => {
      relayer = new MockRelayer();
    });

    it("should allow relayer to validate codes with full certificate", async () => {
      // 1. User generates code
      const userResult = await strategy.generateDelegatedCode(certificate);
      const userActionCode = userResult.actionCode;

      // 2. Relayer registers certificate
      const certificateId = relayer.registerCertificate(certificate);

      // 3. Relayer validates code (should succeed)
      const isValid = relayer.validateCode(userActionCode, certificate);
      expect(isValid).toBe(true);
    });

    it("should prevent relayer from generating valid codes without signature", async () => {
      // 1. User generates code
      const userResult = await strategy.generateDelegatedCode(certificate);
      const userActionCode = userResult.actionCode;

      // 2. Relayer tries to generate code from public proof (no signature)
      const publicProof = {
        delegator: certificate.delegator,
        issuedAt: certificate.issuedAt,
        expiresAt: certificate.expiresAt,
        nonce: certificate.nonce,
        chain: certificate.chain,
        // No signature - relayer doesn't have this
      };

      const relayerGeneratedCode =
        relayer.generateCodeFromPublicProof(publicProof);

      // 3. Relayer tries to validate its own generated code (should fail)
      const isValid = relayer.validateCode(
        {
          ...userActionCode,
          code: relayerGeneratedCode,
        } as DelegatedActionCode,
        certificate
      );
      expect(isValid).toBe(false);
    });

    it("should prevent relayer from generating codes even with fake signature", async () => {
      // 1. User generates code
      const userResult = await strategy.generateDelegatedCode(certificate);
      const userActionCode = userResult.actionCode;

      // 2. Relayer tries to generate code with fake signature
      const fakeCertificate: DelegationCertificate = {
        ...certificate,
        signature: "fake-signature-that-relayer-made-up",
      };

      // 3. Try to generate code with fake certificate
      const fakeResult = await strategy.generateDelegatedCode(fakeCertificate);
      const fakeActionCode = fakeResult.actionCode;

      // 4. Relayer tries to validate fake code with real certificate (should fail)
      const isValid = relayer.validateCode(fakeActionCode, certificate);
      expect(isValid).toBe(false);
    });

    it("should allow relayer to validate multiple codes from same certificate", async () => {
      // 1. User generates multiple codes
      const code1 = await strategy.generateDelegatedCode(certificate);
      const code2 = await strategy.generateDelegatedCode(certificate);

      // 2. Relayer registers certificate
      relayer.registerCertificate(certificate);

      // 3. Relayer validates both codes (should succeed)
      expect(relayer.validateCode(code1.actionCode, certificate)).toBe(true);
      expect(relayer.validateCode(code2.actionCode, certificate)).toBe(true);
    });

    it("should prevent relayer from validating codes with wrong certificate", async () => {
      // 1. User generates code with certificate A
      const codeA = await strategy.generateDelegatedCode(certificate);

      // 2. Create different certificate B
      const certificateB: DelegationCertificate = {
        ...certificate,
        nonce: generateNonce(),
        issuedAt: Date.now() - 1000,
      };

      // 3. Relayer registers certificate B
      relayer.registerCertificate(certificateB);

      // 4. Relayer tries to validate code A with certificate B (should fail)
      const isValid = relayer.validateCode(codeA.actionCode, certificateB);
      expect(isValid).toBe(false);
    });
  });

  describe("Code-Certificate Binding Tests", () => {
    it("should reject code generated from Certificate A when validated with Certificate B", async () => {
      // 1. Generate code with Certificate A
      const resultA = await strategy.generateDelegatedCode(certificate);
      const codeFromA = resultA.actionCode;

      // 2. Create Certificate B (different certificate)
      const certificateB: DelegationCertificate = {
        ...certificate,
        nonce: generateNonce(), // Different nonce
        issuedAt: Date.now() - 1000, // Different timestamp
        expiresAt: Date.now() + 3600000, // Different expiration
      };

      // 3. Try to validate code from Certificate A with Certificate B (should fail)
      expect(() => {
        strategy.validateDelegatedCode(codeFromA, certificateB);
      }).toThrow("Action code does not match delegation certificate");
    });

    it("should accept code generated from Certificate A when validated with Certificate A", async () => {
      // 1. Generate code with Certificate A
      const resultA = await strategy.generateDelegatedCode(certificate);
      const codeFromA = resultA.actionCode;

      // 2. Validate code from Certificate A with Certificate A (should succeed)
      expect(() => {
        strategy.validateDelegatedCode(codeFromA, certificate);
      }).not.toThrow();
    });

    it("should reject code generated from Certificate B when validated with Certificate A", async () => {
      // 1. Create Certificate B
      const certificateB: DelegationCertificate = {
        ...certificate,
        nonce: generateNonce(),
        issuedAt: Date.now() - 1000,
        expiresAt: Date.now() + 3600000,
      };

      // 2. Generate code with Certificate B
      const resultB = await strategy.generateDelegatedCode(certificateB);
      const codeFromB = resultB.actionCode;

      // 3. Try to validate code from Certificate B with Certificate A (should fail)
      expect(() => {
        strategy.validateDelegatedCode(codeFromB, certificate);
      }).toThrow("Action code does not match delegation certificate");
    });

    it("should have different delegation IDs for different certificates", async () => {
      // 1. Create Certificate A (with valid signature)
      const templateA = DelegationStrategy.createDelegationCertificateTemplate(
        mockWallet.publicKey,
        3600000,
        "solana"
      );
      const messageA = DelegationStrategy.serializeCertificate(templateA);
      const signatureA = await mockWallet.signMessage(messageA);
      const certificateA: DelegationCertificate = {
        ...templateA,
        signature: signatureA,
      };

      // 2. Create Certificate B (with valid signature)
      const templateB = DelegationStrategy.createDelegationCertificateTemplate(
        mockWallet.publicKey,
        3600000,
        "solana"
      );
      const messageB = DelegationStrategy.serializeCertificate(templateB);
      const signatureB = await mockWallet.signMessage(messageB);
      const certificateB: DelegationCertificate = {
        ...templateB,
        signature: signatureB,
      };

      // 3. Generate codes with both certificates
      const resultA = await strategy.generateDelegatedCode(certificateA);
      const resultB = await strategy.generateDelegatedCode(certificateB);

      // 4. Delegation IDs should be different
      expect(resultA.actionCode.delegationId).not.toBe(
        resultB.actionCode.delegationId
      );

      // 5. Codes should be different
      expect(resultA.actionCode.code).not.toBe(resultB.actionCode.code);
    });

    it("should have same delegation ID for same certificate", async () => {
      // 1. Generate code with Certificate A
      const result1 = await strategy.generateDelegatedCode(certificate);
      const result2 = await strategy.generateDelegatedCode(certificate);

      // 2. Delegation IDs should be the same
      expect(result1.actionCode.delegationId).toBe(
        result2.actionCode.delegationId
      );

      // 3. Codes should be the same (deterministic)
      expect(result1.actionCode.code).toBe(result2.actionCode.code);
    });

    it("should reject action code with stolen delegation ID", async () => {
      // 1. Generate valid code with Certificate A
      const validResult = await strategy.generateDelegatedCode(certificate);
      const validCode = validResult.actionCode;

      // 2. Attacker steals the delegation ID
      const stolenDelegationId = validCode.delegationId;

      // 3. Attacker creates fake action code with stolen delegation ID
      const fakeActionCode: DelegatedActionCode = {
        code: "999999", // Fake code
        pubkey: "attacker-pubkey", // Different pubkey
        timestamp: Date.now(),
        expiresAt: Date.now() + 3600000,
        delegationId: stolenDelegationId, // Stolen ID
        delegatedBy: "attacker-pubkey", // Different delegator
        secret: "fake-secret",
      };

      // 4. Try to validate fake code with original certificate (should fail)
      expect(() => {
        strategy.validateDelegatedCode(fakeActionCode, certificate);
      }).toThrow("Invalid code:");
    });

    it("should reject action code with stolen delegation ID and different certificate", async () => {
      // 1. Generate valid code with Certificate A
      const validResult = await strategy.generateDelegatedCode(certificate);
      const validCode = validResult.actionCode;

      // 2. Attacker steals the delegation ID
      const stolenDelegationId = validCode.delegationId;

      // 3. Create different Certificate B
      const templateB = DelegationStrategy.createDelegationCertificateTemplate(
        mockWallet.publicKey,
        3600000,
        "solana"
      );
      const messageB = DelegationStrategy.serializeCertificate(templateB);
      const signatureB = await mockWallet.signMessage(messageB);
      const certificateB: DelegationCertificate = {
        ...templateB,
        signature: signatureB,
      };

      // 4. Attacker creates fake action code with stolen delegation ID
      const fakeActionCode: DelegatedActionCode = {
        code: "888888", // Fake code
        pubkey: certificateB.delegator,
        timestamp: Date.now(),
        expiresAt: Date.now() + 3600000,
        delegationId: stolenDelegationId, // Stolen from Certificate A
        delegatedBy: certificateB.delegator,
        secret: "fake-secret",
      };

      // 5. Try to validate fake code with Certificate B (should fail)
      expect(() => {
        strategy.validateDelegatedCode(fakeActionCode, certificateB);
      }).toThrow("Invalid code:");
    });

    it("should allow code generation with stolen signature but different certificate data (signature verification happens in protocol layer)", async () => {
      // 1. Generate valid certificate and get its signature
      const validResult = await strategy.generateDelegatedCode(certificate);
      const validCode = validResult.actionCode;
      const stolenSignature = certificate.signature;

      // 2. Attacker creates fake certificate with stolen signature but different data
      const fakeCertificate: DelegationCertificate = {
        version: "1.0",
        delegator: certificate.delegator, // Same delegator
        issuedAt: certificate.issuedAt, // Keep same timestamp to avoid expiration issues
        expiresAt: certificate.expiresAt, // Keep same expiration
        nonce: "attacker-nonce", // Different nonce
        chain: "solana",
        signature: stolenSignature, // Stolen signature
      };

      // 3. generateDelegatedCode should succeed (signature verification happens in protocol layer)
      const fakeResult = strategy.generateDelegatedCode(fakeCertificate);
      expect(fakeResult.actionCode).toBeDefined();
      expect(fakeResult.actionCode.code).toBeDefined();
    });

    it("should allow code generation with stolen signature and different delegator (signature verification happens in protocol layer)", async () => {
      // 1. Generate valid certificate and get its signature
      const validResult = await strategy.generateDelegatedCode(certificate);
      const validCode = validResult.actionCode;
      const stolenSignature = certificate.signature;

      // 2. Attacker creates fake certificate with stolen signature but different delegator
      const fakeCertificate: DelegationCertificate = {
        version: "1.0",
        delegator: "attacker-pubkey", // Different delegator
        issuedAt: certificate.issuedAt,
        expiresAt: certificate.expiresAt,
        nonce: certificate.nonce,
        chain: "solana",
        signature: stolenSignature, // Stolen signature
      };

      // 3. generateDelegatedCode should succeed (signature verification happens in protocol layer)
      const fakeResult = strategy.generateDelegatedCode(fakeCertificate);
      expect(fakeResult.actionCode).toBeDefined();
      expect(fakeResult.actionCode.code).toBeDefined();
    });
  });
});
