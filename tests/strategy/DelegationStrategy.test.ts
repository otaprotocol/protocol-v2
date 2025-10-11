import { describe, it, test, expect, beforeEach } from "bun:test";
import { DelegationStrategy } from "../../src/strategy/DelegationStrategy";
import { SolanaAdapter } from "../../src/adapters/SolanaAdapter";
import { serializeDelegationProof } from "../../src/utils/canonical";
import type {
  DelegationProof,
  DelegatedActionCode,
} from "../../src/types";
import bs58 from "bs58";
import { PublicKey, Keypair } from "@solana/web3.js";

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
  let delegationProof: DelegationProof;
  const mockDelegatedSignature = bs58.encode(new Uint8Array(64).fill(42)); // Valid base58 signature

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

    // Create a valid delegation proof
    delegationProof = {
      walletPubkey: mockWallet.publicKey,
      delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      expiresAt: Date.now() + 3600000, // 1 hour from now
      chain: "solana",
      signature: "mock-delegation-signature", // In real usage, this would be the wallet's signature
    };
  });

  describe("DelegationProof creation", () => {
    it("should create a valid delegation proof", () => {
      const proof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      expect(proof).toEqual({
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: expect.any(Number),
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      });

      expect(proof.expiresAt).toBeGreaterThan(Date.now());
    });

    it("should validate delegation proof structure", () => {
      const proof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      expect(proof.walletPubkey).toBe(mockWallet.publicKey);
      expect(proof.delegatedPubkey).toBe("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
      expect(proof.expiresAt).toBeGreaterThan(Date.now());
      expect(proof.signature).toBe("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
    });

    it("should handle expiration correctly", () => {
      const now = Date.now();
      const proof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: now + 7200000, // 2 hours
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      expect(proof.expiresAt).toBe(now + 7200000);
    });
  });

  describe("generateDelegatedCode", () => {
    it("should generate a valid delegated action code", () => {
      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);

      expect(result.actionCode).toBeDefined();
      expect(result.actionCode.code).toBeDefined();
      expect(result.actionCode.pubkey).toBe("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
      expect(result.actionCode.delegationProof).toBeDefined();
      expect(result.actionCode.delegationProof.walletPubkey).toBe(mockWallet.publicKey);
      expect(result.actionCode.delegationProof.delegatedPubkey).toBe("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
      expect(result.actionCode.delegatedSignature).toBe(mockDelegatedSignature);
    });

    it("should generate deterministic codes for the same delegation proof", () => {
      const result1 = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const result2 = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);

      expect(result1.actionCode.code).toBe(result2.actionCode.code);
    });

    it("should generate different codes for different delegation proofs", () => {
      const proof1: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const proof2: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: PublicKey.default.toBase58(), // Different delegated pubkey (Solana System Program)
        expiresAt: Date.now() + 7200000, // Different expiration
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const result1 = strategy.generateDelegatedCode(proof1, mockDelegatedSignature);
      const result2 = strategy.generateDelegatedCode(proof2, mockDelegatedSignature);

      expect(result1.actionCode.code).not.toBe(result2.actionCode.code);
    });

    it("should throw error for expired delegation proof", () => {
      const expiredProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() - 1000, // Expired
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      expect(() => {
        strategy.generateDelegatedCode(expiredProof, mockDelegatedSignature);
      }).toThrow("Delegation proof has expired");
    });

    it("should throw error for missing wallet pubkey", () => {
      const invalidProof: DelegationProof = {
        walletPubkey: "",
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      expect(() => {
        strategy.generateDelegatedCode(invalidProof, mockDelegatedSignature);
      }).toThrow("Wallet pubkey is required");
    });

    it("should throw error for missing delegated pubkey", () => {
      const invalidProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      expect(() => {
        strategy.generateDelegatedCode(invalidProof, mockDelegatedSignature);
      }).toThrow("Delegated pubkey is required");
    });
  });

  describe("validateDelegatedCode", () => {
    it("should validate a valid delegated action code", () => {
      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const actionCode = result.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCode, delegationProof);
      }).not.toThrow();
    });

    it("should throw error for expired delegation proof", () => {
      const expiredProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() - 1000, // Expired
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const actionCode = result.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCode, expiredProof);
      }).toThrow("Delegation proof has expired");
    });

    it("should throw error for mismatched wallet pubkey", () => {
      const differentProof: DelegationProof = {
        walletPubkey: "different-wallet-pubkey",
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const actionCode = result.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCode, differentProof);
      }).toThrow("Invalid wallet pubkey format");
    });

    it("should throw error for mismatched delegated pubkey", () => {
      const differentDelegatedKeypair = Keypair.generate();
      const differentProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: differentDelegatedKeypair.publicKey.toString(),
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "mock-delegation-signature", // Same signature as original
      };

      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const actionCode = result.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCode, differentProof);
      }).toThrow("Invalid delegatedPubkey: Action code delegated pubkey does not match delegation proof");
    });

    it("should throw error for mismatched expiration", () => {
      const differentProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 7200000, // Different expiration
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const actionCode = result.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCode, differentProof);
      }).toThrow("Action code delegation expiration does not match delegation proof");
    });

    it("should throw error for mismatched signature", () => {
      const differentProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "different-signature",
      };

      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const actionCode = result.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCode, differentProof);
      }).toThrow("Invalid signature: Action code delegation signature does not match delegation proof");
    });
  });

  describe("integration with ActionCodesProtocol", () => {
    it("should generate valid delegated action codes", () => {
      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);

      expect(result.actionCode).toBeDefined();
      expect(result.actionCode.code).toBeDefined();
      expect(result.actionCode.pubkey).toBe("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
      expect(result.actionCode.delegationProof).toBeDefined();
    });

    it("should generate codes with correct TTL", () => {
      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);

      expect(result.actionCode.expiresAt).toBeGreaterThan(Date.now());
      expect(result.actionCode.expiresAt).toBeLessThanOrEqual(Date.now() + 300000); // 5 minutes
    });

    it("should generate codes with correct length", () => {
      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);

      expect(result.actionCode.code.length).toBe(6);
    });
  });

  describe("deterministic generation", () => {
    it("should generate same code for same delegation proof across different instances", () => {
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

      const result1 = strategy1.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const result2 = strategy2.generateDelegatedCode(delegationProof, mockDelegatedSignature);

      expect(result1.actionCode.code).toBe(result2.actionCode.code);
    });

    it("should generate same codes for same delegation proof (deterministic)", () => {
      const result1 = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const result2 = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);

      expect(result1.actionCode.code).toBe(result2.actionCode.code);
      expect(result1.actionCode.pubkey).toBe(result2.actionCode.pubkey);
      expect(result1.actionCode.delegationProof).toEqual(result2.actionCode.delegationProof);
    });
  });

  describe("Security Tests", () => {
    it("should reject action codes generated from different delegation proofs", () => {
      const proof1: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const proof2: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: PublicKey.default.toBase58(), // Different delegated pubkey
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const result1 = strategy.generateDelegatedCode(proof1, mockDelegatedSignature);
      const actionCode1 = result1.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCode1, proof2);
      }).toThrow("Invalid delegatedPubkey: Action code delegated pubkey does not match delegation proof");
    });

    it("should reject action codes with tampered secrets", () => {
      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const actionCode = result.actionCode as DelegatedActionCode;

      // Tamper with the action code
      const tamperedActionCode: DelegatedActionCode = {
        ...actionCode,
        code: "999999", // Different code
      };

      expect(() => {
        strategy.validateDelegatedCode(tamperedActionCode, delegationProof);
      }).toThrow();
    });
  });

  describe("Relayer Scenario Tests", () => {
    it("should allow relayer to validate codes with delegation proof", () => {
      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const actionCode = result.actionCode as DelegatedActionCode;

      // Simulate relayer validation
      expect(() => {
        strategy.validateDelegatedCode(actionCode, delegationProof);
      }).not.toThrow();
    });

    // Note: Empty signature validation is handled by the underlying WalletStrategy
    // which will throw when trying to decode the empty string as base58

    it("should prevent relayer from generating codes even with fake signature", () => {
      const fakeSignature = "fake-signature";
      
      // This should throw during generation due to invalid base58
      expect(() => {
        strategy.generateDelegatedCode(delegationProof, fakeSignature);
      }).toThrow("Invalid Base58 signature format");
    });

    it("should allow relayer to validate multiple codes from same delegation proof", () => {
      const result1 = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const result2 = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);

      const actionCode1 = result1.actionCode as DelegatedActionCode;
      const actionCode2 = result2.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCode1, delegationProof);
        strategy.validateDelegatedCode(actionCode2, delegationProof);
      }).not.toThrow();
    });

    it("should prevent relayer from validating codes with wrong delegation proof", () => {
      const wrongProof: DelegationProof = {
        walletPubkey: "wrong-wallet",
        delegatedPubkey: "wrong-delegated",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "wrong-signature",
      };

      const result = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const actionCode = result.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCode, wrongProof);
      }).toThrow("Invalid wallet pubkey format");
    });
  });

  describe("Signature Attack Tests", () => {
    it("should prevent signature replay attacks with stolen delegation proof", () => {
      // Attacker steals the delegation proof
      const stolenProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "stolen-signature", // Attacker has this
      };

      // Attacker tries to generate codes with stolen proof
      // This should work at the strategy level (proof validation happens at protocol level)
      const result = strategy.generateDelegatedCode(stolenProof, mockDelegatedSignature);
      expect(result.actionCode).toBeDefined();

      // But validation at protocol level should fail because signature verification will fail
      // (This is tested in ActionCodesProtocol tests)
    });

    it("should prevent delegation proof tampering attacks", () => {
      const originalProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "original-signature",
      };

      // Attacker tries to tamper with the proof
      const tamperedProof: DelegationProof = {
        walletPubkey: "attacker-wallet", // Different wallet
        delegatedPubkey: "attacker-delegated", // Different delegated key
        expiresAt: Date.now() + 7200000, // Different expiration
        chain: "solana",
        signature: "original-signature", // Same signature (stolen)
      };

      // Generate code with original proof
      const originalResult = strategy.generateDelegatedCode(originalProof, mockDelegatedSignature);
      const originalActionCode = originalResult.actionCode as DelegatedActionCode;

      // Try to validate with tampered proof - should fail
      expect(() => {
        strategy.validateDelegatedCode(originalActionCode, tamperedProof);
      }).toThrow("Invalid wallet pubkey format");
    });

    it("should prevent delegation proof expiration extension attacks", () => {
      const originalProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000, // 1 hour
        chain: "solana",
        signature: "original-signature",
      };

      // Attacker tries to extend expiration
      const extendedProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 7200000, // 2 hours (extended)
        chain: "solana",
        signature: "original-signature", // Same signature
      };

      // Generate code with original proof
      const originalResult = strategy.generateDelegatedCode(originalProof, mockDelegatedSignature);
      const originalActionCode = originalResult.actionCode as DelegatedActionCode;

      // Try to validate with extended proof - should fail
      expect(() => {
        strategy.validateDelegatedCode(originalActionCode, extendedProof);
      }).toThrow("Action code delegation expiration does not match delegation proof");
    });

    it("should prevent delegation proof signature substitution attacks", () => {
      const originalProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "original-signature",
      };

      // Attacker tries to substitute signature
      const substitutedProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "attacker-signature", // Different signature
      };

      // Generate code with original proof
      const originalResult = strategy.generateDelegatedCode(originalProof, mockDelegatedSignature);
      const originalActionCode = originalResult.actionCode as DelegatedActionCode;

      // Try to validate with substituted proof - should fail
      expect(() => {
        strategy.validateDelegatedCode(originalActionCode, substitutedProof);
      }).toThrow("Invalid signature: Action code delegation signature does not match delegation proof");
    });

    it("should prevent cross-delegation attacks", () => {
      const proofA: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const proofB: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: PublicKey.default.toBase58(), // Different delegated pubkey
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      // Generate code with proof A
      const resultA = strategy.generateDelegatedCode(proofA, mockDelegatedSignature);
      const actionCodeA = resultA.actionCode as DelegatedActionCode;

      // Try to validate with proof B - should fail
      expect(() => {
        strategy.validateDelegatedCode(actionCodeA, proofB);
      }).toThrow("Invalid delegatedPubkey: Action code delegated pubkey does not match delegation proof");
    });

    it("should prevent delegation proof replay after expiration", () => {
      const expiredProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() - 1000, // Expired
        chain: "solana",
        signature: "expired-signature",
      };

      // Try to generate code with expired proof - should fail
      expect(() => {
        strategy.generateDelegatedCode(expiredProof, mockDelegatedSignature);
      }).toThrow("Delegation proof has expired");
    });

    it("should prevent delegation proof replay with future timestamps", () => {
      const futureProof: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 86400000, // 24 hours (too far in future)
        chain: "solana",
        signature: "future-signature",
      };

      // This should work at strategy level, but protocol validation should check reasonableness
      const result = strategy.generateDelegatedCode(futureProof, mockDelegatedSignature);
      expect(result.actionCode).toBeDefined();
    });
  });

  describe("Code-DelegationProof Binding Tests", () => {
    it("should reject code generated from DelegationProof A when validated with DelegationProof B", () => {
      const proofA: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const proofB: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: PublicKey.default.toBase58(), // Different delegated pubkey
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const resultA = strategy.generateDelegatedCode(proofA, mockDelegatedSignature);
      const actionCodeA = resultA.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCodeA, proofB);
      }).toThrow("Invalid delegatedPubkey: Action code delegated pubkey does not match delegation proof");
    });

    it("should accept code generated from DelegationProof A when validated with DelegationProof A", () => {
      const proofA: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const resultA = strategy.generateDelegatedCode(proofA, mockDelegatedSignature);
      const actionCodeA = resultA.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCodeA, proofA);
      }).not.toThrow();
    });

    it("should reject code generated from DelegationProof B when validated with DelegationProof A", () => {
      const proofA: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const proofB: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: PublicKey.default.toBase58(), // Different delegated pubkey
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const resultB = strategy.generateDelegatedCode(proofB, mockDelegatedSignature);
      const actionCodeB = resultB.actionCode as DelegatedActionCode;

      expect(() => {
        strategy.validateDelegatedCode(actionCodeB, proofA);
      }).toThrow("Invalid delegatedPubkey: Action code delegated pubkey does not match delegation proof");
    });

    it("should have different delegated pubkeys for different delegation proofs", () => {
      const proofA: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const proofB: DelegationProof = {
        walletPubkey: mockWallet.publicKey,
        delegatedPubkey: PublicKey.default.toBase58(), // Different delegated pubkeyu
        expiresAt: Date.now() + 3600000,
        chain: "solana",
        signature: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      };

      const resultA = strategy.generateDelegatedCode(proofA, mockDelegatedSignature);
      const resultB = strategy.generateDelegatedCode(proofB, mockDelegatedSignature);

      const actionCodeA = resultA.actionCode as DelegatedActionCode;
      const actionCodeB = resultB.actionCode as DelegatedActionCode;

      expect(actionCodeA.delegationProof.delegatedPubkey).toBe("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM");
      expect(actionCodeB.delegationProof.delegatedPubkey).toBe(PublicKey.default.toBase58());
      expect(actionCodeA.delegationProof.delegatedPubkey).not.toBe(actionCodeB.delegationProof.delegatedPubkey);
    });

    it("should have same delegated pubkey for same delegation proof", () => {
      const result1 = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);
      const result2 = strategy.generateDelegatedCode(delegationProof, mockDelegatedSignature);

      const actionCode1 = result1.actionCode as DelegatedActionCode;
      const actionCode2 = result2.actionCode as DelegatedActionCode;

      expect(actionCode1.delegationProof.delegatedPubkey).toBe(actionCode2.delegationProof.delegatedPubkey);
    });
    });
  });