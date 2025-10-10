import { ActionCodesProtocol } from "../src/ActionCodesProtocol";
import {
  BaseChainAdapter,
  type ChainWalletStrategyContext,
  type ChainWalletStrategyRevokeContext,
} from "../src/adapters/BaseChainAdapter";
import { SolanaAdapter, SolanaContext } from "../src/adapters/SolanaAdapter";
import { Transaction, Keypair } from "@solana/web3.js";
import { MEMO_PROGRAM_ID } from "@solana/spl-memo";
import type {
  ChainAdapter,
} from "../src/adapters/BaseChainAdapter";
import type { ProtocolMetaFields } from "../src/utils/protocolMeta";
import bs58 from "bs58";
import nacl from "tweetnacl";
import { codeHash } from "../src/utils/crypto";
import { DelegationProof, ActionCode } from "../src/types";
import {
  serializeCanonicalRevoke,
  getCanonicalMessageParts,
    serializeDelegationProof,
} from "../src/utils/canonical";

// Helper function to create a real signature for testing
function createRealSignature(message: Uint8Array, keypair: Keypair): string {
  const signature = nacl.sign.detached(message, keypair.secretKey);
  return bs58.encode(signature);
}

// Helper function to simulate user creating a revoke signature
function createUserRevokeSignature(
  actionCode: ActionCode,
  userKeypair: Keypair
): { signature: string; canonicalRevokeMessageParts: any } {
  // User creates revoke message with the code hash and timestamp from the action code
  const realCodeHash = codeHash(actionCode.code);
  const canonicalRevokeMessageParts = {
    pubkey: actionCode.pubkey,
    codeHash: realCodeHash,
    windowStart: actionCode.timestamp,
  };

  // User signs the revoke message with their wallet
  const revokeMessage = serializeCanonicalRevoke(canonicalRevokeMessageParts);
  const userRevokeSignature = createRealSignature(revokeMessage, userKeypair);

  return {
    signature: userRevokeSignature,
    canonicalRevokeMessageParts,
  };
}

// Mock delegated signature for testing
const mockDelegatedSignature = bs58.encode(new Uint8Array(64).fill(42));

describe("ActionCodesProtocol", () => {
  let protocol: ActionCodesProtocol;
  let testKeypair: Keypair;

  beforeEach(() => {
    protocol = new ActionCodesProtocol({
      codeLength: 8,
      ttlMs: 120000,
    });
    testKeypair = Keypair.generate();
  });

  describe("adapter registry", () => {
    test("has solana adapter by default", () => {
      const solanaAdapter = protocol.getAdapter("solana");
      expect(solanaAdapter).toBeInstanceOf(SolanaAdapter);
    });

    test("can register custom adapters", () => {
      class CustomAdapter extends BaseChainAdapter<any, any, any> {
        verifyWithWallet(context: ChainWalletStrategyContext<any>): boolean {
          return true;
        }
        verifyWithDelegation(
          context: ChainWalletStrategyContext<any>
        ): boolean {
          return true;
        }
        verifyRevokeWithWallet(
          context: ChainWalletStrategyRevokeContext<any>
        ): boolean {
          return true;
        }
      }
      const customAdapter = new CustomAdapter() as unknown as ChainAdapter;
      protocol.registerAdapter(
        "custom",
        customAdapter as unknown as ChainAdapter
      );

      const retrieved = protocol.getAdapter("custom");
      expect(retrieved).toBe(customAdapter);
    });

    test("typed adapter access works", () => {
      const solanaAdapter = protocol.adapter.solana;
      expect(solanaAdapter).toBeInstanceOf(SolanaAdapter);
    });

    test("can create protocol meta instruction via typed access", () => {
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: "test123",
        int: "user@example.com",
        p: { amount: 100 },
      });

      expect(instruction.programId.toString()).toBe(MEMO_PROGRAM_ID.toString());
      expect(instruction.data.toString("utf8")).toContain("actioncodes:ver=2");
    });

    test("can verify transaction matches code via typed access", () => {
      const actionCode = {
        code: "12345678",
        pubkey: "user@example.com",
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        signature: "testsignature",
      };

      const codeHashValue = codeHash(actionCode.code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
      });
      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = testKeypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");

      // Should not throw for valid transaction
      expect(() => {
        protocol.adapter.solana.verifyTransactionMatchesCode(
          actionCode,
          base64String
        );
      }).not.toThrow();
    });

    test("can verify transaction is signed by intended owner via typed access", () => {
      const keypair = Keypair.generate();
      const code = "87654321";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: keypair.publicKey.toString(),
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;
      tx.sign(keypair);

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");

      // Should not throw for valid transaction
      expect(() => {
        protocol.adapter.solana.verifyTransactionSignedByIntentOwner(
          base64String
        );
      }).not.toThrow();
    });

    test("can attach protocol meta to transaction via typed access", () => {
      const tx = new Transaction();
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = testKeypair.publicKey;

      const code = "12345678";
      const codeHashValue = codeHash(code);
      const meta = {
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      };

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      const result = SolanaAdapter.attachProtocolMeta(
        base64String,
        meta as ProtocolMetaFields
      );

      // Should return a new base64 string (not mutate original)
      expect(result).not.toBe(base64String);
      expect(typeof result).toBe("string");

      // Should be able to deserialize the result
      const resultTx = Transaction.from(Buffer.from(result, "base64"));
      expect(resultTx.instructions).toHaveLength(1);

      // Should be able to extract the meta
      const extractedMeta = protocol.adapter.solana.getProtocolMeta(result);
      expect(extractedMeta).toContain("actioncodes:ver=2");
      expect(extractedMeta).toContain(`id=${codeHashValue}`);
    });
  });

  describe("code generation and validation", () => {
    test("generates and validates codes", async () => {
      const canonicalMessage = getCanonicalMessageParts(
        "testpubkey",
        protocol.getConfig().ttlMs
      );
      const signature = createRealSignature(canonicalMessage, testKeypair);
      const { actionCode } = await protocol.generateCode(
        "wallet",
        canonicalMessage,
        signature
      );

      expect(actionCode.code).toBeDefined();
      expect(actionCode.pubkey).toBe("testpubkey");
      expect(actionCode.timestamp).toBeDefined();
      expect(actionCode.expiresAt).toBeDefined();
    });

    test("validates codes with chain adapter", async () => {
      const canonicalMessage = getCanonicalMessageParts(
        "testpubkey",
        protocol.getConfig().ttlMs
      );
      const signature = createRealSignature(canonicalMessage, testKeypair);
      const { actionCode } = await protocol.generateCode(
        "wallet",
        canonicalMessage,
        signature
      );

      // Mock context for validation
      const context = {
        chain: "solana",
        pubkey: "testpubkey",
        signature: "mocksignature",
      } as unknown as ChainWalletStrategyContext<SolanaContext>;

      // This should throw because we're using a mock signature
      expect(() => {
        protocol.validateCode("wallet", actionCode, context);
      }).toThrow();
    });

    test("generates and validates delegated codes", async () => {
      // Create a delegation proof
      const delegationProof = {
        walletPubkey: testKeypair.publicKey.toString(),
        delegatedPubkey: "delegated-pubkey",
        expiresAt: Date.now() + 3600000, // 1 hour from now
        signature: "mock-delegation-signature", // In real usage, this would be the wallet's signature
      };

      // Generate delegated code
      const result = protocol.generateCode(
        "delegation",
        delegationProof,
        mockDelegatedSignature
      );

      expect(result.actionCode).toBeDefined();
      expect(result.actionCode.code).toBeDefined();
      expect(result.actionCode.pubkey).toBe("delegated-pubkey");
      expect(result.actionCode.delegationProof).toBeDefined();
      expect(result.actionCode.delegationProof.walletPubkey).toBe(
        testKeypair.publicKey.toString()
      );

      // Validate the delegated code using the delegation strategy directly
      expect(() => {
        protocol.delegationStrategy.validateDelegatedCode(
          result.actionCode,
          delegationProof
        );
      }).not.toThrow();
    });

    test("validates delegated codes with protocol validation", async () => {
      // Create a delegation proof
      const delegationProof = {
        walletPubkey: testKeypair.publicKey.toString(),
        delegatedPubkey: "delegated-pubkey",
        expiresAt: Date.now() + 3600000, // 1 hour from now
        signature: "mock-delegation-signature", // In real usage, this would be the wallet's signature
      };

      // Generate delegated code
      const result = protocol.generateCode(
        "delegation",
        delegationProof,
        mockDelegatedSignature
      );

      // Validate using protocol's validateCode method (with mock signature verification)
      // This will fail because we're using a mock signature, which is expected
      expect(() => {
        protocol.validateCode("delegation", result.actionCode, {
          chain: "solana",
          pubkey: delegationProof.walletPubkey,
          signature: delegationProof.signature,
          delegationProof,
          delegatedSignature: mockDelegatedSignature,
        });
      }).toThrow("Signature verification failed");
    });

    test("handles delegation strategy configuration", () => {
      // Test that delegation strategy is accessible
      const delegationStrategy = protocol.delegationStrategy;

      expect(delegationStrategy).toBeDefined();
      expect(typeof delegationStrategy.generateDelegatedCode).toBe("function");
      expect(typeof delegationStrategy.validateDelegatedCode).toBe("function");
    });

    test("generates different delegated codes for different proofs", async () => {
      // Create two different delegation proofs
      const delegationProof1 = {
        walletPubkey: testKeypair.publicKey.toString(),
        delegatedPubkey: "delegated-pubkey-1",
        expiresAt: Date.now() + 3600000, // 1 hour
        signature: "mock-delegation-signature-1",
      };
      const delegationProof2 = {
        walletPubkey: testKeypair.publicKey.toString(),
        delegatedPubkey: "delegated-pubkey-2",
        expiresAt: Date.now() + 7200000, // 2 hours
        signature: "mock-delegation-signature-2",
      };

      // Generate codes for both delegation proofs
      const result1 = protocol.generateCode(
        "delegation",
        delegationProof1,
        mockDelegatedSignature
      );
      const result2 = protocol.generateCode(
        "delegation",
        delegationProof2,
        mockDelegatedSignature
      );

      // They should be different
      expect(result1.actionCode.code).not.toBe(result2.actionCode.code);
      expect(result1.actionCode.delegationProof.delegatedPubkey).not.toBe(
        result2.actionCode.delegationProof.delegatedPubkey
      );
    });

    test("validates delegated code expiration", async () => {
      // Create an expired delegation proof
      const expiredDelegationProof = {
        walletPubkey: testKeypair.publicKey.toString(),
        delegatedPubkey: "delegated-pubkey",
        expiresAt: Date.now() - 1000, // Expired 1 second ago
        signature: "mock-delegation-signature",
      };

      // This should throw when generating code with expired delegation proof
      expect(() => {
        protocol.generateCode(
          "delegation",
          expiredDelegationProof,
          mockDelegatedSignature
        );
      }).toThrow("Delegation proof has expired");
    });

    it("should reject codes with stolen signatures during validation", async () => {
      // 1. Generate valid delegation proof and code
      const originalDelegationProof = {
        walletPubkey: testKeypair.publicKey.toString(),
        delegatedPubkey: "delegated-pubkey",
        expiresAt: Date.now() + 3600000, // 1 hour from now
        signature: "original-delegation-signature",
      };
      const originalResult = await protocol.generateCode(
        "delegation",
        originalDelegationProof,
        mockDelegatedSignature
      );
      const originalCode = originalResult.actionCode;

      // 2. Create fake delegation proof with stolen signature but different data
      const fakeDelegationProof = {
        walletPubkey: testKeypair.publicKey.toString(),
        delegatedPubkey: "different-delegated-pubkey", // Different delegated pubkey
        expiresAt: originalDelegationProof.expiresAt, // Same expiration
        signature: originalDelegationProof.signature, // Same signature (stolen)
      };

      // 3. Generate code with fake delegation proof (this should work in strategy layer)
      const fakeResult = protocol.generateCode(
        "delegation",
        fakeDelegationProof,
        mockDelegatedSignature
      );
      const fakeCode = fakeResult.actionCode;

      // 4. Try to validate fake code with original delegation proof (should fail)
      expect(() => {
        protocol.validateCode("delegation", fakeCode, {
          chain: "solana",
          pubkey: originalDelegationProof.walletPubkey,
          signature: originalDelegationProof.signature,
          delegationProof: originalDelegationProof,
          delegatedSignature: mockDelegatedSignature,
        });
      }).toThrow("Action code delegated pubkey does not match delegation proof");
    });

    it("should reject codes with stolen signatures and different delegator during validation", async () => {
      // 1. Generate valid delegation proof and code
      const originalDelegationProof = {
        walletPubkey: testKeypair.publicKey.toString(),
        delegatedPubkey: "delegated-pubkey",
        expiresAt: Date.now() + 3600000, // 1 hour from now
        signature: "original-delegation-signature",
      };
      // Use the delegation proof directly (signature would be created by wallet in real usage)
      const originalProof = originalDelegationProof;
      const originalResult = await protocol.generateCode(
        "delegation",
        originalProof,
        mockDelegatedSignature
      );
      const originalCode = originalResult.actionCode;

      // 2. Create fake proof with stolen signature but different delegator
      const fakeProof: DelegationProof = {
        ...originalProof,
        walletPubkey: "attackerpubkey", // Different delegator
        signature: originalProof.signature, // Same signature (stolen)
      };

      // 3. Generate code with fake proof (this should work in strategy layer)
      const fakeResult = await protocol.generateCode(
        "delegation",
        fakeProof,
        mockDelegatedSignature
      );
      const fakeCode = fakeResult.actionCode;

      // 4. Try to validate fake code with original proof (should fail)
      expect(() => {
        protocol.validateCode("delegation", fakeCode, {
          chain: "solana",
          pubkey: originalProof.walletPubkey,
          signature: originalProof.signature,
          delegationProof: originalProof,
          delegatedSignature: mockDelegatedSignature,
        });
        }).toThrow("Action code wallet pubkey does not match delegation proof");
    });

    it("should require signature for wallet strategy to prevent public key + timestamp attacks", async () => {
      // 1. Generate canonical message first
      const canonicalMessage = getCanonicalMessageParts(
        testKeypair.publicKey.toString(),
        protocol.getConfig().ttlMs
      );

      // 2. Try to generate code without signature (should fail)
      expect(() => {
        protocol.generateCode("wallet", canonicalMessage, "");
      }).toThrow("Missing signature over canonical message");

      // 3. Sign the canonical message
      const signature = createRealSignature(canonicalMessage, testKeypair);

      // 4. Generate code with signature (should succeed)
      const result = protocol.generateCode(
        "wallet",
        canonicalMessage,
        signature
      );

      expect(result.actionCode.code).toBeDefined();
      expect(result.actionCode.signature).toBe(signature);
    });

    it("should prevent public key + timestamp attacks with signature-based generation", async () => {
      // 1. User generates canonical message and signs it
      const userPubkey = testKeypair.publicKey.toString();
      const canonicalMessage = getCanonicalMessageParts(
        userPubkey,
        protocol.getConfig().ttlMs
      );
      const userSignature = createRealSignature(canonicalMessage, testKeypair);
      const userResult = protocol.generateCode(
        "wallet",
        canonicalMessage,
        userSignature
      );
      const userCode = userResult.actionCode;

      // 2. Attacker tries to generate code with same public key but different signature
      const attackerSignature = "fakeattackersignature";
      const attackerResult = protocol.generateCode(
        "wallet",
        canonicalMessage,
        attackerSignature
      );
      const attackerCode = attackerResult.actionCode;

      // 3. Codes should be different because they use different signatures
      expect(userCode.code).not.toBe(attackerCode.code);
      expect(userCode.signature).toBe(userSignature);
      expect(attackerCode.signature).toBe(attackerSignature);

      // 4. Only the user's code should validate correctly
      expect(() => {
        protocol.validateCode("wallet", userCode, {
          chain: "solana",
          pubkey: userPubkey,
          signature: userSignature,
        } as unknown as ChainWalletStrategyContext<SolanaContext>);
      }).not.toThrow();

      expect(() => {
        protocol.validateCode("wallet", attackerCode, {
          chain: "solana",
          pubkey: userPubkey,
          signature: attackerSignature,
        } as unknown as ChainWalletStrategyContext<SolanaContext>);
      }).toThrow("Signature verification failed");
    });
  });

  describe("expiration handling", () => {
    test("generates codes with correct TTL", async () => {
      const canonicalMessage = new TextEncoder().encode(
        JSON.stringify({
          pubkey: testKeypair.publicKey.toString(),
          windowStart: Date.now(),
        })
      );
      const signature = createRealSignature(canonicalMessage, testKeypair);

      const result = protocol.generateCode(
        "wallet",
        canonicalMessage,
        signature
      );
      const actionCode = result.actionCode;

      // Verify TTL is exactly 2 minutes (120000ms)
      const actualTtl = actionCode.expiresAt - actionCode.timestamp;
      expect(actualTtl).toBe(120000);
    });

    test("handles different TTL configurations", async () => {
      const ttlConfigs = [
        { ttlMs: 60000, description: "1 minute" },
        { ttlMs: 120000, description: "2 minutes" },
        { ttlMs: 300000, description: "5 minutes" },
      ];

      for (const config of ttlConfigs) {
        const protocolWithTtl = new ActionCodesProtocol({
          codeLength: 8,
          ttlMs: config.ttlMs,
        });

        const canonicalMessage = new TextEncoder().encode(
          JSON.stringify({
            pubkey: testKeypair.publicKey.toString(),
            windowStart: Date.now(),
          })
        );
        const signature = createRealSignature(canonicalMessage, testKeypair);

        const result = protocolWithTtl.generateCode(
          "wallet",
          canonicalMessage,
          signature
        );
        const actualTtl =
          result.actionCode.expiresAt - result.actionCode.timestamp;
        if (!result.actionCode || !result.canonicalMessage) {
          throw new Error("Invalid result");
        }

        expect(actualTtl).toBe(config.ttlMs);
      }
    });

    test("validates timestamp consistency across protocol", async () => {
      const canonicalMessage = new TextEncoder().encode(
        JSON.stringify({
          pubkey: testKeypair.publicKey.toString(),
          windowStart: Date.now(),
        })
      );
      const signature = createRealSignature(canonicalMessage, testKeypair);

      const result = protocol.generateCode(
        "wallet",
        canonicalMessage,
        signature
      );
      const actionCode = result.actionCode;

      const now = Date.now();

      // Timestamp should be reasonable
      expect(actionCode.timestamp).toBeLessThanOrEqual(now);
      expect(actionCode.timestamp).toBeGreaterThan(now - 10000); // More lenient

      // Expiration should be exactly TTL after timestamp
      expect(actionCode.expiresAt).toBe(actionCode.timestamp + 120000);

      // Both should be valid timestamps
      expect(actionCode.timestamp).toBeGreaterThan(0);
      expect(actionCode.expiresAt).toBeGreaterThan(actionCode.timestamp);
    });

    test("handles rapid code generation with consistent expiration", async () => {
      const results: {
        actionCode: ActionCode;
        canonicalMessage: Uint8Array;
      }[] = [];
      const startTime = Date.now();

      // Generate multiple codes rapidly
      for (let i = 0; i < 5; i++) {
        const canonicalMessage = new TextEncoder().encode(
          JSON.stringify({
            pubkey: testKeypair.publicKey.toString(),
            windowStart: Date.now(),
          })
        );
        const signature = createRealSignature(canonicalMessage, testKeypair);

        const result = protocol.generateCode(
          "wallet",
          canonicalMessage,
          signature
        );
        results.push(result);
      }

      const endTime = Date.now();
      const generationTime = endTime - startTime;

      // All codes should have the same TTL
      const expectedTtl = 120000;
      results.forEach((result) => {
        const actualTtl =
          result.actionCode.expiresAt - result.actionCode.timestamp;
        expect(actualTtl).toBe(expectedTtl);
      });

      // Generation should be fast
      expect(generationTime).toBeLessThan(1000);
    });

    test("verifies expiration with different time windows", async () => {
      const baseTime = Date.now();
      const windowSizes = [60000, 120000, 300000]; // 1, 2, 5 minutes

      for (const windowSize of windowSizes) {
        // Use current time to avoid past timestamps
        const windowStart = Math.floor(baseTime / windowSize) * windowSize;
        const actualWindowStart = Math.max(windowStart, baseTime - 60000); // At most 1 minute ago

        const canonicalMessage = new TextEncoder().encode(
          JSON.stringify({
            pubkey: testKeypair.publicKey.toString(),
            windowStart: actualWindowStart,
          })
        );
        const signature = createRealSignature(canonicalMessage, testKeypair);

        const result = protocol.generateCode(
          "wallet",
          canonicalMessage,
          signature
        );

        // Verify the timestamp matches the window start
        expect(result.actionCode.timestamp).toBe(actualWindowStart);
        expect(result.actionCode.expiresAt).toBe(actualWindowStart + 120000);
      }
    });
  });

  describe("revoke verification integration", () => {
    test("verifyRevokeWithWallet works with real action code and user signature", async () => {
      // 1. Generate a real action code using the protocol
      const canonicalMessage = getCanonicalMessageParts(
        testKeypair.publicKey.toString(),
        protocol.getConfig().ttlMs
      );
      const signature = createRealSignature(canonicalMessage, testKeypair);
      const { actionCode } = await protocol.generateCode(
        "wallet",
        canonicalMessage,
        signature
      );

      // 2. User wants to revoke this action code
      // User creates revoke message with the code hash and timestamp from the action code
      const realCodeHash = codeHash(actionCode.code);
      const canonicalRevokeMessageParts = {
        pubkey: actionCode.pubkey,
        codeHash: realCodeHash,
        windowStart: actionCode.timestamp,
      };

      // 3. User signs the revoke message with their wallet (this is what the user provides)
      const revokeMessage = serializeCanonicalRevoke(
        canonicalRevokeMessageParts
      );
      const userRevokeSignature = createRealSignature(
        revokeMessage,
        testKeypair
      );

      // 4. User provides the signature for verification (this is the input from user)
      const context: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "solana",
        signature: userRevokeSignature, // This is the signature the user provides
        canonicalRevokeMessageParts,
      };

      // 5. System verifies the user's revoke signature
      const solanaAdapter = protocol.getAdapter("solana") as SolanaAdapter;
      const verifyResult = solanaAdapter.verifyRevokeWithWallet(context);

      expect(verifyResult).toBe(true);
    });

    test("verifyRevokeWithWallet rejects invalid revoke signature", async () => {
      // 1. Generate a real action code using the protocol
      const canonicalMessage = getCanonicalMessageParts(
        testKeypair.publicKey.toString(),
        protocol.getConfig().ttlMs
      );
      const signature = createRealSignature(canonicalMessage, testKeypair);
      const { actionCode } = await protocol.generateCode(
        "wallet",
        canonicalMessage,
        signature
      );

      // 2. Get the real code hash and timestamp from the generated action code
      const realCodeHash = codeHash(actionCode.code);
      const canonicalRevokeMessageParts = {
        pubkey: actionCode.pubkey,
        codeHash: realCodeHash,
        windowStart: actionCode.timestamp,
      };

      // 3. Create a revoke message but sign it with a different keypair
      const differentKeypair = Keypair.generate();
      const revokeMessage = serializeCanonicalRevoke(
        canonicalRevokeMessageParts
      );
      const wrongSignature = createRealSignature(
        revokeMessage,
        differentKeypair
      );

      // 4. Create context for revoke verification with wrong signature
      const context: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "solana",
        signature: wrongSignature, // But signed by different keypair
        canonicalRevokeMessageParts,
      };

      // 5. Verify the revoke signature should fail
      const solanaAdapter = protocol.getAdapter("solana") as SolanaAdapter;
      const verifyResult = solanaAdapter.verifyRevokeWithWallet(context);

      expect(verifyResult).toBe(false);
    });

    test("verifyRevokeWithWallet works with different code hashes", async () => {
      const solanaAdapter = protocol.getAdapter("solana") as SolanaAdapter;

      // Test with multiple different action codes
      const testCodes = ["12345678", "87654321", "ABCDEFGH", "ZYXWVUTS"];

      for (const code of testCodes) {
        // 1. Generate action code with specific code
        const canonicalMessage = getCanonicalMessageParts(
          testKeypair.publicKey.toString(),
          protocol.getConfig().ttlMs
        );
        const signature = createRealSignature(canonicalMessage, testKeypair);

        // Mock the code generation to use our specific code
        const mockActionCode: ActionCode = {
          code,
          pubkey: testKeypair.publicKey.toString(),
          timestamp: Math.floor(Date.now() / 120000) * 120000,
          expiresAt: Math.floor(Date.now() / 120000) * 120000 + 120000,
          signature,
        };

        // 2. Get the real code hash
        const realCodeHash = codeHash(mockActionCode.code);
        const canonicalRevokeMessageParts = {
          pubkey: mockActionCode.pubkey,
          codeHash: realCodeHash,
          windowStart: mockActionCode.timestamp,
        };

        // 3. Create and sign revoke message
        const revokeMessage = serializeCanonicalRevoke(
          canonicalRevokeMessageParts
        );
        const revokeSignature = createRealSignature(revokeMessage, testKeypair);

        // 4. Verify revoke signature
        const context: ChainWalletStrategyRevokeContext<SolanaContext> = {
          chain: "solana",
          signature: revokeSignature,
          canonicalRevokeMessageParts,
        };

        const verifyResult = solanaAdapter.verifyRevokeWithWallet(context);
        expect(verifyResult).toBe(true);
      }
    });

    test("realistic user workflow: generate code, then revoke it", async () => {
      // 1. User generates an action code
      const canonicalMessage = getCanonicalMessageParts(
        testKeypair.publicKey.toString(),
        protocol.getConfig().ttlMs
      );
      const signature = createRealSignature(canonicalMessage, testKeypair);
      const { actionCode } = await protocol.generateCode(
        "wallet",
        canonicalMessage,
        signature
      );

      // 2. User decides to revoke the action code
      // User creates a revoke signature using their wallet
      const { signature: userRevokeSignature, canonicalRevokeMessageParts } =
        createUserRevokeSignature(actionCode, testKeypair);

      // 3. User submits the revoke request to the system
      // System verifies the user's revoke signature
      const solanaAdapter = protocol.getAdapter("solana") as SolanaAdapter;
      const context: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "solana",
        signature: userRevokeSignature, // User provided this signature
        canonicalRevokeMessageParts,
      };

      const verifyResult = solanaAdapter.verifyRevokeWithWallet(context);
      expect(verifyResult).toBe(true);

      // 4. System can now safely revoke the action code
      // (In a real implementation, this would mark the code as revoked in the database)
      console.log(
        `Action code ${actionCode.code} successfully revoked by user ${actionCode.pubkey}`
      );
    });
  });
});
