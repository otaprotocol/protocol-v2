import { ActionCodesProtocol } from "../src/ActionCodesProtocol";
import {
  BaseChainAdapter,
  type ChainWalletStrategyContext,
} from "../src/adapters/BaseChainAdapter";
import { SolanaAdapter, SolanaContext } from "../src/adapters/SolanaAdapter";
import { Transaction, Keypair } from "@solana/web3.js";
import { MEMO_PROGRAM_ID } from "@solana/spl-memo";
import type { BaseWalletStrategyContext, ChainAdapter } from "../src/adapters/BaseChainAdapter";
import type { ProtocolMetaFields } from "../src/utils/protocolMeta";
import { DelegationStrategy } from "../src/strategy/DelegationStrategy";
import bs58 from "bs58";
import nacl from "tweetnacl";
import { codeHash } from "../src/utils/crypto";

// Helper function to create a real signature for testing
function createRealSignature(message: Uint8Array, keypair: Keypair): string {
  const signature = nacl.sign.detached(message, keypair.secretKey);
  return bs58.encode(signature);
}

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
      class CustomAdapter extends BaseChainAdapter<any, any> {
        verifyWithWallet(context: ChainWalletStrategyContext<any>): boolean {
          return true;
        }
        verifyWithDelegation(context: ChainWalletStrategyContext<any>): boolean {
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

      expect(instruction.programId.toString()).toBe(
        MEMO_PROGRAM_ID.toString()
      );
      expect(instruction.data.toString("utf8")).toContain("actioncodes:ver=2");
    });

    test("can verify transaction matches code via typed access", () => {
      const actionCode = {
        code: "12345678",
        pubkey: "user@example.com",
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        signature: "test-signature",
      };

      const codeHashValue = codeHash(actionCode.code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
      });
      const tx = new Transaction().add(instruction);

      // Should not throw for valid transaction
      expect(() => {
        protocol.adapter.solana.verifyTransactionMatchesCode(actionCode, tx);
      }).not.toThrow();
    });

    test("can verify transaction is signed by intended owner via typed access", () => {
      const keypair = Keypair.generate();
      const code = "87654321";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: keypair.publicKey.toString()
      });
      
      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.sign(keypair);

      // Should not throw for valid transaction
      expect(() => {
        protocol.adapter.solana.verifyTransactionSignedByIntentOwner(tx);
      }).not.toThrow();
    });

    test("can attach protocol meta to transaction via typed access", () => {
      const tx = new Transaction();
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const meta = {
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 }
      };
      
      const result = SolanaAdapter.attachProtocolMeta(tx, meta as ProtocolMetaFields);
      
      // Should be the same transaction instance (mutated)
      expect(result).toBe(tx);
      
      // Should have the memo instruction
      expect(tx.instructions).toHaveLength(1);
      
      // Should be able to extract the meta
      const extractedMeta = protocol.adapter.solana.getProtocolMeta(tx);
      expect(extractedMeta).toContain("actioncodes:ver=2");
      expect(extractedMeta).toContain(`id=${codeHashValue}`);
    });
  });

  describe("code generation and validation", () => {
    test("generates and validates codes", async () => {
      const { actionCode } = await protocol.generateCode('wallet', 'test-pubkey');

      expect(actionCode.code).toBeDefined();
      expect(actionCode.pubkey).toBe("test-pubkey");
      expect(actionCode.timestamp).toBeDefined();
      expect(actionCode.expiresAt).toBeDefined();
    });

    test("validates codes with chain adapter", async () => {
      const { actionCode } = await protocol.generateCode('wallet', 'test-pubkey');

      // Mock context for validation
      const context = {
        chain: "solana",
        pubkey: "test-pubkey",
        signature: "mock-signature",
      } as unknown as ChainWalletStrategyContext<SolanaContext>;

      // This should throw because we're using a mock signature
      expect(() => {
        protocol.validateCode("wallet", actionCode, context);
      }).toThrow();
    });

    test("generates and validates delegated codes", async () => {
      // Create a delegation certificate template
      const certificateTemplate = protocol.createDelegationCertificateTemplate(
        testKeypair.publicKey.toString(),
        3600000, // 1 hour
        "solana"
      );

      // Create a real signature for the certificate
      const message = DelegationStrategy.serializeCertificate(certificateTemplate);
      const realSignature = createRealSignature(message, testKeypair);
      const certificate = {
        ...certificateTemplate,
        signature: realSignature,
      };

      // Generate delegated code
      const result = protocol.generateCode("delegation", certificate);
      
      expect(result.actionCode).toBeDefined();
      expect(result.actionCode.code).toBeDefined();
      expect(result.actionCode.pubkey).toBe(testKeypair.publicKey.toString());
      expect(result.actionCode.delegationId).toBeDefined();
      expect(result.actionCode.delegatedBy).toBe(testKeypair.publicKey.toString());

      // Validate the delegated code using the delegation strategy directly
      expect(() => {
        protocol.delegationStrategy.validateDelegatedCode(result.actionCode, certificate);
      }).not.toThrow();
    });

    test("validates delegated codes with protocol validation", async () => {
      // Create a delegation certificate template
      const certificateTemplate = protocol.createDelegationCertificateTemplate(
        testKeypair.publicKey.toString(),
        3600000, // 1 hour
        "solana"
      );

      // Create a real signature for the certificate
      const message = DelegationStrategy.serializeCertificate(certificateTemplate);
      const realSignature = createRealSignature(message, testKeypair);
      const certificate = {
        ...certificateTemplate,
        signature: realSignature,
      };

      // Generate delegated code
      const result = protocol.generateCode("delegation", certificate);

      // Validate using protocol's validateCode method (with real signature verification)
      expect(() => {
        protocol.validateCode("delegation", result.actionCode, certificate);
      }).not.toThrow();
    });


    test("handles delegation strategy configuration", () => {
      // Test that delegation strategy is accessible
      const delegationStrategy = protocol.delegationStrategy;
      
      expect(delegationStrategy).toBeDefined();
      expect(typeof delegationStrategy.generateDelegatedCode).toBe("function");
      expect(typeof delegationStrategy.validateDelegatedCode).toBe("function");
    });

    test("generates different delegated codes for different certificates", async () => {
      // Create two different certificates
      const certificate1Template = protocol.createDelegationCertificateTemplate(
        testKeypair.publicKey.toString(),
        3600000,
        "solana"
      );
      const certificate2Template = protocol.createDelegationCertificateTemplate(
        testKeypair.publicKey.toString(),
        7200000, // 2 hours
        "solana"
      );

      // Create real signatures for both certificates
      const message1 = DelegationStrategy.serializeCertificate(certificate1Template);
      const message2 = DelegationStrategy.serializeCertificate(certificate2Template);
      const signature1 = createRealSignature(message1, testKeypair);
      const signature2 = createRealSignature(message2, testKeypair);

      const certificate1 = {
        ...certificate1Template,
        signature: signature1,
      };
      const certificate2 = {
        ...certificate2Template,
        signature: signature2,
      };

      // Generate codes for both certificates
      const result1 = protocol.generateCode("delegation", certificate1);
      const result2 = protocol.generateCode("delegation", certificate2);

      // They should be different
      expect(result1.actionCode.code).not.toBe(result2.actionCode.code);
      expect(result1.actionCode.delegationId).not.toBe(result2.actionCode.delegationId);
    });

    test("validates delegated code expiration", async () => {
      // Create an expired certificate
      const expiredTemplate = protocol.createDelegationCertificateTemplate(
        testKeypair.publicKey.toString(),
        -1000 // Expired 1 second ago
      );
      
      // Create a real signature for the expired certificate
      const message = DelegationStrategy.serializeCertificate(expiredTemplate);
      const realSignature = createRealSignature(message, testKeypair);
      const expiredCertificate = {
        ...expiredTemplate,
        signature: realSignature,
      };

      // This should throw when generating code with expired certificate
      expect(() => {
        protocol.generateCode("delegation", expiredCertificate);
      }).toThrow("Invalid delegation certificate");
    });
  });
});
