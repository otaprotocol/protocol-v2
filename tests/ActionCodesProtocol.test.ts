import { ActionCodesProtocol } from "../src/ActionCodesProtocol";
import {
  BaseChainAdapter,
  type ChainContext,
} from "../src/adapters/BaseChainAdapter";
import { SolanaAdapter } from "../src/adapters/SolanaAdapter";
import { Transaction, Keypair } from "@solana/web3.js";
import { MEMO_PROGRAM_ID } from "@solana/spl-memo";
import type { ChainAdapter } from "../src/adapters/BaseChainAdapter";
import type { ProtocolMetaFields } from "../src/utils/protocolMeta";
import { codeHash } from "../src/utils/crypto";

describe("ActionCodesProtocol", () => {
  let protocol: ActionCodesProtocol;

  beforeEach(() => {
    protocol = new ActionCodesProtocol({
      codeLength: 8,
      ttlMs: 120000,
    });
  });

  describe("adapter registry", () => {
    test("has solana adapter by default", () => {
      const solanaAdapter = protocol.getAdapter("solana");
      expect(solanaAdapter).toBeInstanceOf(SolanaAdapter);
    });

    test("can register custom adapters", () => {
      class CustomAdapter extends BaseChainAdapter<any> {
        verify(context: ChainContext<any>): boolean {
          return true;
        }
      }
      const customAdapter = new CustomAdapter();
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
      const { actionCode } = await protocol.generateCode("test-pubkey");

      expect(actionCode.code).toBeDefined();
      expect(actionCode.pubkey).toBe("test-pubkey");
      expect(actionCode.timestamp).toBeDefined();
      expect(actionCode.expiresAt).toBeDefined();
    });

    test("validates codes with chain adapter", async () => {
      const { actionCode } = await protocol.generateCode("test-pubkey");

      // Mock context for validation
      const context = {
        pubkey: "test-pubkey",
        signature: "mock-signature",
      };

      // This should throw because we're using a mock signature
      await expect(protocol.validateCode(actionCode, "solana", context)).rejects.toThrow();
    });
  });
});
