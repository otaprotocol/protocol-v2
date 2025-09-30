import {
  Keypair,
  PublicKey,
  Transaction,
  VersionedTransaction,
  MessageV0,
} from "@solana/web3.js";
import { MEMO_PROGRAM_ID } from "@solana/spl-memo";
import bs58 from "bs58";
import nacl from "tweetnacl";
import {
  SolanaAdapter,
  type SolanaContext,
} from "../../src/adapters/SolanaAdapter";
import { type ChainContext } from "../../src/adapters/BaseChainAdapter";
import { serializeCanonical } from "../../src/utils/canonical";
import { codeHash } from "../../src/utils/crypto";
import type { ActionCode } from "../../src/types";
import type { ProtocolMetaFields } from "../../src/utils/protocolMeta";

describe("SolanaAdapter", () => {
  let adapter: SolanaAdapter;
  let keypair: Keypair;

  beforeEach(() => {
    adapter = new SolanaAdapter();
    keypair = Keypair.generate();
  });

  describe("verify method", () => {
    test("verify returns true for valid signature", () => {
      const canonicalMessageParts = {
        pubkey: keypair.publicKey.toString(),
        windowStart: Date.now(),
      };
      const message = serializeCanonical(canonicalMessageParts);
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const context: ChainContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey,
        signature: signatureB58,
        canonicalMessageParts,
      };

      const result = adapter.verifyWithWallet(context);
      expect(result).toBe(true);
    });

    test("verify returns false for invalid signature", () => {
      const canonicalMessageParts = {
        pubkey: keypair.publicKey.toString(),
        windowStart: Date.now(),
      };
      const message = serializeCanonical(canonicalMessageParts);
      const wrongKeypair = nacl.sign.keyPair();
      const signature = nacl.sign.detached(message, wrongKeypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const context: ChainContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey, // Different pubkey than the one used to sign
        signature: signatureB58,
        canonicalMessageParts,
      };

      const result = adapter.verifyWithWallet(context);
      expect(result).toBe(false);
    });

    test("verify works with both string and PublicKey pubkeys", () => {
      const canonicalMessageParts = {
        pubkey: keypair.publicKey.toString(),
        windowStart: Date.now(),
      };
      const message = serializeCanonical(canonicalMessageParts);
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      // Test with PublicKey object
      const context1: ChainContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey, // PublicKey object
        signature: signatureB58,
        canonicalMessageParts,
      };
      expect(adapter.verifyWithWallet(context1)).toBe(true);

      // Test with base58 string
      const context2: ChainContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey.toString(), // base58 string
        signature: signatureB58,
        canonicalMessageParts,
      };
      expect(adapter.verifyWithWallet(context2)).toBe(true);
    });
  });

  describe("transaction meta methods", () => {
    test("createProtocolMetaIx creates valid memo instruction", () => {
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      });

      expect(instruction.programId.toString()).toBe(MEMO_PROGRAM_ID.toString());
      expect(instruction.keys).toHaveLength(0);
      expect(instruction.data.toString("utf8")).toContain("actioncodes:ver=2");
    });

    test("getProtocolMeta extracts meta from transaction", () => {
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      });
      const tx = new Transaction().add(instruction);

      const result = adapter.getProtocolMeta(tx);
      expect(result).toContain("actioncodes:ver=2");
      expect(result).toContain(`id=${codeHashValue}`);
      expect(result).toContain("int=user%40example.com"); // URL encoded @
      expect(result).toContain("p=%7B%22amount%22%3A100%7D"); // URL encoded JSON
    });

    test("getProtocolMeta returns null when no memo instruction", () => {
      const tx = new Transaction(); // Empty transaction

      const result = adapter.getProtocolMeta(tx);
      expect(result).toBe(null);
    });

    test("parseMeta extracts and parses meta from transaction", () => {
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      });
      const tx = new Transaction().add(instruction);

      const result = adapter.parseMeta(tx);
      expect(result).toEqual({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      });
    });

    test("parseMeta returns null when no valid meta", () => {
      const tx = new Transaction(); // Empty transaction

      const result = adapter.parseMeta(tx);
      expect(result).toBe(null);
    });

    test("verifyTransactionMatchesCode validates action code against transaction meta", () => {
      const actionCode: ActionCode = {
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
        adapter.verifyTransactionMatchesCode(actionCode, tx);
      }).not.toThrow();
    });

    test("verifyTransactionMatchesCode throws when meta doesn't match", () => {
      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: "user@example.com",
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        signature: "test-signature",
      };

      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: "different-codehash", // Different codeHash
        int: "user@example.com",
      });
      const tx = new Transaction().add(instruction);

      expect(() => {
        adapter.verifyTransactionMatchesCode(actionCode, tx);
      }).toThrow();
    });

    test("verifyTransactionMatchesCode throws when no meta", () => {
      const actionCode: ActionCode = {
        code: "12345678",
        pubkey: "user@example.com",
        timestamp: Date.now(),
        expiresAt: Date.now() + 120000,
        signature: "test-signature",
      };

      const tx = new Transaction(); // Empty transaction

      expect(() => {
        adapter.verifyTransactionMatchesCode(actionCode, tx);
      }).toThrow();
    });

    test("verifyTransactionSignedByIntentOwner returns true when transaction is signed by intended owner", () => {
      const keypair = Keypair.generate();
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: keypair.publicKey.toString(), // Use the keypair's pubkey as intended
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111"; // Mock recent blockhash
      tx.sign(keypair); // Sign with the intended keypair

      // Should not throw for valid transaction
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(tx);
      }).not.toThrow();
    });

    test("verifyTransactionSignedByIntentOwner throws when transaction is not signed by intended owner", () => {
      const intendedKeypair = Keypair.generate();
      const signingKeypair = Keypair.generate(); // Different keypair
      const code = "12345678";
      const codeHashValue = codeHash(code);

      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: intendedKeypair.publicKey.toString(), // Intended is different from signer
      });

      const tx = new Transaction().add(instruction);
      tx.recentBlockhash = "11111111111111111111111111111111"; // Mock recent blockhash
      tx.sign(signingKeypair); // Sign with different keypair

      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(tx);
      }).toThrow();
    });

    test("verifyTransactionSignedByIntentOwner throws when no meta", () => {
      const keypair = Keypair.generate();
      const tx = new Transaction();
      tx.recentBlockhash = "11111111111111111111111111111111"; // Mock recent blockhash
      tx.sign(keypair);

      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(tx);
      }).toThrow();
    });

    test("verifyTransactionSignedByIntentOwner throws when intended pubkey is invalid", () => {
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: codeHashValue,
        int: "invalid-pubkey", // Invalid pubkey format
      });

      const tx = new Transaction().add(instruction);

      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(tx);
      }).toThrow();
    });

    test("attachProtocolMeta adds meta to legacy transaction", () => {
      const tx = new Transaction();
      const code = "12345678";
      const codeHashValue = codeHash(code);
      const meta = {
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      };

      const result = SolanaAdapter.attachProtocolMeta(
        tx,
        meta as ProtocolMetaFields
      );

      // Should be the same transaction instance (mutated)
      expect(result).toBe(tx);

      // Should have the memo instruction
      expect(tx.instructions).toHaveLength(1);
      expect(tx.instructions[0]!.programId.toString()).toBe(
        MEMO_PROGRAM_ID.toString()
      );

      // Should be able to extract the meta
      const extractedMeta = adapter.getProtocolMeta(tx);
      expect(extractedMeta).toContain("actioncodes:ver=2");
      expect(extractedMeta).toContain(`id=${codeHashValue}`);
    });

    test("attachProtocolMeta adds meta to versioned transaction", () => {
      const keypair = Keypair.generate();
      const tx = new VersionedTransaction(
        new MessageV0({
          header: {
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0,
          },
          staticAccountKeys: [keypair.publicKey],
          recentBlockhash: "11111111111111111111111111111111",
          compiledInstructions: [],
          addressTableLookups: [],
        })
      );

      const code = "87654321";
      const codeHashValue = codeHash(code);
      const meta = {
        ver: 2,
        id: codeHashValue,
        int: "user2@example.com",
      };

      const result = SolanaAdapter.attachProtocolMeta(
        tx,
        meta as ProtocolMetaFields
      );

      // Should be a new transaction instance
      expect(result).not.toBe(tx);

      // Should be able to extract the meta
      const extractedMeta = adapter.getProtocolMeta(result);
      expect(extractedMeta).toContain("actioncodes:ver=2");
      expect(extractedMeta).toContain(`id=${codeHashValue}`);
    });

    test("attachProtocolMeta preserves existing signatures", () => {
      const keypair = Keypair.generate();
      const tx = new VersionedTransaction(
        new MessageV0({
          header: {
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0,
          },
          staticAccountKeys: [keypair.publicKey],
          recentBlockhash: "11111111111111111111111111111111",
          compiledInstructions: [],
          addressTableLookups: [],
        })
      );

      // Add some mock signatures
      tx.signatures = [new Uint8Array(64).fill(1)];

      const code = "11111111";
      const codeHashValue = codeHash(code);
      const meta = {
        ver: 2,
        id: codeHashValue,
        int: "user3@example.com",
      };

      const result = SolanaAdapter.attachProtocolMeta(
        tx,
        meta as ProtocolMetaFields
      );

      // Should preserve signatures
      expect(result.signatures).toEqual(tx.signatures);
    });

    test("attachProtocolMeta handles MEMO_PROGRAM_ID already present", () => {
      const keypair = Keypair.generate();
      const tx = new VersionedTransaction(
        new MessageV0({
          header: {
            numRequiredSignatures: 1,
            numReadonlySignedAccounts: 0,
            numReadonlyUnsignedAccounts: 0,
          },
          staticAccountKeys: [keypair.publicKey, MEMO_PROGRAM_ID], // Already present
          recentBlockhash: "11111111111111111111111111111111",
          compiledInstructions: [],
          addressTableLookups: [],
        })
      );

      const code = "22222222";
      const codeHashValue = codeHash(code);
      const meta = {
        ver: 2,
        id: codeHashValue,
        int: "user4@example.com",
      };

      const result = SolanaAdapter.attachProtocolMeta(
        tx,
        meta as ProtocolMetaFields
      );

      // Should not duplicate MEMO_PROGRAM_ID
      const msg = result.message as MessageV0;
      const memoProgramCount = msg.staticAccountKeys.filter((k) =>
        k.equals(MEMO_PROGRAM_ID)
      ).length;
      expect(memoProgramCount).toBe(1);

      // Should still work
      const extractedMeta = adapter.getProtocolMeta(result);
      expect(extractedMeta).toContain("actioncodes:ver=2");
    });

    test("attachProtocolMeta throws for unsupported transaction type", () => {
      const code = "33333333";
      const codeHashValue = codeHash(code);
      const meta = { ver: 2, id: codeHashValue, int: "user" };

      // Mock an unsupported transaction type
      const unsupportedTx = {} as any;

      expect(() => {
        SolanaAdapter.attachProtocolMeta(
          unsupportedTx,
          meta as ProtocolMetaFields
        );
      }).toThrow("Unsupported transaction type");
    });
  });

  describe("integration tests", () => {
    test("full workflow: sign message and verify with adapter", () => {
      // Simulate the full workflow
      const canonicalMessageParts = {
        pubkey: keypair.publicKey.toString(),
        windowStart: Date.now(),
      };
      const canonicalMessage = serializeCanonical(canonicalMessageParts);
      const signature = nacl.sign.detached(canonicalMessage, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const context: ChainContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey,
        signature: signatureB58,
        canonicalMessageParts,
      };

      // Verify the signature
      const verifyResult = adapter.verifyWithWallet(context);
      expect(verifyResult).toBe(true);

      // Note: Protocol meta validation is now handled by transaction inspection
      // This is a policy decision, not a protocol requirement
    });

    test("performance test: multiple verifications", () => {
      const canonicalMessageParts = {
        pubkey: keypair.publicKey.toString(),
        windowStart: Date.now(),
      };
      const canonicalMessage = serializeCanonical(canonicalMessageParts);
      const signature = nacl.sign.detached(canonicalMessage, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const context: ChainContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey,
        signature: signatureB58,
        canonicalMessageParts,
      };

      // Test different batch sizes
      const batchSizes = [10, 50, 100, 200];
      const results: {
        batchSize: number;
        timeMs: number;
        perVerificationMs: number;
      }[] = [];

      for (const batchSize of batchSizes) {
        const start = Date.now();
        const batchResults = Array.from({ length: batchSize }, () =>
          adapter.verifyWithWallet(context)
        );
        const end = Date.now();

        const timeMs = end - start;
        const perVerificationMs = timeMs / batchSize;

        results.push({ batchSize, timeMs, perVerificationMs });

        // All should be true
        expect(batchResults.every((r) => r === true)).toBe(true);
      }

      console.log("\n=== Performance Results ===");
      results.forEach(({ batchSize, timeMs, perVerificationMs }) => {
        console.log(
          `${batchSize} verifications: ${timeMs}ms (${perVerificationMs.toFixed(
            2
          )}ms each)`
        );
      });

      // Performance should be reasonable for 100 verifications
      const hundredVerifications = results.find((r) => r.batchSize === 100);
      expect(hundredVerifications?.timeMs).toBeLessThan(500); // 500ms for 100 verifications
      expect(hundredVerifications?.perVerificationMs).toBeLessThan(5); // 5ms per verification
    });
  });
});
