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
import {
  type ChainWalletStrategyContext,
  type ChainWalletStrategyRevokeContext,
} from "../../src/adapters/BaseChainAdapter";
import {
  serializeCanonical,
  serializeCanonicalRevoke,
} from "../../src/utils/canonical";
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

      const context: ChainWalletStrategyContext<SolanaContext> = {
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

      const context: ChainWalletStrategyContext<SolanaContext> = {
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
      const context1: ChainWalletStrategyContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey, // PublicKey object
        signature: signatureB58,
        canonicalMessageParts,
      };
      expect(adapter.verifyWithWallet(context1)).toBe(true);

      // Test with base58 string
      const context2: ChainWalletStrategyContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey.toString(), // base58 string
        signature: signatureB58,
        canonicalMessageParts,
      };
      expect(adapter.verifyWithWallet(context2)).toBe(true);
    });
  });

  describe("verifyRevokeWithWallet method", () => {
    test("verifyRevokeWithWallet returns true for valid signature", () => {
      const canonicalRevokeMessageParts = {
        pubkey: keypair.publicKey.toString(),
        codeHash: "test-code-hash-123",
        windowStart: Date.now(),
      };
      const message = serializeCanonicalRevoke(canonicalRevokeMessageParts);
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const context: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey,
        signature: signatureB58,
        canonicalRevokeMessageParts,
      };

      const result = adapter.verifyRevokeWithWallet(context);
      expect(result).toBe(true);
    });

    test("verifyRevokeWithWallet returns false for invalid signature", () => {
      const canonicalRevokeMessageParts = {
        pubkey: keypair.publicKey.toString(),
        codeHash: "test-code-hash-123",
        windowStart: Date.now(),
      };
      const message = serializeCanonicalRevoke(canonicalRevokeMessageParts);
      const wrongKeypair = nacl.sign.keyPair();
      const signature = nacl.sign.detached(message, wrongKeypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const context: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey, // Different pubkey than the one used to sign
        signature: signatureB58,
        canonicalRevokeMessageParts,
      };

      const result = adapter.verifyRevokeWithWallet(context);
      expect(result).toBe(false);
    });

    test("verifyRevokeWithWallet works with both string and PublicKey pubkeys", () => {
      const canonicalRevokeMessageParts = {
        pubkey: keypair.publicKey.toString(),
        codeHash: "test-code-hash-456",
        windowStart: Date.now(),
      };
      const message = serializeCanonicalRevoke(canonicalRevokeMessageParts);
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      // Test with PublicKey object
      const context1: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey, // PublicKey object
        signature: signatureB58,
        canonicalRevokeMessageParts,
      };
      expect(adapter.verifyRevokeWithWallet(context1)).toBe(true);

      // Test with base58 string
      const context2: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey.toString(), // base58 string
        signature: signatureB58,
        canonicalRevokeMessageParts,
      };
      expect(adapter.verifyRevokeWithWallet(context2)).toBe(true);
    });

    test("verifyRevokeWithWallet returns false for wrong chain", () => {
      const canonicalRevokeMessageParts = {
        pubkey: keypair.publicKey.toString(),
        codeHash: "test-code-hash-789",
        windowStart: Date.now(),
      };
      const message = serializeCanonicalRevoke(canonicalRevokeMessageParts);
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);

      const context: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "ethereum", // Wrong chain
        pubkey: keypair.publicKey,
        signature: signatureB58,
        canonicalRevokeMessageParts,
      };

      const result = adapter.verifyRevokeWithWallet(context);
      expect(result).toBe(false);
    });

    test("verifyRevokeWithWallet returns false for missing required fields", () => {
      const canonicalRevokeMessageParts = {
        pubkey: keypair.publicKey.toString(),
        codeHash: "test-code-hash-999",
        windowStart: Date.now(),
      };

      // Missing signature
      const context1: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey,
        signature: "", // Empty signature
        canonicalRevokeMessageParts,
      };
      expect(adapter.verifyRevokeWithWallet(context1)).toBe(false);

      // Missing pubkey
      const context2: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "solana",
        pubkey: "", // Empty pubkey
        signature: "some-signature",
        canonicalRevokeMessageParts,
      };
      expect(adapter.verifyRevokeWithWallet(context2)).toBe(false);

      // Missing canonicalRevokeMessageParts
      const context3: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey,
        signature: "some-signature",
        canonicalRevokeMessageParts: null as any, // Missing parts
      };
      expect(adapter.verifyRevokeWithWallet(context3)).toBe(false);
    });

    test("verifyRevokeWithWallet handles malformed signature gracefully", () => {
      const canonicalRevokeMessageParts = {
        pubkey: keypair.publicKey.toString(),
        codeHash: "test-code-hash-malformed",
        windowStart: Date.now(),
      };

      const context: ChainWalletStrategyRevokeContext<SolanaContext> = {
        chain: "solana",
        pubkey: keypair.publicKey,
        signature: "invalid-base58-signature", // Invalid base58
        canonicalRevokeMessageParts,
      };

      const result = adapter.verifyRevokeWithWallet(context);
      expect(result).toBe(false);
    });

    test("verifyRevokeWithWallet handles different codeHash values", () => {
      const codeHashes = [
        "test-code-hash-1",
        "another-code-hash-2",
        "yet-another-code-hash-3",
        "a".repeat(64), // Long hash
        "short", // Short hash
      ];

      for (const codeHash of codeHashes) {
        const canonicalRevokeMessageParts = {
          pubkey: keypair.publicKey.toString(),
          codeHash,
          windowStart: Date.now(),
        };
        const message = serializeCanonicalRevoke(canonicalRevokeMessageParts);
        const signature = nacl.sign.detached(message, keypair.secretKey);
        const signatureB58 = bs58.encode(signature);

        const context: ChainWalletStrategyRevokeContext<SolanaContext> = {
          chain: "solana",
          pubkey: keypair.publicKey,
          signature: signatureB58,
          canonicalRevokeMessageParts,
        };

        const result = adapter.verifyRevokeWithWallet(context);
        expect(result).toBe(true);
      }
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
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      const result = adapter.getProtocolMeta(base64String);
      expect(result).toContain("actioncodes:ver=2");
      expect(result).toContain(`id=${codeHashValue}`);
      expect(result).toContain("int=user%40example.com"); // URL encoded @
      expect(result).toContain("p=%7B%22amount%22%3A100%7D"); // URL encoded JSON
    });

    test("getProtocolMeta returns null when no memo instruction", () => {
      const tx = new Transaction(); // Empty transaction
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      const result = adapter.getProtocolMeta(base64String);
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
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      const result = adapter.parseMeta(base64String);
      expect(result).toEqual({
        ver: 2,
        id: codeHashValue,
        int: "user@example.com",
        p: { amount: 100 },
      });
    });

    test("parseMeta returns null when no valid meta", () => {
      const tx = new Transaction(); // Empty transaction
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      const result = adapter.parseMeta(base64String);
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
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      // Should not throw for valid transaction
      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionMatchesCode(actionCode, base64String);
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
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionMatchesCode(actionCode, base64String);
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
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionMatchesCode(actionCode, base64String);
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
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;
      tx.recentBlockhash = "11111111111111111111111111111111"; // Mock recent blockhash
      tx.sign(keypair); // Sign with the intended keypair

      // Should not throw for valid transaction
      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
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
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = signingKeypair.publicKey; // Use the signing keypair as fee payer
      tx.sign(signingKeypair); // Sign with different keypair

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
      }).toThrow();
    });

    test("verifyTransactionSignedByIntentOwner throws when no meta", () => {
      const keypair = Keypair.generate();
      const tx = new Transaction();
      tx.recentBlockhash = "11111111111111111111111111111111"; // Mock recent blockhash
      tx.feePayer = keypair.publicKey;
      tx.sign(keypair);

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
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
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");
      expect(() => {
        adapter.verifyTransactionSignedByIntentOwner(base64String);
      }).toThrow();
    });

    test("attachProtocolMeta adds meta to legacy transaction", () => {
      const tx = new Transaction();
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;

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

      // Should return a new base64 string
      expect(result).not.toBe(base64String);

      // Should be able to deserialize the result
      const resultTx = Transaction.from(Buffer.from(result, "base64"));
      expect(resultTx.instructions).toHaveLength(1);
      expect(resultTx.instructions[0]!.programId.toString()).toBe(
        MEMO_PROGRAM_ID.toString()
      );

      // Should be able to extract the meta
      const extractedMeta = adapter.getProtocolMeta(result);
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

      const base64String = Buffer.from(tx.serialize()).toString("base64");
      const result = SolanaAdapter.attachProtocolMeta(
        base64String,
        meta as ProtocolMetaFields
      );

      // Should return a new base64 string
      expect(result).not.toBe(base64String);

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

      const base64String = Buffer.from(tx.serialize()).toString("base64");
      const result = SolanaAdapter.attachProtocolMeta(
        base64String,
        meta as ProtocolMetaFields
      );

      // Should preserve signatures
      const resultTx = VersionedTransaction.deserialize(
        Buffer.from(result, "base64")
      );
      expect(resultTx.signatures).toEqual(tx.signatures);
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

      const base64String = Buffer.from(tx.serialize()).toString("base64");
      const result = SolanaAdapter.attachProtocolMeta(
        base64String,
        meta as ProtocolMetaFields
      );

      // Should not duplicate MEMO_PROGRAM_ID
      const resultTx = VersionedTransaction.deserialize(
        Buffer.from(result, "base64")
      );
      const msg = resultTx.message as MessageV0;
      const memoProgramCount = msg.staticAccountKeys.filter((k) =>
        k.equals(MEMO_PROGRAM_ID)
      ).length;
      expect(memoProgramCount).toBe(1);

      // Should still work
      const extractedMeta = adapter.getProtocolMeta(result);
      expect(extractedMeta).toContain("actioncodes:ver=2");
    });

    test("attachProtocolMeta throws for invalid transaction format", () => {
      const code = "33333333";
      const codeHashValue = codeHash(code);
      const meta = { ver: 2, id: codeHashValue, int: "user" };

      // Mock an invalid base64 string
      const invalidBase64 = "invalid-base64-string";

      expect(() => {
        SolanaAdapter.attachProtocolMeta(
          invalidBase64,
          meta as ProtocolMetaFields
        );
      }).toThrow("Invalid base64 transaction format");
    });

    test("attachProtocolMeta throws when transaction already has protocol meta", () => {
      const code = "44444444";
      const codeHashValue = codeHash(code);

      // Create transaction with existing protocol meta
      const existingMeta = {
        ver: 2,
        id: "existing-hash",
        int: keypair.publicKey.toString(),
      } as ProtocolMetaFields;
      const existingMetaIx = SolanaAdapter.createProtocolMetaIx(existingMeta);

      const tx = new Transaction();
      tx.recentBlockhash = "11111111111111111111111111111111";
      tx.feePayer = keypair.publicKey;
      tx.add(existingMetaIx);

      const base64String = Buffer.from(
        tx.serialize({ requireAllSignatures: false })
      ).toString("base64");

      // Try to attach new protocol meta
      const newMeta = { ver: 2, id: codeHashValue, int: "user" };

      expect(() => {
        SolanaAdapter.attachProtocolMeta(
          base64String,
          newMeta as ProtocolMetaFields
        );
      }).toThrow("Transaction already contains protocol meta");
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

      const context: ChainWalletStrategyContext<SolanaContext> = {
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

      const context: ChainWalletStrategyContext<SolanaContext> = {
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

  describe("String-based interface", () => {
    describe("deserializeTransaction", () => {
      test("should deserialize versioned transaction from base64", () => {
        // Create a simple versioned transaction
        const versionedTx = new VersionedTransaction(
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

        const base64String = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // Test that we can deserialize it
        const result = adapter.getProtocolMeta(base64String);
        expect(result).toBeNull(); // No memo instructions, so should be null
      });

      test("should deserialize legacy transaction from base64", () => {
        // Create a simple legacy transaction
        const legacyTx = new Transaction();
        legacyTx.recentBlockhash = "11111111111111111111111111111111";
        legacyTx.feePayer = keypair.publicKey;

        const base64String = Buffer.from(
          legacyTx.serialize({ requireAllSignatures: false })
        ).toString("base64");

        // Test that we can deserialize it
        const result = adapter.getProtocolMeta(base64String);
        expect(result).toBeNull(); // No memo instructions, so should be null
      });

      test("should throw error for invalid base64", () => {
        expect(() => {
          adapter.getProtocolMeta("invalid-base64-string");
        }).not.toThrow(); // getProtocolMeta should return null for invalid input
      });
    });

    describe("getProtocolMetaFromString", () => {
      test("should extract protocol meta from versioned transaction with memo", () => {
        // Create versioned transaction with memo
        const versionedTx = new VersionedTransaction(
          new MessageV0({
            header: {
              numRequiredSignatures: 1,
              numReadonlySignedAccounts: 0,
              numReadonlyUnsignedAccounts: 0,
            },
            staticAccountKeys: [keypair.publicKey, MEMO_PROGRAM_ID],
            recentBlockhash: "11111111111111111111111111111111",
            compiledInstructions: [
              {
                programIdIndex: 1,
                accountKeyIndexes: [],
                data: Buffer.from("test-memo", "utf8"),
              },
            ],
            addressTableLookups: [],
          })
        );

        const base64String = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        // This should return null because it's not a valid protocol meta
        const result = adapter.getProtocolMeta(base64String);
        expect(result).toBeNull();
      });
    });

    describe("parseMetaFromString", () => {
      test("should parse valid protocol meta from string", () => {
        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        // Create a transaction with valid protocol meta
        const tx = new Transaction();
        tx.recentBlockhash = "11111111111111111111111111111111";
        tx.feePayer = keypair.publicKey;

        // Add memo instruction with protocol meta using the proper format
        const metaIx = SolanaAdapter.createProtocolMetaIx(meta);
        tx.add(metaIx);

        const base64String = Buffer.from(
          tx.serialize({ requireAllSignatures: false })
        ).toString("base64");

        const result = adapter.parseMeta(base64String);
        expect(result).toEqual(meta);
      });
    });

    describe("verifyTransactionMatchesCode", () => {
      test("should verify transaction matches action code", () => {
        const actionCode: ActionCode = {
          code: "test-code",
          pubkey: keypair.publicKey.toString(),
          expiresAt: Date.now() + 3600000, // 1 hour from now
          timestamp: Date.now(),
        };

        const meta: ProtocolMetaFields = {
          ver: 2,
          id: codeHash("test-code"),
          int: keypair.publicKey.toString(),
        };

        // Create transaction with matching meta
        const tx = new Transaction();
        tx.recentBlockhash = "11111111111111111111111111111111";
        tx.feePayer = keypair.publicKey;

        const metaIx = SolanaAdapter.createProtocolMetaIx({
          ver: 2,
          id: codeHash("test-code"),
          int: keypair.publicKey.toString(),
        });
        tx.add(metaIx);

        const base64String = Buffer.from(
          tx.serialize({ requireAllSignatures: false })
        ).toString("base64");

        // Should not throw
        expect(() => {
          adapter.verifyTransactionMatchesCode(actionCode, base64String);
        }).not.toThrow();
      });
    });

    describe("attachProtocolMeta - Transaction Integrity", () => {
      test("should not modify original transaction string", () => {
        const originalTx = new Transaction();
        originalTx.recentBlockhash = "11111111111111111111111111111111";
        originalTx.feePayer = keypair.publicKey;

        const originalBase64 = Buffer.from(
          originalTx.serialize({ requireAllSignatures: false })
        ).toString("base64");
        const originalTxCopy = Transaction.from(
          Buffer.from(originalBase64, "base64")
        );

        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        // Attach protocol meta
        const newBase64 = SolanaAdapter.attachProtocolMeta(
          originalBase64,
          meta
        );

        // Original string should be unchanged
        expect(newBase64).not.toBe(originalBase64);

        // Original transaction should be unchanged
        const originalTxAfter = Transaction.from(
          Buffer.from(originalBase64, "base64")
        );
        expect(originalTxAfter.instructions.length).toBe(
          originalTxCopy.instructions.length
        );

        // New transaction should have one more instruction (the memo)
        const newTx = Transaction.from(Buffer.from(newBase64, "base64"));
        expect(newTx.instructions.length).toBe(
          originalTxCopy.instructions.length + 1
        );
      });

      test("should preserve signatures in versioned transaction", () => {
        const versionedTx = new VersionedTransaction(
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

        // Add a fake signature
        versionedTx.signatures = [new Uint8Array(64).fill(1)];

        const originalBase64 = Buffer.from(versionedTx.serialize()).toString(
          "base64"
        );

        const meta: ProtocolMetaFields = {
          ver: 2,
          id: "test-hash",
          int: keypair.publicKey.toString(),
        };

        const newBase64 = SolanaAdapter.attachProtocolMeta(
          originalBase64,
          meta
        );
        const newTx = VersionedTransaction.deserialize(
          Buffer.from(newBase64, "base64")
        );

        // Signatures should be preserved
        expect(newTx.signatures).toEqual(versionedTx.signatures);
      });
    });
  });
});
