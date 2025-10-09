import nacl from "tweetnacl";
import bs58 from "bs58";
import {
  PublicKey,
  Transaction,
  VersionedTransaction,
  TransactionInstruction,
  MessageV0,
} from "@solana/web3.js";
import { createMemoInstruction, MEMO_PROGRAM_ID } from "@solana/spl-memo";
import {
  BaseChainAdapter,
  type ChainWalletStrategyContext,
  type ChainWalletStrategyRevokeContext,
  type ChainDelegationStrategyContext,
} from "./BaseChainAdapter";
import {
  buildProtocolMeta,
  parseProtocolMeta,
  type ProtocolMetaFields,
} from "../utils/protocolMeta";
import { codeHash } from "../utils/crypto";
import type { ActionCode } from "../types";
import { ProtocolError } from "../errors";
import {
  serializeCanonical,
  serializeCanonicalRevoke,
} from "../utils/canonical";
import { DelegationStrategy } from "../strategy/DelegationStrategy";

export type SolanaContext = {
  pubkey: string | PublicKey;
  signature: string; // base58
};

/** Union of supported Solana txn types */
export type SolanaTransaction = Transaction | VersionedTransaction;

export class SolanaAdapter extends BaseChainAdapter<
  SolanaContext,
  SolanaContext,
  SolanaContext
> {
  /** Normalize pubkey input to PublicKey */
  private normalizePubkey(input: string | PublicKey): PublicKey {
    if (typeof input === "string") {
      return new PublicKey(input);
    }
    return input;
  }

  /** Verify the signature over canonical message (protocol-level) */
  verifyWithWallet(
    context: ChainWalletStrategyContext<SolanaContext>
  ): boolean {
    // Early validation checks - these are fast and don't leak timing info
    if (context.chain !== "solana") return false;
    if (!context.pubkey || !context.signature || !context.canonicalMessageParts)
      return false;

    // Perform all operations in a single try-catch to ensure consistent timing
    try {
      const message = serializeCanonical(context.canonicalMessageParts);
      const pub = this.normalizePubkey(context.pubkey);
      const sigBytes = bs58.decode(context.signature);
      const pubBytes = pub.toBytes();

      // Validate lengths
      if (sigBytes.length !== 64 || pubBytes.length !== 32) {
        return false;
      }

      // Perform signature verification
      return nacl.sign.detached.verify(message, sigBytes, pubBytes);
    } catch {
      // All errors result in false with consistent timing
      return false;
    }
  }

  /** Verify delegation certificate signature */
  verifyWithDelegation(
    context: ChainDelegationStrategyContext<SolanaContext>
  ): boolean {
    // Early validation checks - these are fast and don't leak timing info
    if (context.chain !== "solana") return false;
    if (!context.pubkey || !context.signature || !context.certificate)
      return false;

    const cert = context.certificate;

    // Use strategy for chain-agnostic certificate validation
    if (!DelegationStrategy.validateCertificateStructure(cert)) {
      return false;
    }

    // Check delegator matches the pubkey
    if (cert.delegator !== context.pubkey) return false;

    // Check chain matches
    if (cert.chain !== context.chain) return false;

    // Perform all operations in a single try-catch to ensure consistent timing
    try {
      // Serialize certificate for signature verification (using strategy method)
      const certWithoutSignature = {
        version: cert.version,
        delegator: cert.delegator,
        issuedAt: cert.issuedAt,
        expiresAt: cert.expiresAt,
        nonce: cert.nonce,
        chain: cert.chain,
      };
      const message =
        DelegationStrategy.serializeCertificate(certWithoutSignature);

      const pub = this.normalizePubkey(context.pubkey);
      const sigBytes = bs58.decode(context.signature);
      const pubBytes = pub.toBytes();

      // Validate lengths
      if (sigBytes.length !== 64 || pubBytes.length !== 32) {
        return false;
      }

      // Perform signature verification
      return nacl.sign.detached.verify(message, sigBytes, pubBytes);
    } catch {
      // All errors result in false with consistent timing
      return false;
    }
  }

  /** Verify the signature over canonical revoke message (protocol-level) */
  verifyRevokeWithWallet(
    context: ChainWalletStrategyRevokeContext<SolanaContext>
  ): boolean {
    // Early validation checks - these are fast and don't leak timing info
    if (context.chain !== "solana") return false;
    if (
      !context.pubkey ||
      !context.signature ||
      !context.canonicalRevokeMessageParts
    )
      return false;

    // Perform all operations in a single try-catch to ensure consistent timing
    try {
      const message = serializeCanonicalRevoke(
        context.canonicalRevokeMessageParts
      );
      const pub = this.normalizePubkey(context.pubkey);
      const sigBytes = bs58.decode(context.signature);
      const pubBytes = pub.toBytes();

      // Validate lengths
      if (sigBytes.length !== 64 || pubBytes.length !== 32) {
        return false;
      }

      // Perform signature verification
      return nacl.sign.detached.verify(message, sigBytes, pubBytes);
    } catch {
      // All errors result in false with consistent timing
      return false;
    }
  }

  /** Create a Solana memo instruction carrying protocol meta (for SDK/clients) */
  static createProtocolMetaIx(
    meta: ProtocolMetaFields
  ): TransactionInstruction {
    const metaString = buildProtocolMeta(meta);
    return createMemoInstruction(metaString);
  }

  /** Extract protocol metadata string (memo) from a base64-encoded transaction, or null */
  getProtocolMeta(txString: string): string | null {
    try {
      const tx = this.deserializeTransaction(txString);
      for (const ix of this.getMemoInstructions(tx)) {
        const data = ix.data;
        try {
          const s = new TextDecoder().decode(data);
          // Optionally: test parse
          const parsed = parseProtocolMeta(s);
          if (parsed) return s;
        } catch {
          // ignore
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  /** Deserialize a base64-encoded transaction string to SolanaTransaction */
  private deserializeTransaction(txString: string): SolanaTransaction {
    try {
      // Try versioned first (most common now)
      const versionedTx = VersionedTransaction.deserialize(
        Buffer.from(txString, "base64")
      );

      // Check if this is actually a versioned transaction by checking if it has a MessageV0
      if (versionedTx.message instanceof MessageV0) {
        return versionedTx;
      } else {
        // This is likely a legacy transaction that was incorrectly deserialized as versioned
        // Fall back to legacy deserialization
        return Transaction.from(Buffer.from(txString, "base64"));
      }
    } catch {
      try {
        // Fallback to legacy
        return Transaction.from(Buffer.from(txString, "base64"));
      } catch {
        throw ProtocolError.invalidTransactionFormat(
          "Invalid base64 transaction format"
        );
      }
    }
  }

  /** Get parsed ProtocolMeta object from base64-encoded transaction, or null if none or invalid */
  parseMeta(txString: string): ProtocolMetaFields | null {
    const s = this.getProtocolMeta(txString);
    if (!s) return null;
    return parseProtocolMeta(s);
  }

  /** List memo instructions from the transaction (legacy & versioned) */
  private getMemoInstructions(tx: SolanaTransaction): TransactionInstruction[] {
    if (tx instanceof Transaction) {
      return tx.instructions.filter((ix) =>
        ix.programId.equals(MEMO_PROGRAM_ID)
      );
    } else {
      // VersionedTransaction: inspect `message.compiledInstructions` / static keys
      const vtx = tx as VersionedTransaction;
      const msg = vtx.message;
      if (msg instanceof MessageV0) {
        const memos: TransactionInstruction[] = [];
        for (const ix of msg.compiledInstructions) {
          const pid = msg.staticAccountKeys[ix.programIdIndex];
          if (pid && pid.equals(MEMO_PROGRAM_ID)) {
            // reconstruct a TransactionInstruction for inspection
            const keys = ix.accountKeyIndexes.map((i) => ({
              pubkey: msg.staticAccountKeys[i]!,
              isSigner: false,
              isWritable: false,
            }));
            memos.push(
              new TransactionInstruction({
                keys,
                programId: pid,
                data: ix.data as Buffer,
              })
            );
          }
        }
        return memos;
      }
      return [];
    }
  }

  /**
   * Validate that a base64-encoded transaction's memo meta aligns with the bound `actionCode`.
   * Throws ProtocolError if validation fails.
   */
  verifyTransactionMatchesCode(actionCode: ActionCode, txString: string): void {
    // Check expiration first
    const currentTime = Date.now();
    if (currentTime > actionCode.expiresAt) {
      throw ProtocolError.expiredCode(
        actionCode.code,
        actionCode.expiresAt,
        currentTime
      );
    }

    const meta = this.parseMeta(txString);
    if (!meta) {
      throw ProtocolError.missingMeta();
    }

    // Check version
    if (meta.ver !== 2) {
      throw ProtocolError.metaMismatch("2", String(meta.ver), "ver");
    }

    // Check code ID - should be codeHash of the code, not the code itself
    const expectedCodeHash = codeHash(actionCode.code);
    if (meta.id !== expectedCodeHash) {
      throw ProtocolError.metaMismatch(expectedCodeHash, meta.id, "id");
    }

    // Check intended pubkey
    if (meta.int !== actionCode.pubkey) {
      throw ProtocolError.metaMismatch(actionCode.pubkey, meta.int, "int");
    }
  }

  /**
   * Verify that the base64-encoded transaction is signed by the "intendedFor" pubkey
   * as declared in the protocol meta of the transaction.
   * Throws ProtocolError if validation fails.
   */
  verifyTransactionSignedByIntentOwner(txString: string): void {
    const meta = this.parseMeta(txString);
    if (!meta) {
      throw ProtocolError.missingMeta();
    }

    const intended = meta.int;
    if (!intended) {
      throw ProtocolError.invalidMetaFormat(
        "Missing 'int' (intendedFor) field"
      );
    }

    let pubkey: PublicKey;
    try {
      pubkey = new PublicKey(intended);
    } catch {
      throw ProtocolError.invalidPubkeyFormat(
        intended,
        "Invalid public key format"
      );
    }

    const tx = this.deserializeTransaction(txString);
    const actualSigners: string[] = [];

    // For legacy Transaction
    if (tx instanceof Transaction) {
      const isSigned = tx.signatures.some((sig) => {
        if (!sig.signature) return false;
        actualSigners.push(sig.publicKey.toString());
        return sig.publicKey.equals(pubkey);
      });

      if (!isSigned) {
        throw ProtocolError.transactionNotSignedByIntendedOwner(
          intended,
          actualSigners
        );
      }
      return;
    }

    // For VersionedTransaction (MessageV0)
    if (tx instanceof VersionedTransaction) {
      const msg = tx.message;
      if (msg instanceof MessageV0) {
        const signerCount = msg.header.numRequiredSignatures;
        for (let i = 0; i < signerCount; i++) {
          const key = msg.staticAccountKeys[i];
          if (key) {
            actualSigners.push(key.toString());
            if (key.equals(pubkey)) {
              return; // Found the intended signer
            }
          }
        }
        throw ProtocolError.transactionNotSignedByIntendedOwner(
          intended,
          actualSigners
        );
      }
    }

    throw ProtocolError.invalidTransactionFormat(
      "Unsupported transaction format"
    );
  }

  /**
   * Attach protocol meta into a base64-encoded transaction and return the modified transaction as base64.
   * Throws ProtocolError if the transaction already contains protocol meta.
   */
  static attachProtocolMeta(
    txString: string,
    meta: ProtocolMetaFields
  ): string {
    // Check if transaction already has protocol meta
    const adapter = new SolanaAdapter();
    const existingMeta = adapter.getProtocolMeta(txString);
    if (existingMeta) {
      throw ProtocolError.invalidTransactionFormat(
        "Transaction already contains protocol meta. Cannot attach additional protocol meta."
      );
    }

    const metaIx = SolanaAdapter.createProtocolMetaIx(meta);

    try {
      // Try to deserialize as versioned first
      const versionedTx = VersionedTransaction.deserialize(
        Buffer.from(txString, "base64")
      );

      // Check if this is actually a versioned transaction by checking if it has a MessageV0
      if (versionedTx.message instanceof MessageV0) {
        const msg = versionedTx.message;

        // Extend static account keys with programId if missing
        const newStaticKeys = [...msg.staticAccountKeys];
        if (!newStaticKeys.some((k) => k.equals(MEMO_PROGRAM_ID))) {
          newStaticKeys.push(MEMO_PROGRAM_ID);
        }

        // Program ID index
        const programIdIndex = newStaticKeys.findIndex((k) =>
          k.equals(MEMO_PROGRAM_ID)
        );

        // Memo instruction as compiled instruction
        const compiledIx = {
          programIdIndex,
          accountKeyIndexes: [],
          data: metaIx.data,
        };

        const newMsg = new MessageV0({
          header: msg.header,
          staticAccountKeys: newStaticKeys,
          recentBlockhash: msg.recentBlockhash,
          compiledInstructions: [...msg.compiledInstructions, compiledIx],
          addressTableLookups: msg.addressTableLookups,
        });

        // Re-wrap in VersionedTransaction
        const newTx = new VersionedTransaction(newMsg);
        // Preserve existing signatures if any
        newTx.signatures = versionedTx.signatures;

        return Buffer.from(newTx.serialize()).toString("base64");
      } else {
        // This is likely a legacy transaction that was incorrectly deserialized as versioned
        // Fall back to legacy deserialization
        const legacyTx = Transaction.from(Buffer.from(txString, "base64"));

        // Legacy tx: just push memo instruction
        legacyTx.add(metaIx);

        return Buffer.from(
          legacyTx.serialize({ requireAllSignatures: false })
        ).toString("base64");
      }
    } catch {
      try {
        // Fallback to legacy transaction
        const legacyTx = Transaction.from(Buffer.from(txString, "base64"));

        // Legacy tx: just push memo instruction
        legacyTx.add(metaIx);

        return Buffer.from(
          legacyTx.serialize({ requireAllSignatures: false })
        ).toString("base64");
      } catch {
        throw ProtocolError.invalidTransactionFormat(
          "Invalid base64 transaction format"
        );
      }
    }
  }
}
