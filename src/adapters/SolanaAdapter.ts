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
import { BaseChainAdapter, type ChainContext } from "./BaseChainAdapter";
import {
  buildProtocolMeta,
  parseProtocolMeta,
  type ProtocolMetaFields,
} from "../utils/protocolMeta";
import { codeHash } from "../utils/crypto";
import type { ActionCode } from "../types";
import { ProtocolError } from "../errors";
import { serializeCanonical } from "../utils/canonical";

export type SolanaContext = {
  pubkey: string | PublicKey;
  signature: string; // base58
};

/** Union of supported Solana txn types */
export type SolanaTransaction = Transaction | VersionedTransaction;

export class SolanaAdapter extends BaseChainAdapter<SolanaContext> {
  /** Normalize pubkey input to PublicKey */
  private normalizePubkey(input: string | PublicKey): PublicKey {
    if (typeof input === "string") {
      return new PublicKey(input);
    }
    return input;
  }

  /** Verify the signature over canonical message (protocol-level) */
  verify(context: ChainContext<SolanaContext>): boolean {
    if (context.chain !== "solana") return false;
    if (!context.pubkey || !context.signature || !context.canonicalMessageParts)
      return false;

    const message = serializeCanonical(context.canonicalMessageParts);

    let pub: PublicKey;
    try {
      pub = this.normalizePubkey(context.pubkey);
    } catch {
      return false;
    }

    let sigBytes: Uint8Array;
    try {
      sigBytes = bs58.decode(context.signature);
    } catch {
      return false;
    }

    const pubBytes = pub.toBytes();
    if (sigBytes.length !== 64) return false;
    if (pubBytes.length !== 32) return false;

    try {
      return nacl.sign.detached.verify(message, sigBytes, pubBytes);
    } catch {
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

  /** Extract protocol metadata string (memo) from a transaction, or null */
  getProtocolMeta(tx: SolanaTransaction): string | null {
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
  }

  /** Get parsed ProtocolMeta object, or null if none or invalid */
  parseMeta(tx: SolanaTransaction): ProtocolMetaFields | null {
    const s = this.getProtocolMeta(tx);
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
   * Validate that a transaction's memo meta aligns with the bound `actionCode`.
   * Throws ProtocolError if validation fails.
   */
  verifyTransactionMatchesCode(
    actionCode: ActionCode,
    tx: SolanaTransaction
  ): void {
    // Check expiration first
    const currentTime = Date.now();
    if (currentTime > actionCode.expiresAt) {
      throw ProtocolError.expiredCode(
        actionCode.code,
        actionCode.expiresAt,
        currentTime
      );
    }

    const meta = this.parseMeta(tx);
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
   * Verify that the transaction is signed by the "intendedFor" pubkey
   * as declared in the protocol meta of the transaction.
   * Throws ProtocolError if validation fails.
   */
  verifyTransactionSignedByIntentOwner(tx: SolanaTransaction): void {
    const meta = this.parseMeta(tx);
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
   * Attach protocol meta into a legacy or versioned transaction.
   *
   * ⚠️ Note: this mutates the given transaction.
   */
  static attachProtocolMeta<T extends SolanaTransaction>(
    tx: T,
    meta: ProtocolMetaFields
  ): T {
    const metaIx = SolanaAdapter.createProtocolMetaIx(meta);

    if (tx instanceof Transaction) {
      // Legacy tx: just push memo instruction
      tx.add(metaIx);
      return tx as T;
    }

    if (tx instanceof VersionedTransaction) {
      const msg = tx.message as MessageV0;

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
      newTx.signatures = tx.signatures;
      return newTx as T;
    }

    throw new Error("Unsupported transaction type");
  }
}
