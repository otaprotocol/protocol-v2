// !! this is only for demonstration purposes, do not use in production
// this shouldnt be exported from the package
import { createSign, createVerify, createPublicKey, generateKeyPairSync, KeyObject } from "crypto";
import { BaseChainAdapter, type ChainWalletStrategyContext, type ChainDelegationStrategyContext } from "./BaseChainAdapter";
import {
  buildProtocolMeta,
  parseProtocolMeta,
  type ProtocolMetaFields,
} from "../utils/protocolMeta";
import { codeHash } from "../utils/crypto";
import { serializeCanonical } from "../utils/canonical";
import type { ActionCode } from "../types";
import { ProtocolError } from "../errors";

export type NodeCryptoContext = {
  pubkey: string; // PEM format public key
  signature: string; // Base64 encoded signature
};

export class NodeCryptoAdapter extends BaseChainAdapter<NodeCryptoContext, NodeCryptoContext> {
  /** Verify the signature over canonical message using Node.js crypto */
  verifyWithWallet(context: ChainWalletStrategyContext<NodeCryptoContext>): boolean {
    if (context.chain !== "nodecrypto") return false;
    if (!context.pubkey || !context.signature || !context.canonicalMessageParts) return false;

    try {
      // Generate canonical message from parts
      const canonicalMessage = serializeCanonical(context.canonicalMessageParts);
      
      // Create verifier with the public key
      const verifier = createVerify("SHA256");
      verifier.update(canonicalMessage);
      
      // Verify the signature
      const publicKey = createPublicKey(context.pubkey);
      const isValid = verifier.verify(publicKey, context.signature, "base64");
      
      return isValid;
    } catch {
      // Invalid public key format or signature
      return false;
    }
  }

  /** Verify delegation certificate signature */
  verifyWithDelegation(_context: ChainDelegationStrategyContext<NodeCryptoContext>): boolean {
    // For now, just return true as this is a demo adapter
    // In a real implementation, this would verify the certificate signature
    return true;
  }

  /** Create a protocol meta instruction for NodeCrypto (simulated) */
  static createProtocolMetaInstruction(
    meta: ProtocolMetaFields
  ): { data: string; type: string } {
    const metaString = buildProtocolMeta(meta);
    return {
      data: metaString,
      type: "protocol-meta"
    };
  }

  /** Extract protocol metadata from a simulated transaction */
  getProtocolMeta(tx: { instructions?: Array<{ data: string; type: string }> }): string | null {
    if (!tx.instructions) return null;
    
    for (const instruction of tx.instructions) {
      if (instruction.type === "protocol-meta") {
        try {
          const parsed = parseProtocolMeta(instruction.data);
          if (parsed) return instruction.data;
        } catch {
          // ignore invalid meta
        }
      }
    }
    return null;
  }

  /** Get parsed ProtocolMeta object, or null if none or invalid */
  parseMeta(tx: { instructions?: Array<{ data: string; type: string }> }): ProtocolMetaFields | null {
    const s = this.getProtocolMeta(tx);
    if (!s) return null;
    return parseProtocolMeta(s);
  }

  /**
   * Validate that a transaction's meta aligns with the bound `actionCode`.
   * Throws ProtocolError if validation fails.
   */
  verifyTransactionMatchesCode(
    actionCode: ActionCode,
    tx: { instructions?: Array<{ data: string; type: string }> }
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
  verifyTransactionSignedByIntentOwner(
    tx: { 
      instructions?: Array<{ data: string; type: string }>;
      signatures?: Array<{ pubkey: string; signature: string }>;
    }
  ): void {
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

    // Check if the intended pubkey is in the signatures
    const signatures = tx.signatures || [];
    const isSigned = signatures.some(sig => sig.pubkey === intended);
    
    if (!isSigned) {
      const actualSigners = signatures.map(sig => sig.pubkey);
      throw ProtocolError.transactionNotSignedByIntendedOwner(
        intended,
        actualSigners
      );
    }
  }

  /**
   * Attach protocol meta to a simulated transaction.
   */
  static attachProtocolMeta(
    tx: { instructions?: Array<{ data: string; type: string }> },
    meta: ProtocolMetaFields
  ): { instructions: Array<{ data: string; type: string }> } {
    const metaInstruction = NodeCryptoAdapter.createProtocolMetaInstruction(meta);
    
    return {
      instructions: [...(tx.instructions || []), metaInstruction]
    };
  }

  /**
   * Sign a message with a private key
   */
  static signMessage(
    message: Uint8Array,
    privateKey: KeyObject
  ): string {
    const signer = createSign("SHA256");
    signer.update(message);
    return signer.sign(privateKey, "base64");
  }

  /**
   * Generate a key pair for testing
   */
  static generateKeyPair(): { publicKey: KeyObject; privateKey: KeyObject } {
    return generateKeyPairSync("rsa", {
      modulusLength: 2048
    });
  }
}
