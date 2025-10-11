import { WalletStrategy } from "./WalletStrategy";
import { getCanonicalMessageParts, serializeCanonical } from "../utils/canonical";
import { ProtocolError } from "../errors";
import { PublicKey } from "@solana/web3.js";
import nacl from "tweetnacl";
import bs58 from "bs58";

import type {
  DelegationProof,
  DelegatedActionCode,
  CodeGenerationConfig,
  DelegationStrategyCodeGenerationResult,
} from "../types";

export class DelegationStrategy {
  private walletStrategy: WalletStrategy;
  private config: CodeGenerationConfig;

  constructor(config: CodeGenerationConfig) {
    this.config = config;
    this.walletStrategy = new WalletStrategy(config);
  }

  /**
   * Generate a delegated action code using a delegation proof and delegated signature
   */
  generateDelegatedCode(
    delegationProof: DelegationProof,
    delegatedSignature: string
  ): DelegationStrategyCodeGenerationResult {
    // Validate delegation proof format and expiration
    this.validateDelegationProof(delegationProof);

    // Generate canonical message using the delegated pubkey (the signer)
    const canonicalMessage = getCanonicalMessageParts(
      delegationProof.delegatedPubkey,
      this.config.ttlMs
    );

    // Generate code using existing WalletStrategy with canonical message
    const result = this.walletStrategy.generateCode(
      canonicalMessage,
      delegatedSignature // Use delegated signature
    );

    // Create delegated action code
    const delegatedActionCode: DelegatedActionCode = {
      ...result.actionCode,
      pubkey: delegationProof.walletPubkey, // Code belongs to the user who delegated
      delegationProof: delegationProof,
      delegatedSignature: delegatedSignature,
    };

    return {
      actionCode: delegatedActionCode,
    };
  }

  /**
   * Validate a delegated action code
   */
  validateDelegatedCode(
    actionCode: DelegatedActionCode,
    delegationProof: DelegationProof
  ): void {
    // Basic validation checks (similar to WalletStrategy.validateCode)
    const currentTime = Date.now();
    if (currentTime > actionCode.expiresAt + (this.config.clockSkewMs ?? 0)) {
      throw ProtocolError.expiredCode(
        actionCode.code,
        actionCode.expiresAt,
        currentTime
      );
    }

    // Verify delegation proof is still valid
    this.validateDelegationProof(delegationProof);

    // Verify the delegation proof matches the action code
    if (
      actionCode.delegationProof.walletPubkey !== delegationProof.walletPubkey
    ) {
      throw ProtocolError.invalidInput(
        "walletPubkey",
        actionCode.delegationProof.walletPubkey,
        "Action code wallet pubkey does not match delegation proof"
      );
    }

    if (
      actionCode.delegationProof.delegatedPubkey !==
      delegationProof.delegatedPubkey
    ) {
      throw ProtocolError.invalidInput(
        "delegatedPubkey",
        actionCode.delegationProof.delegatedPubkey,
        "Invalid delegatedPubkey: Action code delegated pubkey does not match delegation proof"
      );
    }

    if (actionCode.delegationProof.expiresAt !== delegationProof.expiresAt) {
      throw ProtocolError.invalidInput(
        "expiresAt",
        actionCode.delegationProof.expiresAt,
        "Action code delegation expiration does not match delegation proof"
      );
    }

    if (actionCode.delegationProof.signature !== delegationProof.signature) {
      throw ProtocolError.invalidInput(
        "signature",
        actionCode.delegationProof.signature,
        "Invalid signature: Action code delegation signature does not match delegation proof"
      );
    }

    // Verify delegated signature is present
    if (!actionCode.delegatedSignature) {
      throw ProtocolError.missingRequiredField("delegatedSignature");
    }

    // Finally, verify the delegated signature against the canonical message
    // Use the original timestamp from the action code, not the current time
    const canonicalMessage = serializeCanonical({
      pubkey: delegationProof.delegatedPubkey,
      windowStart: actionCode.timestamp,
    });
    
    // Decode and verify the delegated signature
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = bs58.decode(actionCode.delegatedSignature);
    } catch {
      throw ProtocolError.invalidSignature("Invalid Base58 delegated signature format");
    }

    // Verify the signature using the delegated keypair's public key
    const delegatedPubkeyBytes = bs58.decode(delegationProof.delegatedPubkey);
    const isValidSignature = nacl.sign.detached.verify(
      canonicalMessage,
      signatureBytes,
      delegatedPubkeyBytes
    );

    if (!isValidSignature) {
      throw ProtocolError.invalidSignature("Delegated signature verification failed");
    }
  }

  /**
   * Validate a delegation proof with comprehensive input validation
   */
  private validateDelegationProof(delegationProof: DelegationProof): void {
    // Validate walletPubkey using Solana's PublicKey constructor
    if (!delegationProof.walletPubkey || typeof delegationProof.walletPubkey !== 'string') {
      throw ProtocolError.invalidInput("walletPubkey", delegationProof.walletPubkey, "Wallet pubkey is required and must be a string");
    }
    try {
      new PublicKey(delegationProof.walletPubkey);
    } catch {
      throw ProtocolError.invalidInput("walletPubkey", delegationProof.walletPubkey, "Invalid wallet pubkey format");
    }

    // Validate delegatedPubkey using Solana's PublicKey constructor
    if (!delegationProof.delegatedPubkey || typeof delegationProof.delegatedPubkey !== 'string') {
      throw ProtocolError.invalidInput("delegatedPubkey", delegationProof.delegatedPubkey, "Delegated pubkey is required and must be a string");
    }
    try {
      new PublicKey(delegationProof.delegatedPubkey);
    } catch {
      throw ProtocolError.invalidInput("delegatedPubkey", delegationProof.delegatedPubkey, "Invalid delegated pubkey format");
    }

    // Validate chain
    if (!delegationProof.chain || typeof delegationProof.chain !== 'string') {
      throw ProtocolError.invalidInput("chain", delegationProof.chain, "Chain is required and must be a string");
    }
    if (delegationProof.chain.length === 0 || delegationProof.chain.length > 50) {
      throw ProtocolError.invalidInput("chain", delegationProof.chain, "Chain must be between 1 and 50 characters");
    }
    if (!/^[a-z0-9-]+$/.test(delegationProof.chain)) {
      throw ProtocolError.invalidInput("chain", delegationProof.chain, "Chain contains invalid characters (only lowercase letters, numbers, and hyphens allowed)");
    }

    // Validate expiresAt
    if (typeof delegationProof.expiresAt !== 'number' || !Number.isInteger(delegationProof.expiresAt)) {
      throw ProtocolError.invalidInput("expiresAt", delegationProof.expiresAt, "Expiration time must be a valid integer timestamp");
    }
    if (delegationProof.expiresAt <= 0) {
      throw ProtocolError.invalidInput("expiresAt", delegationProof.expiresAt, "Expiration time must be positive");
    }
    
    // Check for reasonable expiration bounds (not too far in the future)
    const now = Date.now();
    const maxFuture = 365 * 24 * 60 * 60 * 1000; // 1 year from now
    
    if (delegationProof.expiresAt > now + maxFuture) {
      throw ProtocolError.invalidInput("expiresAt", delegationProof.expiresAt, "Expiration time is too far in the future");
    }

    // Check if delegation has expired
    if (delegationProof.expiresAt < now) {
      throw ProtocolError.expiredCode("Delegation proof has expired", delegationProof.expiresAt, now);
    }

    // Validate signature
    if (!delegationProof.signature || typeof delegationProof.signature !== 'string') {
      throw ProtocolError.invalidInput("signature", delegationProof.signature, "Delegation signature is required and must be a string");
    }
    if (delegationProof.signature.length === 0 || delegationProof.signature.length > 200) {
      throw ProtocolError.invalidInput("signature", delegationProof.signature, "Delegation signature must be between 1 and 200 characters");
    }
    // Note: Signature format validation will be done during actual verification
  }

  /**
   * Get canonical message parts for delegation
   */
  getCanonicalMessageParts(pubkey: string): Uint8Array {
    return getCanonicalMessageParts(pubkey, this.config.ttlMs);
  }
}
