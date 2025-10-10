import { WalletStrategy } from "./WalletStrategy";
import { getCanonicalMessageParts } from "../utils/canonical";
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

    // Generate canonical message using the delegated pubkey
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
    // Validate the action code itself
    this.walletStrategy.validateCode(actionCode);

    // Verify delegation proof is still valid
    this.validateDelegationProof(delegationProof);

    // Verify the delegation proof matches the action code
    if (
      actionCode.delegationProof.walletPubkey !== delegationProof.walletPubkey
    ) {
      throw new Error(
        "Action code wallet pubkey does not match delegation proof"
      );
    }

    if (
      actionCode.delegationProof.delegatedPubkey !==
      delegationProof.delegatedPubkey
    ) {
      throw new Error(
        "Action code delegated pubkey does not match delegation proof"
      );
    }

    if (actionCode.delegationProof.expiresAt !== delegationProof.expiresAt) {
      throw new Error(
        "Action code delegation expiration does not match delegation proof"
      );
    }

    if (actionCode.delegationProof.signature !== delegationProof.signature) {
      throw new Error(
        "Action code delegation signature does not match delegation proof"
      );
    }

    // Verify delegated signature is present
    if (!actionCode.delegatedSignature) {
      throw new Error("Delegated signature is required");
    }
  }

  /**
   * Validate a delegation proof
   */
  private validateDelegationProof(delegationProof: DelegationProof): void {
    if (!delegationProof.walletPubkey) {
      throw new Error("Wallet pubkey is required");
    }

    if (!delegationProof.delegatedPubkey) {
      throw new Error("Delegated pubkey is required");
    }

    if (!delegationProof.expiresAt) {
      throw new Error("Expiration time is required");
    }

    if (!delegationProof.signature) {
      throw new Error("Delegation signature is required");
    }

    // Check if delegation has expired
    if (delegationProof.expiresAt < Date.now()) {
      throw new Error("Delegation proof has expired");
    }
  }

  /**
   * Get the wallet strategy instance for advanced usage
   */
  getWalletStrategy(): WalletStrategy {
    return this.walletStrategy;
  }

  /**
   * Get canonical message parts for delegation
   */
  getCanonicalMessageParts(
    pubkey: string,
    providedSecret?: string
  ): Uint8Array {
    return getCanonicalMessageParts(pubkey, this.config.ttlMs, providedSecret);
  }
}
