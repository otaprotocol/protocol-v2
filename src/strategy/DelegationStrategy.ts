import { WalletStrategy } from "./WalletStrategy";
import { sha256 } from "../utils/crypto";
import {
  serializeCanonical,
  createDelegationCertificateTemplate,
  validateCertificateStructure,
  serializeCertificate,
  getCanonicalMessageParts,
} from "../utils/canonical";
import type {
  DelegationCertificate,
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
   * Generate a delegated action code using a signed certificate and delegated signature
   * The certificate acts as the secret for deterministic generation
   */
  generateDelegatedCode(
    certificate: DelegationCertificate,
    delegatedSignature: string
  ): DelegationStrategyCodeGenerationResult {
    // Validate certificate format and expiration only
    // Signature verification happens in ActionCodesProtocol.validateCode()
    if (!this.validateCertificateStructure(certificate)) {
      throw new Error("Invalid delegation certificate");
    }

    // Use certificate as the secret for deterministic generation
    const certificateSecret = this.hashCertificate(certificate);

    // Generate canonical message for delegation
    const windowStart =
      Math.floor(Date.now() / this.config.ttlMs) * this.config.ttlMs;
    const canonicalMessage = serializeCanonical({
      pubkey: certificate.delegator,
      windowStart,
      secret: certificateSecret,
    });

    // Generate code using existing WalletStrategy with canonical message
    const result = this.walletStrategy.generateCode(
      canonicalMessage,
      delegatedSignature, // Use delegated signature
      certificateSecret // Use certificate hash as secret
    );

    // Create delegated action code
    const delegatedActionCode: DelegatedActionCode = {
      ...result.actionCode,
      delegationId: this.hashCertificate(certificate),
      delegatedBy: certificate.delegator,
      delegatedSignature: delegatedSignature,
      delegatedPubkey: certificate.delegatedPubkey,
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
    certificate: DelegationCertificate
  ): void {
    // Validate the action code itself
    this.walletStrategy.validateCode(actionCode);

    // Verify delegation is still valid
    if (!this.validateCertificateStructure(certificate)) {
      throw new Error("Delegation certificate expired or invalid");
    }

    // Verify the certificate matches the action code
    if (actionCode.delegationId !== this.hashCertificate(certificate)) {
      throw new Error("Action code does not match delegation certificate");
    }

    // Verify the delegator matches
    if (actionCode.delegatedBy !== certificate.delegator) {
      throw new Error("Action code delegator does not match certificate");
    }

    // Verify the delegated pubkey matches
    if (actionCode.delegatedPubkey !== certificate.delegatedPubkey) {
      throw new Error(
        "Action code delegated pubkey does not match certificate"
      );
    }

    // Verify delegated signature is present
    if (!actionCode.delegatedSignature) {
      throw new Error("Delegated signature is required");
    }
  }

  /**
   * Get the wallet strategy instance for advanced usage
   */
  getWalletStrategy(): WalletStrategy {
    return this.walletStrategy;
  }

  // Instance methods for accessing canonical functions
  createDelegationCertificateTemplate(
    userPublicKey: string,
    delegatedPubkey: string,
    durationMs: number = 3600000,
    chain: string = "solana"
  ): Omit<DelegationCertificate, "signature"> {
    return createDelegationCertificateTemplate(
      userPublicKey,
      delegatedPubkey,
      durationMs,
      chain
    );
  }

  hashCertificate(certificate: DelegationCertificate): string {
    // Include signature in hash to prevent relayer code generation
    const serialized = this.serializeCertificate(certificate);
    const signatureBytes = new TextEncoder().encode(certificate.signature);

    // Combine certificate data with signature
    const combined = new Uint8Array(serialized.length + signatureBytes.length);
    combined.set(serialized, 0);
    combined.set(signatureBytes, serialized.length);

    const hash = sha256(combined);
    return Array.from(hash) 
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  serializeCertificate(
    certificate: Omit<DelegationCertificate, "signature">
  ): Uint8Array {
    return serializeCertificate(certificate);
  }

  validateCertificateStructure(certificate: DelegationCertificate): boolean {
    return validateCertificateStructure(certificate);
  }

  getCanonicalMessageParts(
    pubkey: string,
    providedSecret?: string
  ): Uint8Array {
    return getCanonicalMessageParts(pubkey, this.config.ttlMs, providedSecret);
  }
}
