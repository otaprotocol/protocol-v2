import { WalletStrategy } from "./WalletStrategy";
import { generateNonce, sha256 } from "../utils/crypto";
import { serializeCanonical } from "../utils/canonical";
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
   * Create a delegation certificate template (no signing)
   * The wallet should sign this template to create a valid certificate
   */
  static createDelegationCertificateTemplate(
    userPublicKey: string,
    delegatedPubkey: string,
    durationMs: number = 3600000, // 1 hour default
    chain: string = "solana"
  ): Omit<DelegationCertificate, "signature"> {
    const now = Date.now();
    return {
      version: "1.0",
      delegator: userPublicKey,
      delegatedPubkey: delegatedPubkey,
      issuedAt: now,
      expiresAt: now + durationMs,
      nonce: generateNonce(),
      chain,
    };
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
    if (!this.validateCertificate(certificate)) {
      throw new Error("Invalid delegation certificate");
    }

    // Use certificate as the secret for deterministic generation
    const certificateSecret = DelegationStrategy.hashCertificate(certificate);

    // Generate canonical message for delegation
    const windowStart = Math.floor(Date.now() / this.config.ttlMs) * this.config.ttlMs;
    const canonicalMessage = serializeCanonical({ 
      pubkey: certificate.delegator, 
      windowStart, 
      secret: certificateSecret 
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
      delegationId: DelegationStrategy.hashCertificate(certificate),
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
    if (!this.validateCertificate(certificate)) {
      throw new Error("Delegation certificate expired or invalid");
    }

    // Verify the certificate matches the action code
    if (actionCode.delegationId !== DelegationStrategy.hashCertificate(certificate)) {
      throw new Error("Action code does not match delegation certificate");
    }

    // Verify the delegator matches
    if (actionCode.delegatedBy !== certificate.delegator) {
      throw new Error("Action code delegator does not match certificate");
    }

    // Verify the delegated pubkey matches
    if (actionCode.delegatedPubkey !== certificate.delegatedPubkey) {
      throw new Error("Action code delegated pubkey does not match certificate");
    }

    // Verify delegated signature is present
    if (!actionCode.delegatedSignature) {
      throw new Error("Delegated signature is required");
    }
  }

  /**
   * Check if a certificate is valid (not expired and properly formatted)
   */
  private validateCertificate(certificate: DelegationCertificate): boolean {
    // Check if certificate is expired
    if (Date.now() > certificate.expiresAt) {
      return false;
    }

    // Check if certificate is not yet valid (issued in the future)
    if (Date.now() < certificate.issuedAt) {
      return false;
    }

    // Check required fields
    if (
      !certificate.version ||
      !certificate.delegator ||
      !certificate.delegatedPubkey ||
      !certificate.issuedAt ||
      !certificate.expiresAt ||
      !certificate.nonce ||
      !certificate.chain ||
      !certificate.signature
    ) {
      return false;
    }

    // Check version
    if (certificate.version !== "1.0") {
      return false;
    }

    return true;
  }

  /**
   * Serialize a delegation certificate for signing (chain-agnostic)
   */
  static serializeCertificate(cert: Omit<DelegationCertificate, 'signature'>): Uint8Array {
    const json = JSON.stringify({
      version: cert.version,
      delegator: cert.delegator,
      delegatedPubkey: cert.delegatedPubkey,
      issuedAt: cert.issuedAt,
      expiresAt: cert.expiresAt,
      nonce: cert.nonce,
      chain: cert.chain
    });
    return new TextEncoder().encode(json);
  }

  /**
   * Hash a delegation certificate to create a unique ID (chain-agnostic)
   * Includes signature to prevent relayer from generating codes
   */
  static hashCertificate(cert: DelegationCertificate): string {
    // Include signature in hash to prevent relayer code generation
    const serialized = this.serializeCertificate(cert);
    const signatureBytes = new TextEncoder().encode(cert.signature);
    
    // Combine certificate data with signature
    const combined = new Uint8Array(serialized.length + signatureBytes.length);
    combined.set(serialized, 0);
    combined.set(signatureBytes, serialized.length);
    
    const hash = sha256(combined);
    return Array.from(hash)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Validate certificate structure and timing (chain-agnostic)
   * This should be called before signature verification
   */
  static validateCertificateStructure(certificate: DelegationCertificate): boolean {
    // Check required fields
    if (
      !certificate.version ||
      !certificate.delegator ||
      !certificate.delegatedPubkey ||
      !certificate.issuedAt ||
      !certificate.expiresAt ||
      !certificate.nonce ||
      !certificate.chain ||
      !certificate.signature
    ) {
      return false;
    }

    // Check version
    if (certificate.version !== "1.0") {
      return false;
    }

    // Check if certificate is expired
    if (Date.now() > certificate.expiresAt) {
      return false;
    }

    // Check if certificate is not yet valid (issued in the future)
    if (Date.now() < certificate.issuedAt) {
      return false;
    }

    return true;
  }

  /**
   * Get the wallet strategy instance for advanced usage
   */
  getWalletStrategy(): WalletStrategy {
    return this.walletStrategy;
  }
}
