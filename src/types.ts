export interface ActionCode {
  code: string;
  pubkey: string;
  timestamp: number;
  expiresAt: number;
  signature?: string;
  secretHint?: string;
  // optional secret for offline generation
  secret?: string; // Base64 encoded secret
}

export interface CanonicalMessageParts {
  pubkey: string;
  windowStart: number;
  // optional secret for deterministic but secure generation
  secret?: string; // Base64 encoded secret
}

export interface CanonicalRevokeMessageParts {
  pubkey: string;
  codeHash: string;
  windowStart: number;
}

export interface CodeGenerationConfig {
  codeLength: number; // characters (Base32)
  ttlMs: number; // default 2 minutes
  clockSkewMs?: number; // tolerated skew for validation
}

export interface WalletStrategyCodeGenerationResult {
  actionCode: ActionCode;
  canonicalMessage: Uint8Array;
}

export interface DelegationStrategyCodeGenerationResult {
  actionCode: DelegatedActionCode;
}

export interface DelegationCertificate {
  version: "1.0";
  delegator: string;        // User's public key
  delegatedPubkey: string;  // Delegated keypair's public key
  issuedAt: number;         // Unix timestamp
  expiresAt: number;        // Unix timestamp
  nonce: string;            // Prevent replay attacks
  chain: string;            // "solana", "ethereum", etc.
  signature: string;        // User's signature over the certificate
}

export interface DelegatedActionCode extends ActionCode {
  delegationId: string;     // Hash of the certificate
  delegatedBy: string;      // User's public key (same as delegator)
  delegatedSignature: string; // Signature from delegated keypair
  delegatedPubkey: string;    // Public key of delegated keypair
}

