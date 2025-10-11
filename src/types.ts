export interface ActionCode {
  code: string;
  pubkey: string;
  timestamp: number;
  expiresAt: number;
  signature?: string;
}

export interface CanonicalMessageParts {
  pubkey: string;
  windowStart: number;
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

export interface DelegationProof {
  walletPubkey: string;     // User's public key
  delegatedPubkey: string;  // Delegated keypair's public key
  expiresAt: number;        // Unix timestamp
  chain: string;            // Target blockchain chain
  signature: string;        // User's signature over: walletPubkey + delegatedPubkey + expiresAt + chain
}

export interface DelegatedActionCode extends ActionCode {
  delegationProof: DelegationProof; // The delegation proof
  delegatedSignature: string;       // Signature from delegated keypair
}

