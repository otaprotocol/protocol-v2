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

export interface CodeGenerationConfig {
  codeLength: number; // characters (Base32)
  ttlMs: number; // default 2 minutes
  clockSkewMs?: number; // tolerated skew for validation
}

export interface CodeGenerationResult {
  actionCode: ActionCode;
  canonicalMessage: Uint8Array;
}

