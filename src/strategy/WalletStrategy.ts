import type {
  ActionCode,
  CodeGenerationConfig,
  WalletStrategyCodeGenerationResult,
} from "../types";
import { sha256, hmacSha256, truncateBits, digestToDigits } from "../utils/crypto";
import { CODE_MAX_LENGTH, CODE_MIN_LENGTH } from "../constants";
import { serializeCanonical } from "../utils/canonical";
import { ProtocolError } from "../errors";

export class WalletStrategy {
  constructor(private config: CodeGenerationConfig) {}

  generateCode(
    canonicalMessage: Uint8Array,
    signature: string,
    providedSecret?: string,
  ): WalletStrategyCodeGenerationResult {
    const canonical = canonicalMessage;
    
    // Parse pubkey and windowStart from canonical message
    const decoded = JSON.parse(new TextDecoder().decode(canonical));
    const pubkey = decoded.pubkey;
    const windowStart = decoded.windowStart;
    
    // Only use secret if explicitly provided
    const secret = providedSecret;
    
    // Use signature if provided, otherwise fall back to secret/HMAC
    let digest: Uint8Array;
    if (signature) {
      // Use signature as the primary entropy source
      const signatureBytes = new TextEncoder().encode(signature);
      digest = hmacSha256(signatureBytes, canonical);
    } else if (secret) {
      // Use secret for HMAC
      digest = hmacSha256(secret, canonical);
    } else {
      // Fall back to SHA256 (less secure)
      digest = sha256(canonical);
    }
    
    const clamped = Math.max(
      CODE_MIN_LENGTH,
      Math.min(CODE_MAX_LENGTH, this.config.codeLength)
    );
    const truncated = truncateBits(digest, 8 * Math.ceil(clamped / 2));
    const code = digestToDigits(truncated, clamped);

    const actionCode: ActionCode = {
      code,
      pubkey,
      timestamp: windowStart,
      expiresAt: windowStart + this.config.ttlMs,
      // Include signature if provided
      ...(signature && { signature }),
      // Only include secret if provided
      ...(secret && { secret }),
    };

    return { actionCode, canonicalMessage: canonical };
  }

  validateCode(actionCode: ActionCode): void {
    const currentTime = Date.now();
    if (currentTime > actionCode.expiresAt + (this.config.clockSkewMs ?? 0)) {
      throw ProtocolError.expiredCode(actionCode.code, actionCode.expiresAt, currentTime);
    }
    
    const canonical = serializeCanonical({
      pubkey: actionCode.pubkey,
      windowStart: actionCode.timestamp,
      secret: actionCode.secret, // Include secret if available
    });
    
    // Use same digest method as generation
    let digest: Uint8Array;
    if (actionCode.signature) {
      // Use signature as the primary entropy source
      const signatureBytes = new TextEncoder().encode(actionCode.signature);
      digest = hmacSha256(signatureBytes, canonical);
    } else if (actionCode.secret) {
      // Use secret for HMAC
      digest = hmacSha256(actionCode.secret, canonical);
    } else {
      // Fall back to SHA256 (less secure)
      digest = sha256(canonical);
    }
    
    const clamped = Math.max(
      CODE_MIN_LENGTH,
      Math.min(CODE_MAX_LENGTH, this.config.codeLength)
    );
    const truncated = truncateBits(digest, 8 * Math.ceil(clamped / 2));
    const expected = digestToDigits(truncated, clamped);
    
    if (expected !== actionCode.code) {
      throw ProtocolError.invalidCode(expected, actionCode.code);
    }
  }
}