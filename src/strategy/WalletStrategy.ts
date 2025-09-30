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
    pubkey: string,
    providedSecret?: string,
  ): WalletStrategyCodeGenerationResult {
    const windowStart = alignToWindow(Date.now(), this.config.ttlMs);
    
    // Only use secret if explicitly provided
    const secret = providedSecret;
    
    const canonical = serializeCanonical({ pubkey, windowStart, secret });
    
    // Use HMAC for better security when secret is available
    const digest = secret ? 
      hmacSha256(secret, canonical) : 
      sha256(canonical);
    
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
    const digest = actionCode.secret ? 
      hmacSha256(actionCode.secret, canonical) : 
      sha256(canonical);
    
    const clamped = Math.max(
      CODE_MIN_LENGTH,
      Math.min(CODE_MAX_LENGTH, this.config.codeLength)
    );
    const truncated = truncateBits(digest, 8 * Math.ceil(clamped / 2));
    const expected = digestToDigits(truncated, clamped);
    
    if (expected !== actionCode.code) {
      throw ProtocolError.invalidCodeFormat(actionCode.code, "Code does not match expected value");
    }
  }
}

function alignToWindow(now: number, ttlMs: number): number {
  return Math.floor(now / ttlMs) * ttlMs;
}
