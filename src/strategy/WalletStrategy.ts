import type {
  ActionCode,
  CodeGenerationConfig,
  WalletStrategyCodeGenerationResult,
} from "../types";
import {
  hmacSha256,
  truncateBits,
  digestToDigits,
} from "../utils/crypto";
import { CODE_MAX_LENGTH, CODE_MIN_LENGTH } from "../constants";
import {
  serializeCanonical,
  getCanonicalMessageParts,
} from "../utils/canonical";
import { ProtocolError } from "../errors";
import bs58 from "bs58";

export class WalletStrategy {
  constructor(private config: CodeGenerationConfig) {}

  generateCode(
    canonicalMessage: Uint8Array,
    signature: string
  ): WalletStrategyCodeGenerationResult {
    const canonical = canonicalMessage;

    // Parse pubkey and windowStart from canonical message
    const decoded = JSON.parse(new TextDecoder().decode(canonical));
    const pubkey = decoded.pubkey;
    const windowStart = decoded.windowStart;

    // Use signature as the primary entropy source
    // Decode Base58 signature to bytes
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = bs58.decode(signature);
    } catch {
      throw ProtocolError.invalidSignature("Invalid Base58 signature format");
    }
    const digest = hmacSha256(signatureBytes, canonical);

    const clamped = Math.max(
      CODE_MIN_LENGTH,
      Math.min(CODE_MAX_LENGTH, this.config.codeLength)
    );
    const bitsNeeded = 8 * Math.ceil(clamped / 2);
    const truncated = truncateBits(digest, bitsNeeded);
    const code = digestToDigits(truncated, clamped);

    const actionCode: ActionCode = {
      code,
      pubkey,
      timestamp: windowStart,
      expiresAt: windowStart + this.config.ttlMs,
      signature,
    };

    return { actionCode, canonicalMessage: canonical };
  }

  validateCode(actionCode: ActionCode): void {
    const currentTime = Date.now();
    if (currentTime > actionCode.expiresAt + (this.config.clockSkewMs ?? 0)) {
      throw ProtocolError.expiredCode(
        actionCode.code,
        actionCode.expiresAt,
        currentTime
      );
    }

    const canonical = serializeCanonical({
      pubkey: actionCode.pubkey,
      windowStart: actionCode.timestamp,
    });

    // Use same digest method as generation
    if (!actionCode.signature) {
      throw ProtocolError.missingRequiredField("signature");
    }
    
    // Use signature as the primary entropy source
    // Decode Base58 signature to bytes
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = bs58.decode(actionCode.signature);
    } catch {
      throw ProtocolError.invalidSignature("Invalid Base58 signature format");
    }
    const digest = hmacSha256(signatureBytes, canonical);

    const clamped = Math.max(
      CODE_MIN_LENGTH,
      Math.min(CODE_MAX_LENGTH, this.config.codeLength)
    );
    const truncated = truncateBits(digest, 8 * Math.ceil(clamped / 2));
    const expected = digestToDigits(truncated, clamped);

    if (expected !== actionCode.code) {
      throw ProtocolError.invalidCode();
    }
  }

  // Instance method for accessing canonical functions
  getCanonicalMessageParts(pubkey: string): Uint8Array {
    return getCanonicalMessageParts(pubkey);
  }
}
