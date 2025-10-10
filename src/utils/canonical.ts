import type {
  CanonicalMessageParts,
  CanonicalRevokeMessageParts,
  DelegationCertificate,
} from "../types";
import { generateNonce } from "./crypto";

export const CANONICAL_MESSAGE_VERSION = 1;
export const CANONICAL_MESSAGE_PREFIX = "actioncodes";
export const CANONICAL_REVOKE_MESSAGE_PREFIX = "actioncodes-revoke";

export function serializeCanonical(parts: CanonicalMessageParts): Uint8Array {
  const json = JSON.stringify({
    id: CANONICAL_MESSAGE_PREFIX,
    ver: CANONICAL_MESSAGE_VERSION,
    pubkey: parts.pubkey,
    windowStart: parts.windowStart,
    // Include secret if provided for enhanced security
    ...(parts.secret && { secret: parts.secret }),
  });
  return new TextEncoder().encode(json);
}

export function serializeCanonicalRevoke(
  parts: CanonicalRevokeMessageParts
): Uint8Array {
  const json = JSON.stringify({
    id: CANONICAL_REVOKE_MESSAGE_PREFIX,
    ver: CANONICAL_MESSAGE_VERSION,
    pubkey: parts.pubkey,
    codeHash: parts.codeHash,
    windowStart: parts.windowStart,
  });
  return new TextEncoder().encode(json);
}

// Delegation utility functions
export function createDelegationCertificateTemplate(
  userPublicKey: string,
  delegatedPubkey: string,
  durationMs: number = 3600000,
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

export function serializeCertificate(
  cert: Omit<DelegationCertificate, "signature">
): Uint8Array {
  const json = JSON.stringify({
    version: cert.version,
    delegator: cert.delegator,
    delegatedPubkey: cert.delegatedPubkey,
    issuedAt: cert.issuedAt,
    expiresAt: cert.expiresAt,
    nonce: cert.nonce,
    chain: cert.chain,
  });
  return new TextEncoder().encode(json);
}

export function validateCertificateStructure(
  certificate: DelegationCertificate
): boolean {
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

  if (certificate.version !== "1.0") {
    return false;
  }

  if (certificate.issuedAt >= certificate.expiresAt) {
    return false;
  }

  if (certificate.issuedAt > Date.now()) {
    return false;
  }

  if (certificate.expiresAt < Date.now()) {
    return false;
  }

  return true;
}

export function getCanonicalMessageParts(
  pubkey: string,
  ttlMs: number,
  providedSecret?: string
): Uint8Array {
  const windowStart = Math.floor(Date.now() / ttlMs) * ttlMs;
  return serializeCanonical({ pubkey, windowStart, secret: providedSecret });
}
