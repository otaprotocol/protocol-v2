import type {
  CanonicalMessageParts,
  CanonicalRevokeMessageParts,
  DelegationProof,
} from "../types";

export const CANONICAL_MESSAGE_VERSION = 1;
export const CANONICAL_MESSAGE_PREFIX = "actioncodes";
export const CANONICAL_REVOKE_MESSAGE_PREFIX = "actioncodes-revoke";

export function serializeCanonical(parts: CanonicalMessageParts): Uint8Array {
  const json = JSON.stringify({
    id: CANONICAL_MESSAGE_PREFIX,
    ver: CANONICAL_MESSAGE_VERSION,
    pubkey: parts.pubkey,
    windowStart: parts.windowStart,
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

export function getCanonicalMessageParts(
  pubkey: string,
  ttlMs: number
): Uint8Array {
  const windowStart = Math.floor(Date.now() / ttlMs) * ttlMs;
  return serializeCanonical({ pubkey, windowStart });
}

export function serializeDelegationProof(proof: DelegationProof): Uint8Array {
  const json = JSON.stringify({
    walletPubkey: proof.walletPubkey,
    delegatedPubkey: proof.delegatedPubkey,
    expiresAt: proof.expiresAt,
    chain: proof.chain,
  });
  return new TextEncoder().encode(json);
}
