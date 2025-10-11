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

export function getCanonicalMessageParts(pubkey: string): Uint8Array {
  return serializeCanonical({ pubkey, windowStart: Date.now() });
}

export function serializeDelegationProof(
  proof: Omit<DelegationProof, "signature">
): Uint8Array {
  const json = JSON.stringify({
    walletPubkey: proof.walletPubkey,
    delegatedPubkey: proof.delegatedPubkey,
    expiresAt: proof.expiresAt,
    chain: proof.chain,
  });
  return new TextEncoder().encode(json);
}
