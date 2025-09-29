import type { CanonicalMessageParts } from "../types";

export const CANONICAL_MESSAGE_VERSION = 1;
export const CANONICAL_MESSAGE_PREFIX = "actioncodes";

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


