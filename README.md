## Action Codes Protocol

The Action Codes Protocol is a lightweight way to prove intent and authorize actions across blockchains, apps, and wallets.
Instead of heavy signature popups or complex flows, it uses short-lived one-time codes derived from canonical cryptographic messages.

### This enables:
- Secure intent binding – the code is cryptographically tied to a wallet/public key.
- Fast verification – relayers/servers can validate in microseconds.
- Cross-chain support – adapters handle chain-specific quirks (currently we are supporting Solana)
- Simple dev UX – just generate → sign → verify.

### What's new in v2 (compared to [v1](https://github.com/otaprotocol/actioncodes))
- Now we use Bun as core library. We are down to ~3ms per code signature verification on commodity hardware.
- Canonical Messages only → No ambiguity. Codes are always derived from a canonical serialization (serializeCanonical).
- No AIPs (Action Codes Improvement Proposals) → Overkill for lightweight protocol.
- Chain Adapters simplified → They don't enforce business rules; they just provide utilities:
  - createProtocolMetaIx (for attaching metadata)
  - parseMeta / verifyTransactionMatchesCode (for checking integrity)
  - verifyTransactionSignedByIntentOwner (optional stronger guarantee).
- Errors are typed → Clear ProtocolError.* categories instead of generic fails.
- Performance focus → Benchmarked at ~3.5ms per verification on commodity hardware.

### Core Concepts

1. Action Codes
   - A short-lived, one-time code bound to a wallet/public key.
   - Generated using HMAC/HKDF and canonical serialization.

2. Protocol Meta
   - The "payload" carried with transactions to tie them to action codes.
   - Versioned, deterministic, size-limited. 
   - Perfect for attaching to transactions or off-chain messages for tracing.

3. Canonical Message
   - A deterministic JSON serialization of (pubkey, code, timestamp, optional secret)
   - Always signed by the user's wallet.
   - Prevents replay / tampering.

#### Vision

Action Codes Protocol aim to be the OTP protocol for blockchains but allowing more than authentication: a simple, universal interaction layer usable across apps, chains, and eventually banks/CBDCs.

