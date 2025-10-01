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

## Strategy Architecture

The Action Codes Protocol supports two main strategies for generating and validating codes:

### 1. Wallet Strategy (Direct)

The **Wallet Strategy** is the simplest approach where codes are generated directly from a user's wallet.

#### How it works:
```typescript
// 1. Get canonical message for signing
const canonicalMessage = protocol.getCanonicalMessageParts("user-wallet-address");

// 2. Sign the canonical message with user's wallet
const signature = await userWallet.signMessage(canonicalMessage);

// 3. Generate code with the signed canonical message (secret is optional)
const result = await protocol.generateCode("wallet", canonicalMessage, signature);
// Optional: provide secret for enhanced security
// const result = await protocol.generateCode("wallet", canonicalMessage, signature, "optional-secret");

// 4. Validate code
const isValid = await protocol.validateCode("wallet", result.actionCode, {
  chain: "solana",
  pubkey: "user-wallet-address",
  signature: signature
});
```

#### Key Features:
- **Signature-based security** - Codes require a valid signature over the canonical message (prevents public key + timestamp attacks)
- **Direct wallet binding** - Codes are cryptographically tied to the user's public key
- **Optional secrets** - Users can provide a secret for enhanced security (uses HMAC), or omit it (uses SHA256)
- **Immediate validation** - No delegation certificates needed
- **Perfect for** - Direct user interactions, simple authentication flows

#### Security Model:
- **Signature verification** - All codes require a valid signature over the canonical message
- **Public key + timestamp attack prevention** - Signatures prevent attackers from generating codes with just public key + timestamp
- Codes are bound to the specific public key
- Optional secret provides additional entropy (HMAC vs SHA256)
- Time-based expiration prevents replay attacks
- Canonical message signing ensures integrity

### 2. Delegation Strategy (Advanced)

The **Delegation Strategy** allows users to pre-authorize actions through delegation certificates, enabling more complex workflows like relayer services.

#### How it works:

##### Step 1: Create Delegation Certificate
```typescript
// User creates a delegation certificate template
const template = await protocol.createDelegationCertificateTemplate(
  userPublicKey,
  3600000, // 1 hour expiration
  "solana"
);

// User signs the certificate
const message = DelegationStrategy.serializeCertificate(template);
const signature = await userWallet.signMessage(message);

const certificate: DelegationCertificate = {
  ...template,
  signature: signature
};
```

##### Step 2: Generate Delegated Codes
```typescript
// Generate codes using the delegation certificate
const result = await protocol.generateCode("delegation", certificate);
const actionCode = result.actionCode;
```

##### Step 3: Validate Delegated Codes
```typescript
// Validate the delegated code with the certificate
const isValid = await protocol.validateCode(actionCode, "delegation", certificate);
```

#### Key Features:
- **Pre-authorization** - Users can authorize actions for a limited time
- **Relayer support** - Third parties can validate codes without generating them
- **Certificate-based** - Codes are bound to specific delegation certificates
- **Time-limited** - Certificates have expiration times
- **Perfect for** - Relayer services, automated systems, complex workflows

#### Security Model:
- **Code-Certificate Binding** - Codes are cryptographically bound to their specific certificate
- **Signature Verification** - Certificate signatures are verified using chain adapters
- **Delegation ID** - Each certificate has a unique ID derived from its content + signature
- **Cross-Certificate Protection** - Codes from one certificate cannot be used with another
- **Relayer Security** - Relayers can validate codes but cannot generate them without the user's signature

#### Important Security Guarantees:

1. **Stolen Delegation IDs are Useless**
   - Delegation IDs are public identifiers (like transaction hashes)
   - They cannot be used to generate or validate codes
   - They're safe to share publicly

2. **Stolen Signatures Cannot Create Valid Codes**
   - Even if an attacker steals a signature, they cannot create valid codes
   - Codes are bound to the ENTIRE certificate (not just the signature)
   - Different certificate data = different code = validation failure

3. **Relayer Code Generation Prevention**
   - Relayers cannot generate codes even with public certificate data
   - Certificate hashes include the signature (private user asset)
   - Only the original user can generate valid codes

4. **Code-Certificate Binding**
   - Codes are cryptographically linked to their specific certificate
   - Cross-certificate attacks are impossible
   - Each certificate produces unique codes

#### Delegation Certificate Structure:
```typescript
interface DelegationCertificate {
  version: "1.0";
  delegator: string;        // User's public key
  issuedAt: number;         // Timestamp when issued
  expiresAt: number;        // Expiration timestamp
  nonce: string;           // Unique nonce for this certificate
  chain: string;           // Target blockchain
  signature: string;       // User's signature of the certificate
}
```

#### Delegated Action Code Structure:
```typescript
interface DelegatedActionCode {
  code: string;            // The actual action code
  pubkey: string;          // User's public key
  timestamp: number;       // Generation timestamp
  expiresAt: number;       // Code expiration
  delegationId: string;    // Hash of the certificate (used internally as secret)
  delegatedBy: string;     // Who delegated (same as pubkey)
  // Note: secret field is inherited from ActionCode but not used in delegation
}
```

## Use Cases & Examples

### Wallet Strategy Use Cases

#### 1. Simple Authentication
```typescript
// User logs into a dApp
const canonicalMessage = protocol.getCanonicalMessageParts(userWallet.publicKey);
const signature = await userWallet.signMessage(canonicalMessage);
const result = await protocol.generateCode("wallet", canonicalMessage, signature);

// dApp validates the code
const isValid = await protocol.validateCode('wallet', result.actionCode, {
  chain: "solana",
  pubkey: userWallet.publicKey,
  signature: signature
});
```

#### 2. Transaction Authorization
```typescript
// User authorizes a specific transaction
const canonicalMessage = protocol.getCanonicalMessageParts(userWallet.publicKey);
const signature = await userWallet.signMessage(canonicalMessage);
const result = await protocol.generateCode("wallet", canonicalMessage, signature);
// Optional: add secret for enhanced security
// const result = await protocol.generateCode("wallet", canonicalMessage, signature, `tx-${transactionHash}`);

// Relayer validates before executing
const isValid = await protocol.validateCode('wallet', result.actionCode, {
  chain: "solana",
  pubkey: userWallet.publicKey,
  signature: signature
});
```

### Delegation Strategy Use Cases

#### 1. Relayer Services
```typescript
// User pre-authorizes a relayer for 1 hour
const certificate = await createDelegationCertificate(userWallet, 3600000);

// Relayer can validate codes but not generate them
const relayer = new RelayerService();
relayer.registerCertificate(certificate);

// User generates codes that relayer can validate
const actionCode = await protocol.generateCode("delegation", certificate);
const isValid = relayer.validateCode(actionCode, certificate);
```

#### 2. Automated Trading Bots
```typescript
// User authorizes trading bot for specific operations
const tradingCertificate = await createDelegationCertificate(userWallet, 86400000); // 24 hours

// Bot can execute trades using delegated codes
const tradeCode = await protocol.generateCode("delegation", tradingCertificate);
// Bot executes trade with this code
```

#### 3. Multi-Signature Workflows
```typescript
// Multiple users can delegate to a shared certificate
const sharedCertificate = await createSharedDelegationCertificate([
  user1Wallet,
  user2Wallet,
  user3Wallet
]);

// Any authorized user can generate codes
const actionCode = await protocol.generateCode("delegation", sharedCertificate);
```

## Security Considerations

### What Makes Action Codes Secure?

1. **Cryptographic Binding**
   - Codes are mathematically tied to specific public keys
   - Impossible to forge without the private key

2. **Time-Limited Validity**
   - Codes expire automatically
   - Prevents replay attacks

3. **One-Time Use**
   - Each code is unique and time-bound
   - Cannot be reused

4. **Delegation Security**
   - Delegation certificates are cryptographically signed
   - Codes are bound to specific certificates
   - Cross-certificate attacks are impossible

### Best Practices

1. **Secret Management**
   - Use cryptographically secure random secrets
   - Don't reuse secrets across different contexts
   - Consider using deterministic secrets based on context

2. **Certificate Expiration**
   - Set appropriate expiration times for delegation certificates
   - Shorter expiration = higher security
   - Longer expiration = better UX

3. **Relayer Security**
   - Only trust relayers with full certificates
   - Never share private keys with relayers
   - Monitor relayer behavior

4. **Code Validation**
   - Always validate codes server-side
   - Check expiration times
   - Verify the binding to the correct public key

## Performance

- **Code Generation**: ~1ms per code
- **Code Validation**: ~3ms per validation
- **Memory Usage**: Minimal (no state storage required)
- **Network**: No network calls required for validation

## Getting Started

```bash
# Install
npm install @actioncodes/protocol

# Basic usage
import { ActionCodesProtocol } from '@actioncodes/protocol';

const protocol = new ActionCodesProtocol();

// 1. Get canonical message for signing
const canonicalMessage = protocol.getCanonicalMessageParts("your-public-key");

// 2. Sign the canonical message with your wallet
const signature = await yourWallet.signMessage(canonicalMessage);

// 3. Generate a code with the signed canonical message
const result = await protocol.generateCode("wallet", canonicalMessage, signature);
// Optional: add secret for enhanced security
// const result = await protocol.generateCode("wallet", canonicalMessage, signature, "optional-secret");

// 4. Validate a code
const isValid = await protocol.validateCode("wallet", result.actionCode, {
  chain: "solana",
  pubkey: "your-public-key",
  signature: signature
});
```

#### Vision

Action Codes Protocol aim to be the OTP protocol for blockchains but allowing more than authentication: a simple, universal interaction layer usable across apps, chains, and eventually banks/CBDCs.

