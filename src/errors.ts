export enum ProtocolErrorCode {
  // Code validation errors
  EXPIRED_CODE = "EXPIRED_CODE",
  INVALID_CODE = "INVALID_CODE",
  INVALID_CODE_FORMAT = "INVALID_CODE_FORMAT",
  INVALID_SIGNATURE = "INVALID_SIGNATURE",

  // Meta validation errors
  MISSING_META = "MISSING_META",
  INVALID_META_FORMAT = "INVALID_META_FORMAT",
  META_MISMATCH = "META_MISMATCH",
  META_TOO_LARGE = "META_TOO_LARGE",

  // Transaction errors
  TRANSACTION_NOT_SIGNED_BY_INTENDED_OWNER = "TRANSACTION_NOT_SIGNED_BY_INTENDED_OWNER",
  INVALID_TRANSACTION_FORMAT = "INVALID_TRANSACTION_FORMAT",
  INVALID_PUBKEY_FORMAT = "INVALID_PUBKEY_FORMAT",

  // Input validation errors
  INVALID_INPUT = "INVALID_INPUT",
  MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD",

  // Crypto errors
  CRYPTO_ERROR = "CRYPTO_ERROR",
  INVALID_DIGEST = "INVALID_DIGEST",

  // Adapter errors
  INVALID_ADAPTER = "INVALID_ADAPTER",
}

export class ProtocolError extends Error {
  constructor(
    public readonly code: ProtocolErrorCode,
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "ProtocolError";
  }

  // Code validation errors
  static expiredCode(code: string, expiresAt: number, currentTime: number): ExpiredCodeError {
    return new ExpiredCodeError(code, expiresAt, currentTime);
  }

  static invalidCode(): ProtocolError {
    return new ProtocolError(
      ProtocolErrorCode.INVALID_CODE,
      "Invalid code provided",
      {}
    );
  }

  static invalidCodeFormat(code: string, reason: string): InvalidCodeFormatError {
    return new InvalidCodeFormatError(code, reason);
  }

  static invalidSignature(reason: string): InvalidSignatureError {
    return new InvalidSignatureError(reason);
  }

  // Meta validation errors
  static missingMeta(): MissingMetaError {
    return new MissingMetaError();
  }

  static invalidMetaFormat(reason: string): ProtocolError {
    return new ProtocolError(
      ProtocolErrorCode.INVALID_META_FORMAT,
      `Invalid protocol meta format: ${reason}`,
      { reason }
    );
  }

  static metaMismatch(expected: string, actual: string, field: string): MetaMismatchError {
    return new MetaMismatchError(expected, actual, field);
  }

  static metaTooLarge(maxBytes: number, actualBytes: number): ProtocolError {
    return new ProtocolError(
      ProtocolErrorCode.META_TOO_LARGE,
      `Protocol meta too large: ${actualBytes} bytes (max: ${maxBytes})`,
      { maxBytes, actualBytes }
    );
  }

  // Transaction errors
  static transactionNotSignedByIntendedOwner(intended: string, actualSigners: string[]): TransactionNotSignedByIntendedOwnerError {
    return new TransactionNotSignedByIntendedOwnerError(intended, actualSigners);
  }

  static invalidTransactionFormat(reason: string): ProtocolError {
    return new ProtocolError(
      ProtocolErrorCode.INVALID_TRANSACTION_FORMAT,
      `Invalid transaction format: ${reason}`,
      { reason }
    );
  }

  static invalidPubkeyFormat(pubkey: string, reason: string): InvalidPubkeyFormatError {
    return new InvalidPubkeyFormatError(pubkey, reason);
  }

  // Input validation errors
  static invalidInput(field: string, value: unknown, reason: string): ProtocolError {
    return new ProtocolError(
      ProtocolErrorCode.INVALID_INPUT,
      `Invalid ${field}: ${reason}`,
      { field, value, reason }
    );
  }

  static missingRequiredField(field: string): ProtocolError {
    return new ProtocolError(
      ProtocolErrorCode.MISSING_REQUIRED_FIELD,
      `Missing required field: ${field}`,
      { field }
    );
  }

  // Crypto errors
  static cryptoError(operation: string, reason: string): ProtocolError {
    return new ProtocolError(
      ProtocolErrorCode.CRYPTO_ERROR,
      `Crypto error in ${operation}: ${reason}`,
      { operation, reason }
    );
  }

  static invalidDigest(reason: string): ProtocolError {
    return new ProtocolError(
      ProtocolErrorCode.INVALID_DIGEST,
      `Invalid digest: ${reason}`,
      { reason }
    );
  }

  // Adapter errors
  static invalidAdapter(adapter: string): InvalidAdapterError {
    return new InvalidAdapterError(adapter);
  }

  // Generic error creator
  static create(code: ProtocolErrorCode, message: string, details?: Record<string, unknown>): ProtocolError {
    return new ProtocolError(code, message, details);
  }
}

// Specific error classes for instanceof checks
export class ExpiredCodeError extends ProtocolError {
  constructor(code: string, expiresAt: number, currentTime: number) {
    super(
      ProtocolErrorCode.EXPIRED_CODE,
      `Action code '${code}' expired at ${expiresAt}, current time: ${currentTime}`,
      { code, expiresAt, currentTime }
    );
    this.name = "ExpiredCodeError";
  }
}

export class MissingMetaError extends ProtocolError {
  constructor() {
    super(
      ProtocolErrorCode.MISSING_META,
      "Transaction does not contain valid protocol meta"
    );
    this.name = "MissingMetaError";
  }
}

export class MetaMismatchError extends ProtocolError {
  constructor(expected: string, actual: string, field: string) {
    super(
      ProtocolErrorCode.META_MISMATCH,
      `Meta ${field} mismatch: expected '${expected}', got '${actual}'`,
      { expected, actual, field }
    );
    this.name = "MetaMismatchError";
  }
}

export class TransactionNotSignedByIntendedOwnerError extends ProtocolError {
  constructor(intended: string, actualSigners: string[]) {
    super(
      ProtocolErrorCode.TRANSACTION_NOT_SIGNED_BY_INTENDED_OWNER,
      `Transaction not signed by intended owner '${intended}'. Actual signers: [${actualSigners.join(
        ", "
      )}]`,
      { intended, actualSigners }
    );
    this.name = "TransactionNotSignedByIntendedOwnerError";
  }
}

export class InvalidPubkeyFormatError extends ProtocolError {
  constructor(pubkey: string, reason: string) {
    super(
      ProtocolErrorCode.INVALID_PUBKEY_FORMAT,
      `Invalid public key format '${pubkey}': ${reason}`,
      { pubkey, reason }
    );
    this.name = "InvalidPubkeyFormatError";
  }
}

export class InvalidSignatureError extends ProtocolError {
  constructor(reason: string) {
    super(ProtocolErrorCode.INVALID_SIGNATURE, `Invalid signature: ${reason}`, {
      reason,
    });
    this.name = "InvalidSignatureError";
  }
}

export class InvalidCodeFormatError extends ProtocolError {
  constructor(code: string, reason: string) {
    super(
      ProtocolErrorCode.INVALID_CODE_FORMAT,
      `Invalid code format '${code}': ${reason}`,
      { code, reason }
    );
    this.name = "InvalidCodeFormatError";
  }
}

export class InvalidAdapterError extends ProtocolError {
  constructor(adapter: string) {
    super(ProtocolErrorCode.INVALID_ADAPTER, `Invalid adapter: ${adapter}`, { adapter });
    this.name = "InvalidAdapterError";
  }
}