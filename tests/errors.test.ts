import { 
  ProtocolError, 
  ExpiredCodeError, 
  MissingMetaError, 
  MetaMismatchError, 
  TransactionNotSignedByIntendedOwnerError, 
  InvalidPubkeyFormatError 
} from "../src/errors";

describe("Error System", () => {
  test("errors are catchable with instanceof", () => {
    try {
      throw ProtocolError.expiredCode("test123", 1000, 2000);
    } catch (error) {
      expect(error instanceof ExpiredCodeError).toBe(true);
      expect(error instanceof ProtocolError).toBe(true);
      expect(( error as ProtocolError ).code).toBe("EXPIRED_CODE");
    }
  });

  test("missing meta error", () => {
    try {
      throw ProtocolError.missingMeta();
    } catch (error) {
      expect(error instanceof MissingMetaError).toBe(true);
      expect(error instanceof ProtocolError).toBe(true);
    }
  });

  test("meta mismatch error", () => {
    try {
      throw ProtocolError.metaMismatch("expected", "actual", "field");
    } catch (error) {
      expect(error instanceof MetaMismatchError).toBe(true);
      expect(error instanceof ProtocolError).toBe(true);
      expect(( error as ProtocolError ).details?.expected).toBe("expected");
      expect(( error as ProtocolError ).details?.actual).toBe("actual");
      expect(( error as ProtocolError ).details?.field).toBe("field");
    }
  });

  test("transaction not signed by intended owner error", () => {
    try {
      throw ProtocolError.transactionNotSignedByIntendedOwner("intended123", ["signer1", "signer2"]);
    } catch (error) {
      expect(error instanceof TransactionNotSignedByIntendedOwnerError).toBe(true);
      expect(error instanceof ProtocolError).toBe(true);
      expect(( error as ProtocolError ).details?.intended).toBe("intended123");
      expect(( error as ProtocolError ).details?.actualSigners).toEqual(["signer1", "signer2"]);
    }
  });

  test("invalid pubkey format error", () => {
    try {
      throw ProtocolError.invalidPubkeyFormat("invalid-pubkey", "Invalid format");
    } catch (error) {
      expect(error instanceof InvalidPubkeyFormatError).toBe(true);
      expect(error instanceof ProtocolError).toBe(true);
      expect(( error as ProtocolError ).details?.pubkey).toBe("invalid-pubkey");
      expect(( error as ProtocolError ).details?.reason).toBe("Invalid format");
    }
  });

  test("error handling with specific types", () => {
    const errors = [
      () => ProtocolError.expiredCode("code1", 1000, 2000),
      () => ProtocolError.missingMeta(),
      () => ProtocolError.metaMismatch("exp", "act", "field"),
      () => ProtocolError.transactionNotSignedByIntendedOwner("int", ["sig1"]),
      () => ProtocolError.invalidPubkeyFormat("bad", "reason"),
    ];

    errors.forEach((errorFn, index) => {
      try {
        errorFn();
      } catch (error) {
        expect(error instanceof ProtocolError).toBe(true);
        
        // Test specific instanceof checks
        if (index === 0) expect(error instanceof ExpiredCodeError).toBe(true);
        if (index === 1) expect(error instanceof MissingMetaError).toBe(true);
        if (index === 2) expect(error instanceof MetaMismatchError).toBe(true);
        if (index === 3) expect(error instanceof TransactionNotSignedByIntendedOwnerError).toBe(true);
        if (index === 4) expect(error instanceof InvalidPubkeyFormatError).toBe(true);
      }
    });
  });
});
