import {
  BaseChainAdapter,
  type WalletContext,
  type DelegatedContext,
  type WalletRevokeContext,
  type DelegatedRevokeContext,
} from "../../src/adapters/BaseChainAdapter";

// Test implementation of BaseChainAdapter
class TestChainAdapter extends BaseChainAdapter<
  { testData: string },
  { testData: string },
  { testData: string },
  { testData: string }
> {
  verifyWithWallet(context: WalletContext<{ testData: string }>): boolean {
    // Simple test implementation
    return context.testData === "valid";
  }
  verifyWithDelegation(
    context: DelegatedContext<{ testData: string }>
  ): boolean {
    // Simple test implementation
    return context.testData === "valid";
  }
  verifyRevokeWithWallet(
    context: WalletRevokeContext<{ testData: string }>
  ): boolean {
    // Simple test implementation
    return context.testData === "valid";
  }
  verifyRevokeWithDelegation(
    context: DelegatedRevokeContext<{ testData: string }>
  ): boolean {
    // Simple test implementation
    return context.testData === "valid";
  }
}

describe("BaseChainAdapter", () => {
  let adapter: TestChainAdapter;

  beforeEach(() => {
    adapter = new TestChainAdapter() as TestChainAdapter;
  });

  describe("ChainContext type", () => {
    test("ChainContext includes required fields", () => {
      const context: WalletContext<{ testData: string }> = {
        chain: "test",
        testData: "valid",
        message: {
          pubkey: "test",
          windowStart: Date.now(),
        },
        walletSignature: "SIG_PLACEHOLDER",
      };

      expect(context.message).toHaveProperty("pubkey");
      expect(context.message).toHaveProperty("windowStart");
      expect(context.chain).toBe("test");
      expect(context.testData).toBe("valid");
    });

    test("ChainContext works with empty generic type", () => {
      const context: WalletContext<{}> = {
        chain: "test",
        message: {
          pubkey: "test",
          windowStart: Date.now(),
        },
        walletSignature: "SIG_PLACEHOLDER",
      };

      expect(context.message).toHaveProperty("pubkey");
      expect(context.message).toHaveProperty("windowStart");
      expect(context.chain).toBe("test");
    });
  });

  describe("verify method", () => {
    test("verifyWithWallet returns true for valid context", async () => {
      const context: WalletContext<{ testData: string }> = {
        chain: "test",
        testData: "valid",
        message: {
          pubkey: "test",
          windowStart: Date.now(),
        },
        walletSignature: "SIG_PLACEHOLDER",
      };

      const result = adapter.verifyWithWallet(context);
      expect(result).toBe(true);
    });

    test("verifyWithWallet returns false for invalid context", async () => {
      const context: WalletContext<{ testData: string }> = {
        chain: "test",
        testData: "invalid",
        message: {
          pubkey: "test",
          windowStart: Date.now(),
        },
        walletSignature: "SIG_PLACEHOLDER",
      };

      const result = adapter.verifyWithWallet(context);
      expect(result).toBe(false);
    });

    test("verifyRevokeWithWallet returns true for valid context", async () => {
      const context: WalletRevokeContext<{ testData: string }> = {
        chain: "test",
        testData: "valid",
        message: {
          pubkey: "test",
          codeHash: "test-hash",
          windowStart: Date.now(),
        },
        walletSignature: "SIG_PLACEHOLDER",
      };

      const result = adapter.verifyRevokeWithWallet(context);
      expect(result).toBe(true);
    });

    test("verifyRevokeWithWallet returns false for invalid context", async () => {
      const context: WalletRevokeContext<{ testData: string }> = {
        chain: "test",
        testData: "invalid",
        message: {
          pubkey: "test",
          codeHash: "test-hash",
          windowStart: Date.now(),
        },
        walletSignature: "SIG_PLACEHOLDER",
      };

      const result = adapter.verifyRevokeWithWallet(context);
      expect(result).toBe(false);
    });
  });

  describe("abstract methods", () => {
    test("BaseChainAdapter is abstract and cannot be instantiated directly", () => {
      // This test verifies that BaseChainAdapter is abstract
      // In TypeScript, this would be caught at compile time
      // At runtime, we need to check if it throws when calling abstract methods
      expect(() => {
        // @ts-expect-error - BaseChainAdapter is abstract
        const instance = new BaseChainAdapter();
        // Try to call the abstract method - this should throw
        instance.verifyWithWallet({} as any);
      }).toThrow();
    });

    test("concrete implementations must implement verify", () => {
      // Test that our test implementation properly implements verify
      expect(typeof adapter.verifyWithWallet).toBe("function");
    });
  });

  describe("type safety", () => {
    test("ChainContext generic type works correctly", () => {
      const context: WalletContext<{
        customField: number;
        anotherField: string;
      }> = {
        chain: "test",
        customField: 42,
        anotherField: "test",
        message: {
          pubkey: "test",
          windowStart: Date.now(),
        },
        walletSignature: "SIG_PLACEHOLDER",
      };

      expect(context.message).toHaveProperty("pubkey");
      expect(context.message).toHaveProperty("windowStart");
      expect(context.chain).toBe("test");
      expect(context.customField).toBe(42);
      expect(context.anotherField).toBe("test");
    });

    test("ChainAdapter interface is properly implemented", () => {
      // Test that our adapter implements the ChainAdapter interface
      expect(typeof adapter.verifyWithWallet).toBe("function");
      expect(typeof adapter.verifyWithDelegation).toBe("function");
    });
  });
});
