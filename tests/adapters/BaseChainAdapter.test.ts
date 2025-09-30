import {
  BaseChainAdapter,
  ChainDelegationStrategyContext,
  type ChainWalletStrategyContext,
} from "../../src/adapters/BaseChainAdapter";

// Test implementation of BaseChainAdapter
class TestChainAdapter extends BaseChainAdapter<
  { testData: string },
  { testData: string }
> {
  verifyWithWallet(
    context: ChainWalletStrategyContext<{ testData: string }>
  ): boolean {
    // Simple test implementation
    return context.testData === "valid";
  }
  verifyWithDelegation(
    context: ChainDelegationStrategyContext<{ testData: string }>
  ): boolean {
    // Simple test implementation
    return context.testData === "valid";
  }
}

describe("BaseChainAdapter", () => {
  let adapter: TestChainAdapter;

  beforeEach(() => {
    adapter = new TestChainAdapter();
  });

  describe("ChainContext type", () => {
    test("ChainContext includes required fields", () => {
      const context: ChainWalletStrategyContext<{ testData: string }> = {
        canonicalMessageParts: {
          pubkey: "test",
          windowStart: Date.now(),
        },
        chain: "test",
        testData: "valid",
      };

      expect(context.canonicalMessageParts).toHaveProperty('pubkey');
      expect(context.canonicalMessageParts).toHaveProperty('windowStart');
      expect(context.chain).toBe("test");
      expect(context.testData).toBe("valid");
    });

    test("ChainContext works with empty generic type", () => {
      const context: ChainWalletStrategyContext<{}> = {
        canonicalMessageParts: {
          pubkey: "test",
          windowStart: Date.now(),
        },
        chain: "test",
      };

      expect(context.canonicalMessageParts).toHaveProperty('pubkey');
      expect(context.canonicalMessageParts).toHaveProperty('windowStart');
      expect(context.chain).toBe("test");
    });
  });

  describe("verify method", () => {
    test("verify returns true for valid context", async () => {
      const context: ChainWalletStrategyContext<{ testData: string }> = {
        canonicalMessageParts: {
          pubkey: "test",
          windowStart: Date.now(),
        },
        chain: "test",
        testData: "valid",
      };

      const result = adapter.verifyWithWallet(context);
      expect(result).toBe(true);
    });

    test("verify returns false for invalid context", async () => {
      const context: ChainWalletStrategyContext<{ testData: string }> = {
        canonicalMessageParts: {
          pubkey: "test",
          windowStart: Date.now(),
        },
        chain: "test",
        testData: "invalid",
      };

      const result = adapter.verifyWithWallet(context);
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
      const context: ChainWalletStrategyContext<{
        customField: number;
        anotherField: string;
      }> = {
        canonicalMessageParts: {
          pubkey: "test",
          windowStart: Date.now(),
        },
        chain: "test",
        customField: 42,
        anotherField: "test",
      };

      expect(context.canonicalMessageParts).toHaveProperty('pubkey');
      expect(context.canonicalMessageParts).toHaveProperty('windowStart');
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
