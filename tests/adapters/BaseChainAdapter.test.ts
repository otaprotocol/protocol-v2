import {
  BaseChainAdapter,
  type ChainContext,
} from "../../src/adapters/BaseChainAdapter";

// Test implementation of BaseChainAdapter
class TestChainAdapter extends BaseChainAdapter<{ testData: string }> {
  verify(context: ChainContext<{ testData: string }>): boolean {
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
      const context: ChainContext<{ testData: string }> = {
        message: new Uint8Array([1, 2, 3, 4]),
        chain: "test",
        testData: "valid",
      };

      expect(context.message).toBeInstanceOf(Uint8Array);
      expect(context.chain).toBe("test");
      expect(context.testData).toBe("valid");
    });

    test("ChainContext works with empty generic type", () => {
      const context: ChainContext<{}> = {
        message: new Uint8Array([1, 2, 3, 4]),
        chain: "test",
      };

      expect(context.message).toBeInstanceOf(Uint8Array);
      expect(context.chain).toBe("test");
    });
  });

  describe("verify method", () => {
    test("verify returns true for valid context", async () => {
      const context: ChainContext<{ testData: string }> = {
        message: new Uint8Array([1, 2, 3, 4]),
        chain: "test",
        testData: "valid",
      };

      const result = adapter.verify(context);
      expect(result).toBe(true);
    });

    test("verify returns false for invalid context", async () => {
      const context: ChainContext<{ testData: string }> = {
        message: new Uint8Array([1, 2, 3, 4]),
        chain: "test",
        testData: "invalid",
      };

      const result = adapter.verify(context);
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
        instance.verify({} as any);
      }).toThrow();
    });

    test("concrete implementations must implement verify", () => {
      // Test that our test implementation properly implements verify
      expect(typeof adapter.verify).toBe("function");
    });
  });

  describe("type safety", () => {
    test("ChainContext generic type works correctly", () => {
      const context: ChainContext<{
        customField: number;
        anotherField: string;
      }> = {
        message: new Uint8Array([1, 2, 3, 4]),
        chain: "test",
        customField: 42,
        anotherField: "test",
      };

      expect(context.message).toBeInstanceOf(Uint8Array);
      expect(context.chain).toBe("test");
      expect(context.customField).toBe(42);
      expect(context.anotherField).toBe("test");
    });

    test("ChainAdapter interface is properly implemented", () => {
      // Test that our adapter implements the ChainAdapter interface
      expect(typeof adapter.verify).toBe("function");
    });
  });
});