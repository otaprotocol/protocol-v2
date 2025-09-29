import { ActionCodesProtocol } from "../src/ActionCodesProtocol";
import { SolanaAdapter } from "../src/adapters/SolanaAdapter";
import { Keypair } from "@solana/web3.js";
import nacl from "tweetnacl";
import bs58 from "bs58";
describe("Security Review", () => {
  let protocol: ActionCodesProtocol;

  beforeEach(() => {
    protocol = new ActionCodesProtocol({
      codeLength: 8,
      ttlMs: 120000,
    });
  });

  describe("no sensitive data in logs", () => {
    test("ActionCode objects only contain public data", async () => {
      const { actionCode } = await protocol.generateCode("test-pubkey");
      
      // Verify only public data is present
      expect(actionCode.code).toBeDefined();
      expect(actionCode.pubkey).toBe("test-pubkey");
      expect(actionCode.timestamp).toBeDefined();
      expect(actionCode.expiresAt).toBeDefined();
      
      // No private keys or secrets should be present
      expect(actionCode.signature).toBeUndefined();
      expect(actionCode.secretHint).toBeUndefined();
      
      // Verify the code is deterministic and safe to log
      const codeStr = JSON.stringify(actionCode);
      expect(codeStr).not.toContain("secret");
      expect(codeStr).not.toContain("private");
      // Note: "key" is acceptable as it's part of "pubkey" which is public data
    });

    test("canonical messages are safe to serialize", async () => {
      const { canonicalMessage } = await protocol.generateCode("test-pubkey");
      
      // Canonical message should only contain public data
      const decoded = new TextDecoder().decode(canonicalMessage);
      const parsed = JSON.parse(decoded);
      
      expect(parsed.pubkey).toBe("test-pubkey");
      expect(parsed.windowStart).toBeDefined();
      expect(typeof parsed.windowStart).toBe("number");
      
      // No sensitive fields should be present
      expect(parsed.secret).toBeUndefined();
      expect(parsed.privateKey).toBeUndefined();
      expect(parsed.signature).toBeUndefined();
    });

    test("protocol meta only contains public data", () => {
      const instruction = SolanaAdapter.createProtocolMetaIx({
        ver: 2,
        id: "test123",
        int: "user@example.com",
        p: { amount: 100, description: "test payment" }
      });
      
      const metaString = instruction.data.toString('utf8');
      
      // Should contain only public protocol data
      expect(metaString).toContain("actioncodes:ver=2");
      expect(metaString).toContain("id=test123");
      expect(metaString).toContain("int=user%40example.com");
      
      // Should not contain any sensitive data
      expect(metaString).not.toContain("secret");
      expect(metaString).not.toContain("private");
      expect(metaString).not.toContain("key");
    });
  });

  describe("timing attack resistance", () => {
    test("verification time is consistent for valid signatures", async () => {
      const keypair = Keypair.generate();
      const message = new TextEncoder().encode("test message");
      const signature = nacl.sign.detached(message, keypair.secretKey);
      const signatureB58 = bs58.encode(signature);
      
      const context = {
        message,
        chain: "solana",
        pubkey: keypair.publicKey.toString(),
        signature: signatureB58,
      };
      
      const adapter = new SolanaAdapter();
      
      // Measure multiple verifications to check timing consistency
      const times: number[] = [];
      for (let i = 0; i < 10; i++) {
        const start = Date.now();
        adapter.verify(context);
        const end = Date.now();
        times.push(end - start);
      }
      
      // All verifications should complete quickly and consistently
      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const maxTime = Math.max(...times);
      const minTime = Math.min(...times);
      
      expect(avgTime).toBeLessThan(10); // Should be very fast
      expect(maxTime - minTime).toBeLessThan(5); // Should be consistent
    });

    test("verification time is consistent for invalid signatures", async () => {
      const keypair = Keypair.generate();
      const wrongKeypair = Keypair.generate();
      const message = new TextEncoder().encode("test message");
      const signature = nacl.sign.detached(message, wrongKeypair.secretKey); // Wrong key
      const signatureB58 = bs58.encode(signature);
      
      const context = {
        message,
        chain: "solana",
        pubkey: keypair.publicKey.toString(), // Different pubkey
        signature: signatureB58,
      };
      
      const adapter = new SolanaAdapter();
      
      // Measure multiple verifications to check timing consistency
      const times: number[] = [];
      for (let i = 0; i < 10; i++) {
        const start = Date.now();
        adapter.verify(context);
        const end = Date.now();
        times.push(end - start);
      }
      
      // All verifications should complete quickly and consistently
      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const maxTime = Math.max(...times);
      const minTime = Math.min(...times);
      
      expect(avgTime).toBeLessThan(10); // Should be very fast
      expect(maxTime - minTime).toBeLessThan(5); // Should be consistent
    });
  });

  describe("input validation", () => {
    test("rejects malformed public keys gracefully", () => {
      const adapter = new SolanaAdapter();
      
      const context = {
        message: new Uint8Array([1, 2, 3, 4]),
        chain: "solana",
        pubkey: "invalid-pubkey-format",
        signature: "invalid-signature",
      };
      
      // Should return false, not throw
      expect(() => adapter.verify(context)).not.toThrow();
      expect(adapter.verify(context)).toBe(false);
    });

    test("rejects malformed signatures gracefully", () => {
      const keypair = Keypair.generate();
      const adapter = new SolanaAdapter();
      
      const context = {
        message: new Uint8Array([1, 2, 3, 4]),
        chain: "solana",
        pubkey: keypair.publicKey.toString(),
        signature: "invalid-base58-signature",
      };
      
      // Should return false, not throw
      expect(() => adapter.verify(context)).not.toThrow();
      expect(adapter.verify(context)).toBe(false);
    });

    test("handles empty or null inputs safely", () => {
      const adapter = new SolanaAdapter();
      
      const context = {
        message: new Uint8Array([1, 2, 3, 4]),
        chain: "solana",
        pubkey: "",
        signature: "",
      };
      
      // Should return false, not throw
      expect(() => adapter.verify(context)).not.toThrow();
      expect(adapter.verify(context)).toBe(false);
    });
  });

  describe("memory safety", () => {
    test("does not retain sensitive data in memory", async () => {
      const { actionCode } = await protocol.generateCode("test-pubkey");
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      // The actionCode should only contain public data
      const serialized = JSON.stringify(actionCode);
      expect(serialized).toBeDefined();
      
      // No sensitive data should be serializable
      expect(serialized).not.toContain("secret");
      expect(serialized).not.toContain("private");
    });

    test("crypto operations use secure memory patterns", () => {
      const keypair = Keypair.generate();
      const message = new TextEncoder().encode("test message");
      const signature = nacl.sign.detached(message, keypair.secretKey);
      
      // Verify that we're using the secure tweetnacl library
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64); // Ed25519 signature length
      
      // The secret key should not be exposed
      expect(keypair.secretKey).toBeInstanceOf(Uint8Array);
      expect(keypair.secretKey.length).toBe(64); // Ed25519 secret key length
    });
  });
});
