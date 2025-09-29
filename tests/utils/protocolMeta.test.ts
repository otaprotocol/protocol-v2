import {
  buildProtocolMeta,
  parseProtocolMeta,
  validateProtocolMetaFormat,
  SCHEME,
} from "../../src/utils/protocolMeta";
import { PROTOCOL_META_MAX_BYTES } from "../../src/constants";

describe("ProtocolMeta", () => {
  test("builds canonical string with ver,id,int and optional p", () => {
    const s = buildProtocolMeta({
      ver: 2,
      id: "abc123",
      int: "wallet:solana",
      p: { action: "pay-2usdc" },
    });
    expect(s).toBe(`${SCHEME}ver=2&id=abc123&int=wallet%3Asolana&p=%7B%22action%22%3A%22pay-2usdc%22%7D`);
  });

  test("parses canonical string and normalizes", () => {
    const input = `${SCHEME}ver=2&id=%20AbC%20123%20&int=wallet%3Asolana&p=%7B%22action%22%3A%22hello%20world%22%7D`;
    const fields = parseProtocolMeta(input);
    expect(fields.ver).toBe(2);
    expect(fields.id).toBe("AbC 123");
    expect(fields.int).toBe("wallet:solana");
    expect(fields.p).toEqual({ action: "hello world" });
  });

  test("rejects unknown keys", () => {
    const bad = `${SCHEME}ver=1&id=abc&int=x&x=1`;
    expect(() => parseProtocolMeta(bad)).toThrow(/unsupported keys/);
  });

  test("requires ver,id,int", () => {
    expect(() => parseProtocolMeta(`${SCHEME}ver=1&int=x`)).toThrow(
      /missing required/
    );
    expect(() => parseProtocolMeta(`${SCHEME}id=abc&int=x`)).toThrow(
      /missing required/
    );
    expect(() => parseProtocolMeta(`${SCHEME}ver=1&id=abc`)).toThrow(
      /missing required/
    );
  });

  test("enforces overall byte limit", () => {
    const big = "x".repeat(PROTOCOL_META_MAX_BYTES + 10);
    expect(() => buildProtocolMeta({ ver: 2, id: big, int: "x" })).toThrow(
      /exceeds/
    );
  });

  test("enforces params byte limit", () => {
    const p = "y".repeat(PROTOCOL_META_MAX_BYTES + 1);
    expect(() => buildProtocolMeta({ ver: 2, id: "a", int: "x", p: { action: p } })).toThrow(
      /params exceed/
    );
  });

  test("validateProtocolMetaFormat ok/fail", () => {
    const ok = `${SCHEME}ver=2&id=abc&int=me`;
    expect(validateProtocolMetaFormat(ok)).toEqual({ ok: true });
    const bad = `wrong:id=abc`;
    const res = validateProtocolMetaFormat(bad);
    expect(res.ok).toBe(false);
  });
});
