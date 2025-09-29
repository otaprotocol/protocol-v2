import { PROTOCOL_META_MAX_BYTES, PROTOCOL_NORMALIZATION } from "../constants";

// v2 protocol meta
export interface ProtocolMetaFields {
  ver: 2;
  id: string; // code id (usually hex/hash)
  int: string; // intent owner who created the code
  p?: Record<string, unknown>; // optional parameters as JSON object
}

export const SCHEME = "actioncodes:";

export function buildProtocolMeta(fields: ProtocolMetaFields): string {
  const norm = normalizeFields(fields);
  if (norm.int != null) guardParamSize(norm.int);
  
  const parts = [
    `ver=${norm.ver}`,
    `id=${encodeURIComponent(norm.id)}`,
    `int=${encodeURIComponent(norm.int)}`,
  ];

  if (norm.p != null && Object.keys(norm.p).length > 0) {
    const paramsJson = JSON.stringify(norm.p);
    guardParamSize(paramsJson);
    parts.push(`p=${encodeURIComponent(paramsJson)}`);
  }
  
  const out = SCHEME + parts.join("&");
  guardSize(out);
  return out;
}

export function parseProtocolMeta(input: string): ProtocolMetaFields {
  if (!input.startsWith(SCHEME)) throw new Error("protocol meta must start with actioncodes:");
  const q = input.slice(SCHEME.length);
  const pairs = q.split("&").filter(Boolean);
  const map = new Map<string, string>();
  for (const pair of pairs) {
    const [k, vRaw] = pair.split("=", 2);
    if (!k) continue;
    const v = vRaw != null ? decodeURIComponent(vRaw) : "";
    map.set(k, v);
  }
  const verStr = map.get("ver");
  const id = map.get("id");
  const int = map.get("int");
  const pStr = map.get("p");
  if (verStr == null || id == null || int == null) throw new Error("protocol meta missing required fields ver or id or int");
  const ver = Number(verStr);
  if (!Number.isInteger(ver) || ver <= 0) throw new Error("protocol meta ver must be positive integer");
  
  let p: Record<string, unknown> | undefined;
  if (pStr != null && pStr !== "") {
    try {
      p = JSON.parse(pStr);
      if (typeof p !== "object" || p === null || Array.isArray(p)) {
        throw new Error("protocol meta p must be a JSON object");
      }
    } catch {
      throw new Error("protocol meta p must be valid JSON");
    }
  }
  
  const norm = normalizeFields({ ver: ver as 2, id, int, p });
  if (norm.int != null) guardParamSize(norm.int);
  if (norm.p != null) guardParamSize(JSON.stringify(norm.p));
  const unknownKeys = [...map.keys()].filter((k) => k !== "ver" && k !== "id" && k !== "int" && k !== "p");
  if (unknownKeys.length > 0) throw new Error("protocol meta contains unsupported keys");
  guardSize(buildProtocolMeta(norm));
  return norm;
}

export function validateProtocolMetaFormat(input: string): { ok: true } | { ok: false; reason: string } {
  try {
    parseProtocolMeta(input);
    return { ok: true };
  } catch (e: unknown) {
    return { ok: false, reason: String(e) };
  }
}

function normalizeFields(fields: ProtocolMetaFields): ProtocolMetaFields {
  const id = fields.id.normalize(PROTOCOL_NORMALIZATION).trim();
  const out: ProtocolMetaFields = { ver: fields.ver, id, int: fields.int };
  if (fields.int != null) out.int = fields.int.normalize(PROTOCOL_NORMALIZATION).trim();
  if (fields.p != null) {
    // For JSON objects, we don't normalize the object itself, just ensure it's valid
    out.p = fields.p;
  }
  return out;
}

function guardSize(s: string): void {
  const bytes = new TextEncoder().encode(s);
  if (bytes.length > PROTOCOL_META_MAX_BYTES) throw new Error(`protocol meta exceeds ${PROTOCOL_META_MAX_BYTES} bytes`);
}

function guardParamSize(value: string): void {
  const bytes = new TextEncoder().encode(value);
  if (bytes.length > PROTOCOL_META_MAX_BYTES) throw new Error(`protocol meta params exceed ${PROTOCOL_META_MAX_BYTES} bytes`);
}


