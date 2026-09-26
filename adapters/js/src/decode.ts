// Request body decoding for Content-Encoding gzip, deflate and br, the JS
// counterpart of adapters/openresty/lib/resty/jev/decode.lua. Express's
// body-parser inflates request bodies by default, so a compressed prompt is
// read by the app; L1 has to read the same text or report it unjudgeable.
//
// gzip uses node:zlib where the runtime has it (Node, Lambda@Edge, Next on
// the Node runtime, Deno, Bun, Workers with nodejs_compat), DecompressionStream
// member by member elsewhere; deflate uses DecompressionStream (Workers,
// Node >= 18, Deno, Bun), and node:zlib where DecompressionStream does not
// work. br uses node:zlib. A coding with no working decoder (br without
// node:zlib; gzip and deflate on Next's edge runtime, whose
// DecompressionStream is a stub that throws) is reported as "<coding> decoder
// not available", and core calls the request unjudgeable. Output is capped at
// maxOut + 1 bytes: a small compressed body cannot expand into unbounded
// memory.

type Coding = "gzip" | "deflate" | "br";

const MAX_CODINGS = 3;

function codings(header: string): Coding[] | string {
  const out: Coding[] = [];
  for (const raw of header.toLowerCase().split(",")) {
    const t = raw.trim();
    if (t === "" || t === "identity") continue;
    if (t === "gzip" || t === "x-gzip") out.push("gzip");
    else if (t === "deflate") out.push("deflate");
    else if (t === "br") out.push("br");
    else return "unsupported encoding: " + t;
  }
  if (out.length > MAX_CODINGS) return "too many encodings";
  return out;
}

async function drain(stream: ReadableStream<Uint8Array>, maxOut: number): Promise<[Uint8Array, boolean]> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const room = maxOut + 1 - size;
      if (value.byteLength >= room) {
        chunks.push(value.subarray(0, room));
        size += room;
        truncated = true;
        reader.cancel().catch(() => {});
        break;
      }
      chunks.push(value);
      size += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  return [concat(chunks, size), truncated];
}

async function viaStream(input: Uint8Array, format: "gzip" | "deflate" | "deflate-raw", maxOut: number): Promise<[Uint8Array, boolean]> {
  const ds = new DecompressionStream(format);
  const writer = ds.writable.getWriter();
  // write and close without awaiting: the readable side applies backpressure
  writer.write(input as unknown as BufferSource).catch(() => {});
  writer.close().catch(() => {});
  return drain(ds.readable as ReadableStream<Uint8Array>, maxOut);
}

interface NodeStream {
  on(ev: "data", cb: (c: Uint8Array) => void): unknown;
  on(ev: "end", cb: () => void): unknown;
  on(ev: "error", cb: (e: unknown) => void): unknown;
  end(b: Uint8Array): unknown;
  destroy(): unknown;
}
type NodeZlib = {
  createBrotliDecompress(): NodeStream;
  createGunzip(): NodeStream;
  createInflate?(): NodeStream;
  createInflateRaw?(): NodeStream;
};
let zlib: NodeZlib | null | undefined;
async function nodeZlib(): Promise<NodeZlib | null> {
  if (zlib !== undefined) return zlib;
  try {
    const name = "node:zlib"; // kept out of static analysis so Worker bundles do not try to resolve it
    zlib = (await import(/* @vite-ignore */ name)) as NodeZlib;
  } catch {
    zlib = null;
  }
  return zlib;
}

function concat(chunks: Uint8Array[], size: number): Uint8Array {
  const all = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return all;
}

/** `input` through a node:zlib decompressor, streaming, so a bomb stops at maxOut + 1 bytes like the others. */
function viaNode(d: NodeStream, input: Uint8Array, maxOut: number): Promise<[Uint8Array, boolean]> {
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let size = 0;
    let settled = false;
    const finish = (truncated: boolean) => {
      settled = true;
      resolve([concat(chunks, size), truncated]);
    };
    d.on("data", (c) => {
      if (settled) return;
      const room = maxOut + 1 - size;
      if (c.byteLength >= room) {
        chunks.push(c.subarray(0, room));
        size += room;
        d.destroy();
        finish(true);
        return;
      }
      chunks.push(c);
      size += c.byteLength;
    });
    d.on("end", () => {
      if (!settled) finish(false);
    });
    d.on("error", (e) => {
      if (!settled) {
        settled = true;
        reject(e);
      }
    });
    d.end(input);
  });
}

// "jev", gzip and zlib-wrapped, to tell a body DecompressionStream cannot
// decode from a DecompressionStream that decodes nothing.
const PROBES: Record<"gzip" | "deflate", number[]> = {
  gzip: [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x13, 0xcb, 0x4a, 0x2d, 0x03, 0x00, 0x0f, 0xdc, 0xed, 0x1b, 0x03, 0x00, 0x00, 0x00],
  deflate: [0x78, 0xda, 0xcb, 0x4a, 0x2d, 0x03, 0x00, 0x02, 0x81, 0x01, 0x46],
};

/**
 * Does this runtime's DecompressionStream decode `format` at all? Asked only
 * after it refused a body: a missing one, or a stub that throws (Next's edge
 * runtime replaces it with one), refuses every body, and the body is then
 * not corrupt, the decoder is not there.
 */
async function streamDecodes(format: "gzip" | "deflate"): Promise<boolean> {
  try {
    const [out] = await viaStream(new Uint8Array(PROBES[format]), format, 16);
    return new TextDecoder().decode(out) === "jev";
  } catch {
    return false;
  }
}

/** Decodes, members walked and header checks included, before a gzip body is called corrupt. */
const MAX_GZIP_TRIES = 64;

/**
 * Concatenated gzip members (RFC 1952) through DecompressionStream, which
 * decodes the first and rejects the rest as trailing junk. A rejected input
 * that is a complete member followed by more is split where that member
 * ends: the first offset that starts a gzip header (1f 8b 08, reserved flag
 * bits clear) at which the prefix decodes whole. A deflate stream ends at one
 * place and its CRC and size follow it, so only the true end does. The
 * members share one maxOut + 1 budget. After MAX_GZIP_TRIES decodes, or when
 * no offset works (trailing bytes that are not a member), the body is
 * corrupt, as in decode.lua.
 */
export async function gunzipMembers(input: Uint8Array, maxOut: number): Promise<[Uint8Array, boolean]> {
  const parts: Uint8Array[] = [];
  let size = 0;
  let tries = 0;
  const attempt = async (bytes: Uint8Array): Promise<[Uint8Array, boolean] | null> => {
    if (++tries > MAX_GZIP_TRIES) throw new Error("corrupt gzip body: too many members");
    try {
      return await viaStream(bytes, "gzip", maxOut - size);
    } catch {
      return null;
    }
  };
  const take = ([out, cut]: [Uint8Array, boolean]): boolean => {
    parts.push(out);
    size += out.byteLength;
    return cut || size > maxOut;
  };
  let off = 0;
  while (off < input.byteLength) {
    const rest = input.subarray(off);
    const whole = await attempt(rest);
    if (whole) {
      const cut = take(whole);
      return [concat(parts, size), cut];
    }
    if (off === 0 && !(await streamDecodes("gzip"))) throw new Error("gzip decoder not available");
    let next = -1;
    for (let p = 18; p + 3 < rest.byteLength; p++) {
      if (rest[p] !== 0x1f || rest[p + 1] !== 0x8b || rest[p + 2] !== 0x08 || (rest[p + 3] & 0xe0) !== 0) continue;
      const got = await attempt(rest.subarray(0, p));
      if (!got) continue;
      if (take(got)) return [concat(parts, size), true];
      next = p;
      break;
    }
    if (next < 0) throw new Error("corrupt gzip body");
    off += next;
  }
  return [concat(parts, size), false];
}

/**
 * gzip, every member of it: node:zlib's gunzip goes on across concatenated
 * members as gunzip(1), body-parser and decode.lua do (it also takes zero
 * padding after the last one, as body-parser does; decode.lua does not).
 */
async function gunzip(input: Uint8Array, maxOut: number): Promise<[Uint8Array, boolean]> {
  const z = await nodeZlib();
  let d: NodeStream | undefined;
  try {
    d = typeof z?.createGunzip === "function" ? z.createGunzip() : undefined;
  } catch {
    d = undefined; // a node:zlib without streams: the member walk below
  }
  return d ? viaNode(d, input, maxOut) : gunzipMembers(input, maxOut);
}

async function one(input: Uint8Array, c: Coding, maxOut: number): Promise<[Uint8Array, boolean]> {
  if (c === "gzip") return gunzip(input, maxOut);
  if (c === "deflate") {
    // HTTP "deflate" is zlib-wrapped; some clients send raw deflate
    try {
      return await viaStream(input, "deflate", maxOut);
    } catch {
      /* raw deflate, below */
    }
    try {
      return await viaStream(input, "deflate-raw", maxOut);
    } catch (e) {
      if (await streamDecodes("deflate")) throw e;
    }
    // no working DecompressionStream: node:zlib where there is one
    const z = await nodeZlib();
    if (typeof z?.createInflate !== "function" || typeof z.createInflateRaw !== "function") {
      throw new Error("deflate decoder not available");
    }
    try {
      return await viaNode(z.createInflate(), input, maxOut);
    } catch {
      return viaNode(z.createInflateRaw(), input, maxOut);
    }
  }
  const z = await nodeZlib();
  if (!z) throw new Error("br decoder not available");
  return viaNode(z.createBrotliDecompress(), input, maxOut);
}

/**
 * Decode `raw` per the Content-Encoding header value, codings applied in
 * reverse order of listing. Returns [bytes, truncated] (bytes is at most
 * maxOut + 1 long; truncated means the decoded body is longer), or
 * [null, error] when a coding is unsupported or the data is corrupt.
 */
export async function decodeBody(raw: Uint8Array, header: string, maxOut: number): Promise<[Uint8Array, boolean] | [null, string]> {
  const cs = codings(header);
  if (typeof cs === "string") return [null, cs];
  let cur = raw;
  let truncated = false;
  for (let i = cs.length - 1; i >= 0; i--) {
    if (cur.byteLength === 0) break;
    try {
      const [out, cut] = await one(cur, cs[i], maxOut);
      cur = out;
      truncated = truncated || cut;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return [null, msg.includes("not available") ? msg : "corrupt " + cs[i] + " body"];
    }
  }
  return [cur, truncated];
}
