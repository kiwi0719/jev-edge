// Request body decoding for Content-Encoding gzip, deflate and br, the JS
// counterpart of adapters/openresty/lib/resty/jev/decode.lua. Express's
// body-parser inflates request bodies by default, so a compressed prompt is
// read by the app; L1 has to read the same text or report it unjudgeable.
//
// gzip / deflate use DecompressionStream (Workers, Node >= 18, Deno, Bun).
// br uses node:zlib when the runtime has it (Node, Lambda@Edge, Next on the
// Node runtime); elsewhere it is reported as unsupported and core calls the
// request unjudgeable. Output is capped at maxOut + 1 bytes: a small
// compressed body cannot expand into unbounded memory.

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
  const all = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return [all, truncated];
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
type NodeZlib = { createBrotliDecompress(): NodeStream };
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

async function one(input: Uint8Array, c: Coding, maxOut: number): Promise<[Uint8Array, boolean]> {
  if (c === "gzip") return viaStream(input, "gzip", maxOut);
  if (c === "deflate") {
    // HTTP "deflate" is zlib-wrapped; some clients send raw deflate
    try {
      return await viaStream(input, "deflate", maxOut);
    } catch {
      return viaStream(input, "deflate-raw", maxOut);
    }
  }
  const z = await nodeZlib();
  if (!z) throw new Error("br decoder not available");
  // streaming, so a brotli bomb stops at maxOut + 1 bytes like the others
  return new Promise((resolve, reject) => {
    const d = z.createBrotliDecompress();
    const chunks: Uint8Array[] = [];
    let size = 0;
    let settled = false;
    const finish = (truncated: boolean) => {
      settled = true;
      const all = new Uint8Array(size);
      let off = 0;
      for (const c of chunks) {
        all.set(c, off);
        off += c.byteLength;
      }
      resolve([all, truncated]);
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
