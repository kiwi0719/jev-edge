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
// memory. In tail mode the last coding reads on to a scan bound and keeps
// only a ring of the last bytes past the cap, so memory stays bounded by
// cap + tail.

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

/** What decodeBody's tail mode hands back beside the head (decode.lua's info). */
export interface DecodeInfo {
  /** the last `tail` bytes after the first maxOut, or null when there are none */
  tail: Uint8Array | null;
  /** bytes the last coding produced */
  size: number;
  /** false when the scan bound came before the stream's end: `tail` is not the end */
  complete: boolean;
}

/**
 * Where a coding's output goes (decode.lua's Sink). The first `limit` bytes
 * are kept whole (the head). With `tail`, every byte past the first
 * `limit - 1` also goes through a ring that keeps the last `tail` of them,
 * and the coding stops once it has produced more than `scan` bytes instead
 * of at the head's end.
 */
class Sink {
  private head: Uint8Array[] = [];
  private headLen = 0;
  private ring: Uint8Array = new Uint8Array(0);
  total = 0;
  constructor(
    private readonly limit: number,
    private readonly tail?: number,
    private readonly scan?: number,
  ) {}

  push(c: Uint8Array): void {
    const cap = this.tail !== undefined ? (this.scan as number) + 1 : this.limit;
    const v = c.byteLength > cap - this.total ? c.subarray(0, Math.max(0, cap - this.total)) : c;
    if (this.headLen < this.limit) {
      const take = Math.min(this.limit - this.headLen, v.byteLength);
      this.head.push(v.subarray(0, take));
      this.headLen += take;
    }
    if (this.tail !== undefined) {
      const skip = this.limit - 1 - this.total;
      if (skip < v.byteLength) {
        const piece = skip > 0 ? v.subarray(skip) : v;
        const joined = new Uint8Array(Math.min(this.tail, this.ring.byteLength + piece.byteLength));
        const fromPiece = Math.min(piece.byteLength, joined.byteLength);
        const fromRing = joined.byteLength - fromPiece;
        joined.set(this.ring.subarray(this.ring.byteLength - fromRing), 0);
        joined.set(piece.subarray(piece.byteLength - fromPiece), fromRing);
        this.ring = joined;
      }
    }
    this.total += v.byteLength;
  }

  /** The sink's state, to put back with restore() when a decode it fed fails (gunzipMembers). */
  mark(): [number, number, Uint8Array, number] {
    return [this.head.length, this.headLen, this.ring, this.total];
  }

  restore([n, len, ring, total]: [number, number, Uint8Array, number]): void {
    this.head.length = n;
    this.headLen = len;
    this.ring = ring; // replaced, never written in place, by push()
    this.total = total;
  }

  /** true once the coding must stop: the head is full, or in tail mode the scan bound is passed */
  full(): boolean {
    return this.tail !== undefined ? this.total > (this.scan as number) : this.total >= this.limit;
  }

  result(complete: boolean): [Uint8Array, boolean, DecodeInfo?] {
    const out = new Uint8Array(this.headLen);
    let off = 0;
    for (const c of this.head) {
      out.set(c, off);
      off += c.byteLength;
    }
    const truncated = this.total >= this.limit;
    if (this.tail === undefined) return [out, truncated];
    return [out, truncated, { tail: this.ring.byteLength > 0 ? this.ring : null, size: this.total, complete }];
  }
}

/** Feed a stream into `sink` until it ends (true) or the sink is full (false). */
async function drain(stream: ReadableStream<Uint8Array>, sink: Sink): Promise<boolean> {
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return true;
      sink.push(value);
      if (sink.full()) {
        reader.cancel().catch(() => {});
        return false;
      }
    }
  } finally {
    reader.releaseLock();
  }
}

async function viaStream(input: Uint8Array, format: "gzip" | "deflate" | "deflate-raw", sink: Sink): Promise<boolean> {
  const ds = new DecompressionStream(format);
  const writer = ds.writable.getWriter();
  // write and close without awaiting: the readable side applies backpressure
  writer.write(input as unknown as BufferSource).catch(() => {});
  writer.close().catch(() => {});
  return drain(ds.readable as ReadableStream<Uint8Array>, sink);
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

/** `input` through a node:zlib decompressor into `sink`, streaming, so a bomb stops where the sink does like the others. Resolves true when the stream ended. */
function viaNode(d: NodeStream, input: Uint8Array, sink: Sink): Promise<boolean> {
  return new Promise((resolve, reject) => {
    let settled = false;
    d.on("data", (chunk) => {
      if (settled) return;
      sink.push(chunk);
      if (sink.full()) {
        settled = true;
        d.destroy();
        resolve(false);
      }
    });
    d.on("end", () => {
      if (!settled) {
        settled = true;
        resolve(true);
      }
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
    const sink = new Sink(17);
    await viaStream(new Uint8Array(PROBES[format]), format, sink);
    return new TextDecoder().decode(sink.result(true)[0]) === "jev";
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
 * members share one sink; what a refused decode fed it is taken back. After
 * MAX_GZIP_TRIES decodes, or when no offset works (trailing bytes that are
 * not a member), the body is corrupt, as in decode.lua. Resolves true when
 * the last member ended, false when the sink filled first.
 */
async function gunzipInto(input: Uint8Array, sink: Sink): Promise<boolean> {
  let tries = 0;
  // the decode's end (true), the sink full (false), or null when it was refused
  const attempt = async (bytes: Uint8Array): Promise<boolean | null> => {
    if (++tries > MAX_GZIP_TRIES) throw new Error("corrupt gzip body: too many members");
    const at = sink.mark();
    try {
      return await viaStream(bytes, "gzip", sink);
    } catch {
      sink.restore(at);
      return null;
    }
  };
  let off = 0;
  while (off < input.byteLength) {
    const rest = input.subarray(off);
    const whole = await attempt(rest);
    if (whole !== null) return whole;
    if (off === 0 && !(await streamDecodes("gzip"))) throw new Error("gzip decoder not available");
    let next = -1;
    for (let p = 18; p + 3 < rest.byteLength; p++) {
      if (rest[p] !== 0x1f || rest[p + 1] !== 0x8b || rest[p + 2] !== 0x08 || (rest[p + 3] & 0xe0) !== 0) continue;
      const got = await attempt(rest.subarray(0, p));
      if (got === null) continue;
      if (!got) return false;
      next = p;
      break;
    }
    if (next < 0) throw new Error("corrupt gzip body");
    off += next;
  }
  return true;
}

/**
 * gunzipInto with a sink of maxOut + 1 bytes: [bytes, truncated], as
 * decodeBody returns them. Exported for the tests.
 */
export async function gunzipMembers(input: Uint8Array, maxOut: number): Promise<[Uint8Array, boolean]> {
  const sink = new Sink(maxOut + 1);
  const complete = await gunzipInto(input, sink);
  const [out, cut] = sink.result(complete);
  return [out, cut];
}

/**
 * gzip, every member of it: node:zlib's gunzip goes on across concatenated
 * members as gunzip(1), body-parser and decode.lua do (it also takes zero
 * padding after the last one, as body-parser does; decode.lua does not).
 */
async function gunzip(input: Uint8Array, sink: Sink): Promise<boolean> {
  const z = await nodeZlib();
  let d: NodeStream | undefined;
  try {
    d = typeof z?.createGunzip === "function" ? z.createGunzip() : undefined;
  } catch {
    d = undefined; // a node:zlib without streams: the member walk below
  }
  return d ? viaNode(d, input, sink) : gunzipInto(input, sink);
}

/** Decode one coding into a sink from `mk` (a fresh one per attempt). Returns the sink and whether the stream ended. */
async function one(input: Uint8Array, c: Coding, mk: () => Sink): Promise<[Sink, boolean]> {
  if (c === "gzip") {
    const sink = mk();
    return [sink, await gunzip(input, sink)];
  }
  if (c === "deflate") {
    // HTTP "deflate" is zlib-wrapped; some clients send raw deflate
    try {
      const sink = mk();
      return [sink, await viaStream(input, "deflate", sink)];
    } catch {
      /* raw deflate, below */
    }
    try {
      const sink = mk();
      return [sink, await viaStream(input, "deflate-raw", sink)];
    } catch (e) {
      if (await streamDecodes("deflate")) throw e;
    }
    // no working DecompressionStream: node:zlib where there is one
    const z = await nodeZlib();
    if (typeof z?.createInflate !== "function" || typeof z.createInflateRaw !== "function") {
      throw new Error("deflate decoder not available");
    }
    try {
      const sink = mk();
      return [sink, await viaNode(z.createInflate(), input, sink)];
    } catch {
      const sink = mk();
      return [sink, await viaNode(z.createInflateRaw(), input, sink)];
    }
  }
  const z = await nodeZlib();
  if (!z) throw new Error("br decoder not available");
  const sink = mk();
  return [sink, await viaNode(z.createBrotliDecompress(), input, sink)];
}

/**
 * Decode `raw` per the Content-Encoding header value, codings applied in
 * reverse order of listing. Returns [bytes, truncated] (bytes is at most
 * maxOut + 1 long; truncated means the decoded body is longer), or
 * [null, error] when a coding is unsupported or the data is corrupt.
 *
 * Tail mode (`opts.tail`, decode.lua's): the last coding goes on past
 * maxOut, up to `opts.scan` bytes of output (default 4 x maxOut), and a
 * third element carries the body's end (DecodeInfo). Every earlier coding
 * must then decode whole within maxOut, or the body is not decodable ("too
 * large to decode whole"): a cut one would feed the last a cut stream.
 */
export async function decodeBody(
  raw: Uint8Array,
  header: string,
  maxOut: number,
  opts?: { tail?: number; scan?: number },
): Promise<[Uint8Array, boolean, DecodeInfo?] | [null, string]> {
  const cs = codings(header);
  if (typeof cs === "string") return [null, cs];
  const tail = opts?.tail !== undefined && opts.tail > 0 ? opts.tail : undefined;
  const limit = maxOut + 1;
  let cur = raw;
  let truncated = false;
  for (let i = cs.length - 1; i >= 0; i--) {
    if (cur.byteLength === 0) break;
    const last = tail !== undefined && i === 0;
    const scan = Math.max(opts?.scan ?? 4 * maxOut, limit);
    try {
      const [sink, complete] = await one(cur, cs[i], () => (last ? new Sink(limit, tail, scan) : new Sink(limit)));
      if (last) return sink.result(complete);
      const [out, cut] = sink.result(complete);
      if (tail !== undefined && cut) return [null, "too large to decode whole"];
      cur = out;
      truncated = truncated || cut;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return [null, msg.includes("not available") ? msg : "corrupt " + cs[i] + " body"];
    }
  }
  if (tail !== undefined && cs.length > 0) return [cur, truncated, { tail: null, size: cur.byteLength, complete: true }];
  return [cur, truncated];
}
