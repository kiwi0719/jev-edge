-- resty/jev/decode.lua
-- Request body decoding for Content-Encoding gzip / deflate / br, via LuaJIT
-- FFI against the system zlib and libbrotlidec. Without it a client can send
-- a compressed body and the filter scans bytes the upstream will inflate into
-- something else entirely.
--
-- Decompression-bomb safety: every stage stops once it has produced
-- max_out + 1 bytes, and the output buffer is a fixed-size chunk, so memory
-- use is bounded by the cap, never by the (attacker-declared) output size.
-- In tail mode (opts.tail) the last stage keeps inflating past the cap, up
-- to opts.scan bytes of output, and keeps only the last opts.tail bytes of
-- what follows the head: memory stays bounded by cap + tail, CPU by scan.
--
-- Libraries load lazily on first use and a missing one only disables its
-- coding: zlib is tried as libz, then as symbols already linked into nginx
-- (ffi.C); brotli as libbrotlidec. No ngx dependency, so plain luajit can
-- load this module too.

local ffi = require "ffi"

local ffi_new, ffi_cast, ffi_string = ffi.new, ffi.cast, ffi.string
local concat, min = table.concat, math.min

local _M = {}

local CHUNK       = 16384       -- output buffer per inflate call
local MAX_CODINGS = 3           -- more stacked codings than this is abuse, not a client
local DEFAULT_MAX = 1048576     -- used when the caller passes no cap

-- Declarations are pcall'ed one by one: another module (lua-ffi-zlib, a
-- brotli binding) may already have declared the same functions, which is
-- fine as long as the ABI matches. Our struct gets a private name, and the
-- functions take void * so they accept it whatever the other module used.
local function cdef(s) pcall(ffi.cdef, s) end

cdef[[
typedef struct jev_z_stream_s {
  const unsigned char *next_in;
  unsigned int         avail_in;
  unsigned long        total_in;
  unsigned char       *next_out;
  unsigned int         avail_out;
  unsigned long        total_out;
  const char          *msg;
  void                *state;
  void                *zalloc;
  void                *zfree;
  void                *opaque;
  int                  data_type;
  unsigned long        adler;
  unsigned long        reserved;
} jev_z_stream;
]]
cdef "const char *zlibVersion(void);"
cdef "int inflateInit2_(void *strm, int windowBits, const char *version, int stream_size);"
cdef "int inflate(void *strm, int flush);"
cdef "int inflateReset(void *strm);"
cdef "int inflateEnd(void *strm);"
cdef "void *BrotliDecoderCreateInstance(void *alloc_func, void *free_func, void *opaque);"
cdef "void BrotliDecoderDestroyInstance(void *state);"
cdef [[int BrotliDecoderDecompressStream(void *state, size_t *available_in, const uint8_t **next_in,
                                        size_t *available_out, uint8_t **next_out, size_t *total_out);]]

local Z_OK, Z_STREAM_END = 0, 1
local Z_DATA_ERROR, Z_BUF_ERROR = -3, -5
local Z_NO_FLUSH = 0

local BROTLI_SUCCESS = 1   -- BROTLI_DECODER_RESULT_ERROR is 0
local BROTLI_NEEDS_MORE_INPUT, BROTLI_NEEDS_MORE_OUTPUT = 2, 3

local Z_STREAM_SIZE = ffi.sizeof("jev_z_stream")

-- Shared output buffer: decoding never yields, so one per worker is enough.
local outbuf

-- Lazy library handles: nil = not tried yet, false = unavailable.
local zlib, brotli

local function has(lib, sym)
  return pcall(function() return lib[sym] end)
end

local function load_zlib()
  if zlib ~= nil then return zlib end
  zlib = false
  for _, name in ipairs({ "z", "libz.so.1" }) do
    local ok, lib = pcall(ffi.load, name)
    if ok and has(lib, "inflateInit2_") then zlib = lib break end
  end
  -- nginx links zlib for gzip/gunzip, so the symbols are often already here.
  if not zlib and has(ffi.C, "inflateInit2_") then zlib = ffi.C end
  return zlib
end

local function load_brotli()
  if brotli ~= nil then return brotli end
  brotli = false
  for _, name in ipairs({ "brotlidec", "libbrotlidec.so.1" }) do
    local ok, lib = pcall(ffi.load, name)
    if ok and has(lib, "BrotliDecoderDecompressStream") then brotli = lib break end
  end
  return brotli
end

local function buffer()
  if not outbuf then outbuf = ffi_new("uint8_t[?]", CHUNK) end
  return outbuf
end

-- Where a stage's output goes. `o.limit` bytes are kept whole (the head).
-- With `o.tail`, every byte past the first `o.limit - 1` also goes through a
-- ring that keeps the last `o.tail` of them, and the stage stops once it has
-- produced more than `o.scan` bytes instead of at the head's end.
local Sink = {}
Sink.__index = Sink

local function sink(o)
  return setmetatable({ limit = o.limit, tail = o.tail, scan = o.scan, from = o.limit - 1,
                        head = {}, head_n = 0, ring = {}, ring_n = 0, total = 0 }, Sink)
end

-- how many bytes the next inflate call may write
function Sink:want()
  if self.tail then return min(CHUNK, self.scan + 1 - self.total) end
  return min(CHUNK, self.limit - self.total)
end

function Sink:push(buf, got)
  local s = ffi_string(buf, got)
  if self.head_n < self.limit then
    local take = min(self.limit - self.head_n, got)
    self.head[#self.head + 1] = take == got and s or s:sub(1, take)
    self.head_n = self.head_n + take
  end
  if self.tail then
    local skip = self.from - self.total
    if skip < got then
      local piece = skip > 0 and s:sub(skip + 1) or s
      local ring = self.ring
      ring[#ring + 1] = piece
      self.ring_n = self.ring_n + #piece
      while self.ring_n - #ring[1] >= self.tail do
        self.ring_n = self.ring_n - #ring[1]
        table.remove(ring, 1)
      end
    end
  end
  self.total = self.total + got
end

-- true once the stage must stop: the head is full, or in tail mode the scan
-- bound is passed (what follows was never produced)
function Sink:full()
  if self.tail then return self.total > self.scan end
  return self.total >= self.limit
end

-- output, truncated[, info]. In tail mode info = { tail = the last bytes
-- after the head or nil, size = bytes produced, complete = the stream
-- ended within the scan bound }.
function Sink:result(complete)
  local out, trunc = concat(self.head), self.total >= self.limit
  if not self.tail then return out, trunc end
  local ring = concat(self.ring)
  if #ring > self.tail then ring = ring:sub(-self.tail) end
  return out, trunc, { tail = ring ~= "" and ring or nil, size = self.total, complete = complete }
end

-- One zlib pass. Returns output, truncated[, info] | nil, err ("data" = bad
-- stream). `o` holds the Sink's limit / tail / scan, and `partial` accepts
-- input that just stops (it was cut by an earlier stage's cap); `multi`
-- continues across concatenated gzip members like gunzip does, so a second
-- member cannot smuggle unscanned text past the filter.
local function zlib_run(z, raw, window_bits, o, multi)
  local strm = ffi_new("jev_z_stream")
  local sp = ffi_cast("void *", strm)
  if z.inflateInit2_(sp, window_bits, z.zlibVersion(), Z_STREAM_SIZE) ~= Z_OK then
    return nil, "init"
  end

  local ok, out, trunc, info = pcall(function()
    local buf = buffer()
    local sk = sink(o)
    strm.next_in = ffi_cast("const unsigned char *", raw)
    strm.avail_in = #raw
    while true do
      local want = sk:want()
      strm.next_out, strm.avail_out = buf, want
      local rc = z.inflate(sp, Z_NO_FLUSH)
      local got = want - strm.avail_out
      if got > 0 then sk:push(buf, got) end

      if rc == Z_STREAM_END and strm.avail_in == 0 then return sk:result(true) end
      if sk:full() then return sk:result(false) end

      if rc == Z_STREAM_END then
        -- Another gzip member follows (1f 8b); anything else is trailing junk.
        local left, nx = strm.avail_in, strm.next_in
        if not (multi and left >= 2 and nx[0] == 0x1f and nx[1] == 0x8b) then
          error("data", 0)
        end
        if z.inflateReset(sp) ~= Z_OK then error("data", 0) end
      elseif rc == Z_BUF_ERROR or (rc == Z_OK and got == 0 and strm.avail_in == 0) then
        -- No progress possible: input ended before the stream did.
        if o.partial then return sk:result(false) end
        error("data", 0)
      elseif rc ~= Z_OK then
        -- Z_DATA_ERROR, Z_NEED_DICT (preset dictionaries are not HTTP), Z_MEM_ERROR
        error(rc == Z_DATA_ERROR and strm.total_out == 0 and "start" or "data", 0)
      end
    end
  end)
  z.inflateEnd(sp)
  if not ok then return nil, out end
  return out, trunc, info
end

-- Brotli pass, same contract as zlib_run (brotli has no member concatenation).
local function brotli_run(b, raw, o)
  local st = b.BrotliDecoderCreateInstance(nil, nil, nil)
  if st == nil then return nil, "init" end

  local ok, out, trunc, info = pcall(function()
    local buf = buffer()
    local sk = sink(o)
    local avail_in = ffi_new("size_t[1]", #raw)
    local next_in = ffi_new("const uint8_t *[1]", ffi_cast("const uint8_t *", raw))
    local avail_out = ffi_new("size_t[1]")
    local next_out = ffi_new("uint8_t *[1]")
    while true do
      local want = sk:want()
      avail_out[0], next_out[0] = want, buf
      local rc = b.BrotliDecoderDecompressStream(st, avail_in, next_in, avail_out, next_out, nil)
      local got = want - tonumber(avail_out[0])
      if got > 0 then sk:push(buf, got) end

      if rc == BROTLI_SUCCESS then
        if avail_in[0] ~= 0 and not sk:full() then error("data", 0) end
        if avail_in[0] == 0 then return sk:result(true) end
      end
      if sk:full() then return sk:result(false) end

      if rc == BROTLI_NEEDS_MORE_INPUT then
        if o.partial then return sk:result(false) end
        error("data", 0)
      elseif rc ~= BROTLI_NEEDS_MORE_OUTPUT then
        error("data", 0)   -- BROTLI_ERROR or anything unknown
      end
    end
  end)
  b.BrotliDecoderDestroyInstance(st)
  if not ok then return nil, out end
  return out, trunc, info
end

-- One coding. Returns output, truncated[, info] | nil, err.
local function run(enc, raw, o)
  if raw == "" then return "", false, o.tail and { size = 0, complete = true } or nil end

  if enc == "br" then
    local b = load_brotli()
    if not b then return nil, "br decoder not available" end
    local out, err, info = brotli_run(b, raw, o)
    if not out then return nil, "corrupt br body" end
    return out, err, info
  end

  local z = load_zlib()
  if not z then return nil, enc .. " decoder not available" end
  local out, err, info
  if enc == "gzip" then
    -- 15 + 32: auto-detect gzip or zlib header, as browsers and nginx do.
    out, err, info = zlib_run(z, raw, 15 + 32, o, true)
  else
    -- "deflate" is meant to be zlib-wrapped (RFC 9110), but raw deflate is
    -- common enough in the wild that everyone falls back to it.
    out, err, info = zlib_run(z, raw, 15, o, false)
    if not out and err == "start" then
      out, err, info = zlib_run(z, raw, -15, o, false)
    end
  end
  if not out then return nil, "corrupt " .. enc .. " body" end
  return out, err, info
end

local ALIASES = { gzip = "gzip", ["x-gzip"] = "gzip", deflate = "deflate", br = "br" }

-- Content-Encoding value(s) -> list of codings in the order they were applied.
local function parse(encodings)
  if type(encodings) == "table" then encodings = concat(encodings, ",") end
  local list = {}
  for tok in tostring(encodings or ""):gmatch("[^,]+") do
    tok = tok:match("^%s*(.-)%s*$"):lower()
    if tok ~= "" and tok ~= "identity" then
      local enc = ALIASES[tok]
      if not enc then return nil, "unsupported encoding: " .. tok end
      list[#list + 1] = enc
      if #list > MAX_CODINGS then return nil, "too many encodings" end
    end
  end
  return list
end

--- Decode a request body.
-- @param raw        the body as received
-- @param encodings  Content-Encoding value: a string, or a list of them (repeated headers)
-- @param max_out    output cap in bytes (default 1 MiB)
-- @param opts       optional { tail = N, scan = M }: tail mode (below)
-- @return decoded, truncated  truncated=true means the body is larger than
--         max_out; decoded is then the first max_out + 1 bytes so a plain
--         `#body > max` check fires. If an inner coding hit the cap first
--         (stacked codings), what follows was decoded from a cut stream and can
--         be shorter: callers must honour the flag, not only the length.
-- @return nil, err    unsupported encoding, missing library or corrupt data
--
-- Tail mode: the last coding goes on inflating past max_out, up to
-- opts.scan bytes of output (default 4 x max_out), and a third value comes
-- back with the decoded body's end: { tail = its last opts.tail bytes after
-- the first max_out (nil when there are none), size = its decoded size,
-- complete = false when the scan bound came first, so `tail` is not the
-- end }. Every earlier (inner) coding must then decode whole within
-- max_out: a cut one would feed the last one a cut stream, whose tail is not
-- the body's, so that is an error ("too large to decode whole").
function _M.decode(raw, encodings, max_out, opts)
  local list, perr = parse(encodings)
  if not list then return nil, perr end
  raw = raw or ""
  if #list == 0 then return raw, false end

  local max = tonumber(max_out) or DEFAULT_MAX
  local limit = max + 1
  local tail = opts and tonumber(opts.tail)
  if tail and tail <= 0 then tail = nil end
  local truncated = false
  -- Codings are listed in the order they were applied, so undo them backwards.
  for i = #list, 1, -1 do
    if tail and i == 1 then
      local scan = math.max(tonumber(opts.scan) or 4 * max, limit)
      return run(list[i], raw, { limit = limit, tail = tail, scan = scan })
    end
    local out, trunc = run(list[i], raw, { limit = limit, partial = truncated })
    if not out then return nil, trunc end
    if tail and trunc then return nil, "too large to decode whole" end
    raw = out
    truncated = truncated or trunc
  end
  return raw, truncated
end

--- Which codings this worker can decode (loads the libraries if needed).
function _M.supported()
  local z = load_zlib() and true or false
  return { gzip = z, deflate = z, br = load_brotli() and true or false }
end

return _M
