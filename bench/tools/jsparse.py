"""bench/tools/jsparse.py: reads tool definitions out of TypeScript source
without running it.

Two things are read: object literals (`const X: Tool = { name: ..., ... }`) and
zod schemas (`z.object({ path: z.string().describe("...") })`), which are
turned into the JSON Schema the MCP SDK sends (zod-to-json-schema's shape:
`additionalProperties: false` on objects, `$schema` at the top). Only what
tool definitions use is supported; anything else raises, so a source that
changes shape fails the build instead of producing a different tool set.
"""

import json
import re

SKIPPED = ("transform", "refine", "superRefine", "pipe")
PUNCT = ["...", "=>", "?.", "%", "^", "~", "@", "#", "{", "}", "[", "]", "(", ")", ",", ":", ";", ".", "+", "?", "=", "<", ">", "|", "&", "!", "-", "*", "/"]
ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


class Tok:
    def __init__(self, kind, val, pos):
        self.kind, self.val, self.pos = kind, val, pos

    def __repr__(self):
        return "%s:%r" % (self.kind, self.val)


def _string(src, i, q):
    out = []
    i += 1
    while True:
        c = src[i]
        if c == "\\":
            n = src[i + 1]
            if n == "u":
                if src[i + 2] == "{":
                    j = src.index("}", i)
                    out.append(chr(int(src[i + 3:j], 16)))
                    i = j + 1
                else:
                    out.append(chr(int(src[i + 2:i + 6], 16)))
                    i += 6
                continue
            if n == "x":
                out.append(chr(int(src[i + 2:i + 4], 16)))
                i += 4
                continue
            if n == "\n":
                i += 2
                continue
            out.append(ESC.get(n, n))
            i += 2
            continue
        if c == q:
            return "".join(out), i + 1
        if q == "`" and c == "$" and src[i + 1] == "{":
            # a template substitution: kept as a marker, resolved by the parser
            depth, j = 1, i + 2
            while depth:
                if src[j] == "{":
                    depth += 1
                elif src[j] == "}":
                    depth -= 1
                j += 1
            out.append("\x00" + src[i + 2:j - 1].strip() + "\x00")
            i = j
            continue
        out.append(c)
        i += 1


def tokens(src, i=0):
    """Yields tokens from src[i:] (comments and whitespace skipped)."""
    n = len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            i = src.index("*/", i) + 2
            continue
        if c in "'\"`":
            s, j = _string(src, i, c)
            yield Tok("tmpl" if c == "`" else "str", s, i)
            i = j
            continue
        m = re.match(r"\d[\d_]*(\.\d+)?([eE][-+]?\d+)?", src[i:])
        if m:
            t = m.group(0).replace("_", "")
            yield Tok("num", float(t) if ("." in t or "e" in t.lower()) else int(t), i)
            i += len(m.group(0))
            continue
        m = re.match(r"[A-Za-z_$][\w$]*", src[i:])
        if m:
            yield Tok("id", m.group(0), i)
            i += len(m.group(0))
            continue
        for p in PUNCT:
            if src.startswith(p, i):
                yield Tok("p", p, i)
                i += len(p)
                break
        else:
            raise ValueError("unexpected %r at %d" % (c, i))
    yield Tok("eof", None, n)


class Parser:
    """Recursive descent over a token stream starting at a position of src.
    env: names a value may refer to (constants, enum members, zod schemas).
    helpers: calls a source defines itself, mapped to a zod base type."""

    def __init__(self, src, pos, env=None, helpers=None):
        self.src = src
        self.toks = tokens(src, pos)
        self.tok = next(self.toks)
        self.env = env if env is not None else {}
        self.helpers = helpers or {}

    def next(self):
        t = self.tok
        self.tok = next(self.toks)
        return t

    def peek(self, kind, val=None):
        return self.tok.kind == kind and (val is None or self.tok.val == val)

    def expect(self, kind, val=None):
        if not self.peek(kind, val):
            raise ValueError("expected %s %r, got %r at %d: %r" % (kind, val, self.tok, self.tok.pos,
                                                                  self.src[self.tok.pos:self.tok.pos + 60]))
        return self.next()

    def accept(self, kind, val=None):
        if self.peek(kind, val):
            return self.next()
        return None

    # -- values ------------------------------------------------------------
    def value(self):
        v = self.primary()
        # string concatenation
        while self.accept("p", "+"):
            w = self.primary()
            v = str(v) + str(w)
        # `as const`, `as Tool`, `satisfies X`
        while self.peek("id", "as") or self.peek("id", "satisfies"):
            self.next()
            self.next()
            while self.accept("p", "."):
                self.next()
            if self.accept("p", "["):
                self.expect("p", "]")
        return v

    def template(self, s):
        def sub(m):
            name = m.group(1)
            if name not in self.env:
                raise ValueError("unresolved ${%s}" % name)
            return str(self.env[name])
        return re.sub("\x00([^\x00]*)\x00", sub, s)

    def primary(self):
        t = self.tok
        if t.kind == "str":
            self.next()
            return t.val
        if t.kind == "tmpl":
            self.next()
            return self.template(t.val)
        if t.kind == "num":
            self.next()
            return t.val
        if self.accept("p", "-"):
            return -self.primary()
        if self.peek("p", "{"):
            return self.obj()
        if self.peek("p", "["):
            return self.arr()
        if self.peek("p", "("):
            self.next()
            v = self.value()
            self.expect("p", ")")
            return v
        if t.kind == "id":
            if t.val in ("true", "false"):
                self.next()
                return t.val == "true"
            if t.val in ("null", "undefined"):
                self.next()
                return None
            if t.val == "z":
                return self.zod()
            if t.val in self.helpers:
                return self.zod()
            return self.ref()
        raise ValueError("unexpected %r at %d: %r" % (t, t.pos, self.src[t.pos:t.pos + 60]))

    def ref(self):
        name = self.expect("id").val
        while name not in self.env and self.peek("p", "."):
            self.next()
            name += "." + self.expect("id").val
        if name not in self.env:
            raise ValueError("unresolved name %s" % name)
        v = self.env[name]
        if isinstance(v, Zod):
            return self.chain(v.copy())
        return v

    def key(self):
        t = self.next()
        if t.kind in ("id", "str", "num"):
            return str(t.val)
        if t.kind == "p" and t.val == "[":
            k = self.value()
            self.expect("p", "]")
            return str(k)
        raise ValueError("bad key %r at %d" % (t, t.pos))

    def obj(self):
        self.expect("p", "{")
        out = {}
        while not self.accept("p", "}"):
            if self.accept("p", "..."):
                out.update(self.value())
            else:
                k = self.key()
                if self.accept("p", ":"):
                    out[k] = self.value()
                else:
                    out[k] = self.env[k]
            if not self.accept("p", ","):
                self.expect("p", "}")
                break
        return out

    def arr(self):
        self.expect("p", "[")
        out = []
        while not self.accept("p", "]"):
            if self.accept("p", "..."):
                out.extend(self.value())
            else:
                out.append(self.value())
            if not self.accept("p", ","):
                self.expect("p", "]")
                break
        return out

    def args(self):
        self.expect("p", "(")
        out = []
        while not self.accept("p", ")"):
            out.append(self.value())
            if not self.accept("p", ","):
                self.expect("p", ")")
                break
        return out

    # -- zod -----------------------------------------------------------------
    def zod(self):
        name = self.expect("id").val
        optional = False
        if name == "z":
            self.expect("p", ".")
            base = self.expect("id").val
            if base == "coerce":
                self.expect("p", ".")
                base = self.expect("id").val
        else:
            # a helper the source imports: "string", or "number?" for an optional one
            base = self.helpers[name]
            optional = base.endswith("?")
            base = base.rstrip("?")
        if base == "preprocess":
            # z.preprocess(fn, schema): the JSON Schema is the schema's
            self.expect("p", "(")
            self.skip_expr()
            self.expect("p", ",")
            inner = self.value()
            self.accept("p", ",")
            self.expect("p", ")")
            return self.chain(inner.copy())
        a = self.args()
        z = Zod.base(base, a)
        z.optional = optional
        return self.chain(z)

    def skip_expr(self):
        """Skips one call argument (a callback, a call the source defines
        elsewhere), up to the comma or closing parenthesis that ends it."""
        depth = 0
        while True:
            t = self.tok
            if t.kind == "eof":
                raise ValueError("unbalanced argument")
            if t.kind == "p" and depth == 0 and t.val in (",", ")"):
                return
            if t.kind == "p" and t.val in "([{":
                depth += 1
            elif t.kind == "p" and t.val in ")]}":
                depth -= 1
            self.next()

    def chain(self, z):
        while self.peek("p", "."):
            self.next()
            m = self.expect("id").val
            if m == "shape" and not self.peek("p", "("):
                return z.shape
            if m in SKIPPED:
                self.skip_args()
                continue
            a = self.args()
            z.method(m, a)
        return z

    def skip_args(self):
        """A call whose arguments are code (a transform or refine callback):
        the input schema is what it applies to, as zod-to-json-schema reads it."""
        self.expect("p", "(")
        depth = 1
        while depth:
            t = self.next()
            if t.kind == "eof":
                raise ValueError("unbalanced call")
            if t.kind == "p" and t.val in "([{":
                depth += 1
            elif t.kind == "p" and t.val in ")]}":
                depth -= 1


class Zod:
    def __init__(self, schema):
        self.schema = schema
        self.optional = False
        self.has_default = False
        self.shape = None

    def copy(self):
        z = Zod(json.loads(json.dumps(self.schema)))
        z.optional, z.has_default, z.shape = self.optional, self.has_default, self.shape
        return z

    @staticmethod
    def base(name, a):
        if name in ("string", "number", "boolean"):
            return Zod({"type": name})
        if name in ("any", "unknown"):
            return Zod({})
        if name == "null":
            return Zod({"type": "null"})
        if name == "enum":
            vals = a[0] if isinstance(a[0], list) else list(a[0].values())
            return Zod({"type": "string", "enum": vals})
        if name == "literal":
            v = a[0]
            t = "string" if isinstance(v, str) else "boolean" if isinstance(v, bool) else "number"
            return Zod({"type": t, "const": v})
        if name == "array":
            return Zod({"type": "array", "items": to_schema(a[0])})
        if name == "object":
            z = Zod(object_schema(a[0] if a else {}))
            z.shape = a[0] if a else {}
            return z
        if name == "record":
            return Zod({"type": "object", "additionalProperties": to_schema(a[-1])})
        if name == "union":
            return Zod({"anyOf": [to_schema(x) for x in a[0]]})
        if name == "tuple":
            return Zod({"type": "array", "items": [to_schema(x) for x in a[0]]})
        raise ValueError("zod base %s not supported" % name)

    def method(self, m, a):
        s = self.schema
        if m == "describe":
            s["description"] = a[0]
        elif m == "optional" or m == "nullish":
            self.optional = True
        elif m == "nullable":
            pass
        elif m == "default":
            s["default"] = a[0]
            self.has_default = True
        elif m == "int":
            s["type"] = "integer"
        elif m in ("min", "max", "gte", "lte", "gt", "lt", "length"):
            t = s.get("type")
            key = {"string": ("minLength", "maxLength"), "array": ("minItems", "maxItems")}.get(t, ("minimum", "maximum"))
            if m in ("min", "gte"):
                s[key[0]] = a[0]
            elif m in ("max", "lte"):
                s[key[1]] = a[0]
            elif m == "gt":
                s["exclusiveMinimum"] = a[0]
            elif m == "lt":
                s["exclusiveMaximum"] = a[0]
        elif m == "positive":
            s["exclusiveMinimum"] = 0
        elif m == "nonnegative":
            s["minimum"] = 0
        elif m == "url":
            s["format"] = "uri"
        elif m == "email":
            s["format"] = "email"
        elif m == "datetime":
            s["format"] = "date-time"
        elif m == "regex":
            pass
        elif m in ("strict", "passthrough", "trim", "toLowerCase", "catch", "brand", "readonly"):
            pass
        elif m == "array":
            self.schema = {"type": "array", "items": s}
        elif m == "or":
            self.schema = {"anyOf": [s, to_schema(a[0])]}
        elif m == "extend":
            s["properties"].update(object_schema(a[0])["properties"])
            s["required"] = sorted(set(s.get("required", [])) | set(object_schema(a[0]).get("required", [])),
                                   key=list(s["properties"]).index)
        else:
            raise ValueError("zod method %s not supported" % m)


def to_schema(v):
    if isinstance(v, Zod):
        return v.schema
    raise ValueError("not a zod schema: %r" % (v,))


def object_schema(shape):
    """A z.object shape (or an MCP SDK raw shape) as JSON Schema."""
    props, req = {}, []
    for k, v in shape.items():
        props[k] = to_schema(v)
        if not (v.optional or v.has_default):
            req.append(k)
    out = {"type": "object", "properties": props}
    if req:
        out["required"] = req
    out["additionalProperties"] = False
    return out


def input_schema(shape_or_zod):
    """What the MCP SDK sends as a tool's inputSchema."""
    s = shape_or_zod.schema if isinstance(shape_or_zod, Zod) else object_schema(shape_or_zod)
    s = dict(s)
    s["$schema"] = "http://json-schema.org/draft-07/schema#"
    return s


DECL = re.compile(r"(?:^|\n)\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w.<>\[\]| ]+)?\s*=\s*", re.M)
ENUM = re.compile(r"(?:export\s+)?enum\s+(\w+)\s*\{([^}]*)\}")


def env_of(src, helpers=None, env=None):
    """Constants, enums and zod schemas declared in src, in order; a
    declaration that is not a literal or zod value is skipped."""
    env = env if env is not None else {}
    for m in ENUM.finditer(src):
        for item in m.group(2).split(","):
            item = re.sub(r"//.*", "", item).strip()
            if "=" in item:
                k, v = item.split("=", 1)
                env[m.group(1) + "." + k.strip()] = json.loads(v.strip().replace("'", '"'))
    for m in DECL.finditer(src):
        try:
            p = Parser(src, m.end(), env, helpers)
            env[m.group(1)] = p.value()
        except (ValueError, KeyError, IndexError, StopIteration, TypeError, AttributeError):
            pass
    return env


def literal_at(src, pos, env=None, helpers=None):
    """The literal (or zod value) starting at src[pos]."""
    return Parser(src, pos, env or {}, helpers).value()


def call_args_at(src, pos, env=None, helpers=None, limit=None):
    """The first `limit` arguments of the call whose '(' is at or after
    src[pos]; a function argument (the handler) ends the list."""
    p = Parser(src, src.index("(", pos), env or {}, helpers)
    p.expect("p", "(")
    out = []
    while not p.peek("p", ")") and (limit is None or len(out) < limit):
        if p.peek("id", "async") or (p.peek("p", "(") and _arrow_ahead(src, p.tok.pos)):
            break
        out.append(p.value())
        if not p.accept("p", ","):
            break
    return out


def _arrow_ahead(src, pos):
    depth, i = 0, pos
    while i < len(src):
        c = src[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return re.match(r"\s*(:\s*[^=]+)?=>", src[i + 1:]) is not None
        i += 1
    return False
