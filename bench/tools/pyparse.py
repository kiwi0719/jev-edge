"""bench/tools/pyparse.py: reads tool definitions out of Python source with
the ast module, without running it.

What is read: module constants and str Enums, pydantic models (as the JSON
Schema model_json_schema() gives: titles, descriptions, defaults, bounds),
dict literals, and calls that build a tool (MCP `Tool(...)`, litellm
`ChatCompletionToolParam(...)`), whose keyword arguments become a dict.
Anything the evaluator does not know raises.
"""

import ast
import re


class Unknown(Exception):
    pass


def title_of(name):
    """pydantic's default field title: max_length -> Max Length."""
    return " ".join(w[:1].upper() + w[1:] for w in name.replace("_", " ").split())


class Module:
    def __init__(self, src, env=None, calls=None):
        self.src = src
        self.tree = ast.parse(src)
        self.env = dict(env or {})
        # functions whose result is taken as given: name -> fn(args, kwargs)
        self.calls = {"refine_prompt": lambda a, k: a[0], "dedent": lambda a, k: _dedent(a[0])}
        self.calls.update(calls or {})
        self.models = {}
        self._scan(self.tree.body)

    # -- module scan -----------------------------------------------------------
    def _scan(self, body):
        for node in body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                try:
                    self.env[node.targets[0].id] = self.ev(node.value)
                except (Unknown, KeyError):
                    pass
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                try:
                    self.env[node.target.id] = self.ev(node.value)
                except (Unknown, KeyError):
                    pass
            elif isinstance(node, ast.ClassDef):
                bases = [ast.unparse(b) for b in node.bases]
                if "Enum" in bases or "str, Enum" in ", ".join(bases):
                    for st in node.body:
                        if isinstance(st, ast.Assign) and isinstance(st.value, ast.Constant):
                            self.env[node.name + "." + st.targets[0].id] = st.value.value
                elif any(b in ("BaseModel",) for b in bases) or any(b in self.models for b in bases):
                    self.models[node.name] = node

    # -- expressions -----------------------------------------------------------
    def ev(self, n, local=None):
        local = local or {}
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, ast.JoinedStr):
            out = []
            for v in n.values:
                if isinstance(v, ast.Constant):
                    out.append(v.value)
                else:
                    out.append(str(self.ev(v.value, local)))
            return "".join(out)
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            return self.ev(n.left, local) + self.ev(n.right, local)
        if isinstance(n, ast.Dict):
            out = {}
            for k, v in zip(n.keys, n.values):
                if k is None:
                    out.update(self.ev(v, local))
                else:
                    out[self.ev(k, local)] = self.ev(v, local)
            return out
        if isinstance(n, (ast.List, ast.Tuple)):
            return [self.ev(x, local) for x in n.elts]
        if isinstance(n, ast.Name):
            if n.id in local:
                return local[n.id]
            if n.id in self.env:
                return self.env[n.id]
            if n.id in ("True", "False", "None"):
                return {"True": True, "False": False, "None": None}[n.id]
            raise Unknown(n.id)
        if isinstance(n, ast.Attribute):
            dotted = ast.unparse(n)
            if dotted in self.env:
                return self.env[dotted]
            if n.attr == "value":
                return self.ev(n.value, local)
            raise Unknown(dotted)
        if isinstance(n, ast.IfExp):
            return self.ev(n.body if self.ev(n.test, local) else n.orelse, local)
        if isinstance(n, ast.Call):
            fn = ast.unparse(n.func)
            if fn.endswith(".model_json_schema"):
                return self.model_schema(fn[: -len(".model_json_schema")])
            args = [self.ev(a, local) for a in n.args]
            kw = {k.arg: self.ev(k.value, local) for k in n.keywords if k.arg}
            if fn in self.calls:
                return self.calls[fn](args, kw)
            if fn.split(".")[-1] in ("Tool", "ToolAnnotations", "ChatCompletionToolParam", "ChatCompletionToolParamFunctionChunk", "dict"):
                return kw
            raise Unknown(fn)
        raise Unknown(ast.dump(n)[:80])

    # -- pydantic --------------------------------------------------------------
    def model_schema(self, name):
        node = self.models[name]
        props, req = {}, []
        for st in node.body:
            if not isinstance(st, ast.AnnAssign) or not isinstance(st.target, ast.Name):
                continue
            fname = st.target.id
            ann = st.annotation
            field = None
            if isinstance(ann, ast.Subscript) and ast.unparse(ann.value) == "Annotated":
                elts = ann.slice.elts
                ann = elts[0]
                for e in elts[1:]:
                    if isinstance(e, ast.Call) and ast.unparse(e.func) == "Field":
                        field = e
            if isinstance(st.value, ast.Call) and ast.unparse(st.value.func) == "Field":
                field = st.value
            p = {"title": title_of(fname)}
            p.update(self.type_schema(ann))
            has_default = False
            if field is not None:
                kw = {k.arg: k.value for k in field.keywords}
                if field.args and not (isinstance(field.args[0], ast.Constant) and field.args[0].value is Ellipsis):
                    p["default"] = self.ev(field.args[0])
                    has_default = True
                if "default" in kw:
                    p["default"] = self.ev(kw["default"])
                    has_default = True
                if "default_factory" in kw:
                    p["default"] = [] if ast.unparse(kw["default_factory"]) == "list" else {}
                    has_default = True
                for a, js in (("description", "description"), ("ge", "minimum"), ("le", "maximum"),
                              ("gt", "exclusiveMinimum"), ("lt", "exclusiveMaximum"), ("title", "title")):
                    if a in kw:
                        p[js] = self.ev(kw[a])
            elif st.value is not None:
                p["default"] = self.ev(st.value)
                has_default = True
            props[fname] = p
            if not has_default:
                req.append(fname)
        out = {"properties": props, "title": name, "type": "object"}
        doc = ast.get_docstring(node)
        if doc:
            out["description"] = doc
        if req:
            out["required"] = req
        return out

    def type_schema(self, ann):
        s = ast.unparse(ann)
        base = {"str": {"type": "string"}, "int": {"type": "integer"}, "float": {"type": "number"},
                "bool": {"type": "boolean"}, "AnyUrl": {"type": "string", "format": "uri", "minLength": 1,
                                                        "maxLength": 2083},
                "dict": {"type": "object"}, "Any": {}}
        if s in base:
            return dict(base[s])
        m = re.fullmatch(r"(?:Optional\[(.+)\]|(.+) \| None)", s)
        if m:
            inner = m.group(1) or m.group(2)
            return {"anyOf": [self.type_schema(ast.parse(inner, mode="eval").body), {"type": "null"}]}
        m = re.fullmatch(r"(?:list|List)\[(.+)\]", s)
        if m:
            return {"type": "array", "items": self.type_schema(ast.parse(m.group(1), mode="eval").body)}
        m = re.fullmatch(r"Literal\[(.+)\]", s)
        if m:
            vals = self.ev(ast.parse("[" + m.group(1) + "]", mode="eval").body)
            return {"enum": vals, "type": "string"}
        if s in self.models:
            return {"$ref": "#/$defs/" + s}
        raise Unknown("type " + s)

    # -- finders ---------------------------------------------------------------
    def calls_named(self, name, within=None):
        """Every call to `name` (last dotted part), evaluated; within: a
        function name whose local assignments are evaluated first."""
        out = []
        roots = [self.tree]
        if within:
            roots = [f for f in ast.walk(self.tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and f.name == within]
        for root in roots:
            local = {}
            if isinstance(root, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # parameters take their defaults
                a = root.args
                for arg, d in zip(a.args[len(a.args) - len(a.defaults):], a.defaults):
                    local[arg.arg] = self.ev(d)
                for st in ast.walk(root):
                    if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                        try:
                            local[st.targets[0].id] = self.ev(st.value, local)
                        except (Unknown, KeyError):
                            pass
            for n in ast.walk(root):
                if isinstance(n, ast.Call) and ast.unparse(n.func).split(".")[-1] == name:
                    out.append(self.ev(n, local))
        return out

    def function(self, name):
        for f in ast.walk(self.tree):
            if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.name == name:
                return f
        raise Unknown("function " + name)

    def classes(self):
        return [n for n in self.tree.body if isinstance(n, ast.ClassDef)]


def _dedent(s):
    import textwrap
    return textwrap.dedent(s)
