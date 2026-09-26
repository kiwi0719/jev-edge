#!/usr/bin/env python3
"""bench/tools/build.py: the tool-definition false-positive set.

Reads the sources bench/tools/fetch.sh downloaded (bench/tools/raw, pinned
commits) and writes one OpenAI chat body per real tool set to
bench/datasets/tools-fp-v1.jsonl:

    {"model": MODEL, "messages": [{"role": "user", "content": MSG}], "tools": [...]}

Every body carries the same short user message, under the llm-endpoints rule's
min_text_chars, so jev-edge judges the tools part and nothing else. No attack
text is added: every string is the project's own.

Nothing is executed. TypeScript is read by jsparse.py, Python by pyparse.py
(ast), YAML by PyYAML, notebooks cell by cell. Where a description depends on
the machine it runs on, the value chosen is written in the record's `notes`.

    python3 bench/tools/build.py [--raw bench/tools/raw] [--out bench/datasets/tools-fp-v1.jsonl]
"""

import argparse
import ast
import json
import os
import re

import yaml

import jsparse as J
import pyparse as P

MSG = "What can you do?"   # 16 characters; min_text_chars is 20
MODEL = "gpt-4o"

RAW = "bench/tools/raw"

REPOS = {
    "mcp": ("modelcontextprotocol/servers", "f46d9578190b476b3501923ea8977d899e8db2cb",
            "Apache-2.0 (MIT for contributions not relicensed)"),
    "arch": ("modelcontextprotocol/servers-archived", "9be4674d1ddf8c469e6461a27a337eeb65f76c2e", "MIT"),
    "ghm": ("github/github-mcp-server", "85598ba6e1256f7ebf4867b95d63b833c4549264", "MIT"),
    "pw": ("microsoft/playwright-mcp", "f1257a5a67aff872f947fae274759f7d54853862", "Apache-2.0"),
    "fc": ("firecrawl/firecrawl-mcp-server", "1b9c89b502a04d7c6383b20484dabdf67a326363", "MIT"),
    "tv": ("tavily-ai/tavily-mcp", "1c1d54c2a619afe52544f775c8d82a56ac6d8bb5", "MIT"),
    "c7": ("upstash/context7", "e275a848a420e0d11c2822f61201ee005bfd1133", "MIT"),
    "exa": ("exa-labs/exa-mcp-server", "f3d71fb6b0ff4b4683f108f05bc2bae61a9f7e97", "MIT"),
    "oh": ("OpenHands/OpenHands", "7fbb48c40679afd674970966b96185657d92a487", "MIT (outside enterprise/)"),
    "swe": ("SWE-agent/SWE-agent", "3ea751c087f32b16e039a2233dd6eefecef325d5", "MIT"),
    "con": ("continuedev/continue", "5522c6f44ca0ac3528b37244818fbfa39b5af470", "Apache-2.0"),
    "ocb": ("openai/openai-cookbook", "5986832a554169dc87285b1b0b396941f235a62e", "MIT"),
    "ccb": ("anthropics/claude-cookbooks", "813fbeec03cdedfda7808529438d1c7af71f26eb", "MIT"),
    "lcc": ("langchain-ai/langchain-community", "f425a3ed1933173fb3694b81359d1519c4f82d36", "MIT"),
    "li": ("run-llama/llama_index", "cf8311c42dfe57bcd6bf106424481c808307ee61", "MIT"),
    "oag": ("openai/openai-agents-python", "265f16fa369df61c0074a08dcb1af644cfd00303", "MIT"),
}


def read(name):
    with open(os.path.join(RAW, name), encoding="utf-8") as f:
        return f.read()


def fn(name, description, parameters):
    """An OpenAI chat tool."""
    f = {"name": name}
    if description is not None:
        f["description"] = description
    if parameters is not None:
        f["parameters"] = parameters
    return {"type": "function", "function": f}


def from_mcp(t):
    """An MCP tool as an MCP client hands it to an OpenAI-compatible model:
    name, description and inputSchema as the parameters (the OpenAI Agents SDK,
    LangChain's MCP adapters and most hosts do this). title, annotations,
    outputSchema and _meta are for the host, not the model, and are dropped."""
    return fn(t["name"], t.get("description"), t.get("inputSchema") or {"type": "object", "properties": {}})


# -- TypeScript ---------------------------------------------------------------

def ts_registered(src, env, helpers=None, call=r"\bregisterTool\("):
    """McpServer.registerTool(name, { description, inputSchema, ... }, handler)."""
    out = []
    for m in re.finditer(call, src):
        name, cfg = J.call_args_at(src, m.start(), env, helpers, limit=2)
        out.append({"name": name, "description": cfg.get("description"),
                    "inputSchema": J.input_schema(cfg.get("inputSchema", {}))})
    return out


def ts_tool_calls(src, env, helpers=None):
    """McpServer.tool(name, description, shape, annotations, handler)."""
    out = []
    for m in re.finditer(r"\bserver\.tool\(", src):
        name, desc, shape = J.call_args_at(src, m.start(), env, helpers, limit=3)
        out.append({"name": name, "description": desc, "inputSchema": J.input_schema(shape)})
    return out


def ts_listed(src, env):
    """The list a Server's ListToolsRequestSchema handler returns: the value
    of the first `tools:` key or `tools =` declaration in it (comments are
    skipped by the tokenizer)."""
    i = src.index("setRequestHandler(ListToolsRequestSchema")
    toks = J.tokens(src, i)
    prev = None
    for t in toks:
        if prev is not None and prev.kind == "id" and prev.val == "tools":
            if t.kind == "p" and t.val == ":":
                nxt = next(toks)
                if nxt.kind == "id" and nxt.val == "Tool":   # `const tools: Tool[] = [...]`
                    for t2 in toks:
                        if t2.kind == "p" and t2.val == "=":
                            break
                    return J.literal_at(src, t2.pos + 1, env)
                return J.literal_at(src, nxt.pos, env)
            if t.kind == "p" and t.val == "=":
                return J.literal_at(src, t.pos + 1, env)
        prev = t
    raise ValueError("no tools list")


def cut_subst(src, marker, value):
    """Replaces the template substitution ${...} that starts with `marker` by
    the text `value` (what it evaluates to for the value chosen)."""
    i = src.index("${" + marker)
    depth, j = 1, i + 2
    while depth:
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
        j += 1
    return src[:i] + value.replace("\\", "\\\\").replace("`", "\\`") + src[j:]


# -- Python ---------------------------------------------------------------------

def py_listed(src, within, env=None, calls=None):
    """The Tool(...) calls in an MCP Server's list_tools handler."""
    return P.Module(src, env=env, calls=calls).calls_named("Tool", within=within)


def class_attrs(mod, cls):
    """The annotated class attributes of `cls` (name, description, ...)."""
    out = {}
    for node in mod.tree.body:
        if isinstance(node, ast.ClassDef) and node.name == cls:
            for st in node.body:
                if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
                    try:
                        out[st.target.id] = mod.ev(st.value)
                    except P.Unknown:
                        out[st.target.id] = ast.unparse(st.value)
            return out
    raise KeyError(cls)


def rm_titles(schema):
    """langchain_core's _rm_titles: property titles go, a property named
    "title" stays."""
    out = {}
    for k, v in schema.items():
        if k == "properties" and isinstance(v, dict):
            out[k] = {pk: rm_titles(pv) if isinstance(pv, dict) else pv for pk, pv in v.items()}
        elif k == "title" and isinstance(v, str):
            continue
        elif isinstance(v, dict):
            out[k] = rm_titles(v)
        else:
            out[k] = v
    return out


def langchain_tool(mod, cls, schema=None):
    """convert_to_openai_tool(BaseTool): the args schema without its title and
    description, property titles removed; the tool's own description."""
    a = class_attrs(mod, cls)
    if schema is None:
        schema = mod.model_schema(a["args_schema"].replace("Type[BaseModel] = ", ""))
    s = dict(schema)
    s.pop("title", None)
    s.pop("description", None)
    return fn(a["name"], a["description"], rm_titles(s))


def notebook_cells(name):
    nb = json.loads(read(name))
    return ["".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "code"]


def cell_value(name, var):
    """The value a notebook cell assigns to `var`."""
    for src in notebook_cells(name):
        if re.search(r"^%s\s*=" % re.escape(var), src, re.M):
            return P.Module(src).env[var]
    raise KeyError(var)


# -- the sets -----------------------------------------------------------------

def mcp_ts(file):
    src = read(file)
    return [from_mcp(t) for t in ts_registered(src, J.env_of(src))]


def s_filesystem():
    return mcp_ts("mcp_filesystem.ts"), ""


def s_memory():
    return mcp_ts("mcp_memory.ts"), ""


def s_sequentialthinking():
    return mcp_ts("mcp_sequentialthinking.ts"), ""


def s_fetch():
    return [from_mcp(t) for t in py_listed(read("mcp_fetch.py"), "list_tools")], ""


def s_git():
    return [from_mcp(t) for t in py_listed(read("mcp_git.py"), "list_tools")], ""


def s_time():
    tools = py_listed(read("mcp_time.py"), "list_tools", env={"local_tz": "UTC"})
    return [from_mcp(t) for t in tools], "local_tz (the server machine's zone) = UTC"


def archived(file):
    def build():
        src = read(file)
        if file.endswith(".py"):
            tools = py_listed(src, "handle_list_tools")
        else:
            tools = ts_listed(src, J.env_of(src))
        return [from_mcp(t) for t in tools], ""
    return build


def s_github():
    readme = read("ghmcp_README.md")
    tools = []
    for f in sorted(os.listdir(RAW)):
        if f.startswith("ghmcp_") and f.endswith(".snap"):
            t = json.loads(read(f))
            assert "`" + t["name"] + "`" in readme or ("**" + t["name"] + "**") in readme, t["name"]
            tools.append(from_mcp(t))
    return tools, ("the default toolsets (context, repos, issues, pull_requests, users): the server's "
                   "own tool snapshots (pkg/github/__toolsnaps__), sorted by name")


def s_playwright():
    src = read("playwright_README.md")
    a = src.index("<summary><b>Core automation</b></summary>")
    b = src.index("</details>", a)
    tools = []
    for block in re.split(r"\n(?=- \*\*)", src[a:b])[1:]:
        name = re.match(r"- \*\*([\w-]+)\*\*", block).group(1)
        desc = re.search(r"\n  - Description: (.*)", block).group(1)
        props, req = {}, []
        for pm in re.finditer(r"\n    - `([^`]+)` \(([\w]+)(, optional)?\): (.*)", block):
            props[pm.group(1)] = {"type": pm.group(2), "description": pm.group(4)}
            if not pm.group(3):
                req.append(pm.group(1))
        params = {"type": "object", "properties": props}
        if req:
            params["required"] = req
        tools.append(fn(name, desc, params))
    return tools, ("the default (core automation) tools, rebuilt from the README's generated tool "
                   "reference: names, descriptions, parameter names, types and descriptions; enums "
                   "and array item types are not in it")


def s_firecrawl():
    src = read("firecrawl_v1.12.0.ts")
    return [from_mcp(t) for t in ts_listed(src, J.env_of(src))], "v1.12.0"


def s_tavily():
    src = read("tavily.ts")
    return [from_mcp(t) for t in ts_listed(src, J.env_of(src))], ""


def s_context7():
    src = read("context7.ts")
    env = J.env_of(read("context7_tool-names.ts"))
    env = J.env_of(src, env=env)
    return [from_mcp(t) for t in ts_registered(src, env)], ""


def s_exa():
    helpers = {"lenientString": "string", "lenientOptionalNumber": "number?",
               "lenientOptionalPositiveNumber": "number?"}
    tools = []
    for f, default in (("exa_webSearch.ts", "web_search_exa"), ("exa_webFetch.ts", "web_fetch_exa")):
        src = read(f).replace('toolName || "%s"' % default, '"%s"' % default)
        tools += [from_mcp(t) for t in ts_tool_calls(src, J.env_of(src, helpers), helpers)]
    return tools, ("the two tools the server enables by default (web_search_exa, web_fetch_exa); the "
                   "lenient* helpers (src/tools/validation.ts, not fetched) read as a string, an "
                   "optional number and an optional number")


def s_openhands():
    names = P.Module(read("openhands_tool_names.py")).env
    names.update(P.Module(read("openhands_security_utils.py")).env)
    calls = {"_get_workspace_mount_path_from_env": lambda a, k: "/workspace"}
    agent = read("openhands_codeact_agent.py")
    for flag in ("enable_cmd", "enable_think", "enable_finish", "enable_browsing", "enable_jupyter",
                 "enable_plan_mode", "enable_editor"):
        assert "self.config." + flag in agent, flag
        assert re.search(flag + r": bool = Field\(default=True\)", read("openhands_agent_config.py")), flag

    def mod(f):
        return P.Module(read(f), env=names, calls=calls)

    tools = [
        mod("openhands_bash.py").calls_named("ChatCompletionToolParam", within="create_cmd_run_tool")[0],
        mod("openhands_think.py").env["ThinkTool"],
        mod("openhands_finish.py").env["FinishTool"],
        mod("openhands_browser.py").env["BrowserTool"],
        mod("openhands_ipython.py").env["IPythonTool"],
        mod("openhands_task_tracker.py").calls_named("ChatCompletionToolParam", within="create_task_tracker_tool")[0],
        mod("openhands_str_replace_editor.py").calls_named("ChatCompletionToolParam",
                                                           within="create_str_replace_editor_tool")[0],
    ]
    return tools, ("CodeActAgent._get_tools with the AgentConfig defaults, in its order, long "
                   "descriptions (a model outside gpt-4/o1/o3/o4), Linux, the docker runtime's /workspace")


def swe_tool(name, docstring, arguments):
    """sweagent Command.get_function_calling_tool."""
    t = fn(name, docstring or "", None)
    props, req = {}, []
    for a in arguments or []:
        props[a["name"]] = {"type": a["type"], "description": a["description"]}
        if a.get("items"):
            props[a["name"]]["items"] = a["items"]
        if a["required"]:
            req.append(a["name"])
        if a.get("enum"):
            props[a["name"]]["enum"] = a["enum"]
    t["function"]["parameters"] = {"type": "object", "properties": props, "required": req} if props else {"type": "object"}
    return t


def s_sweagent():
    cfg = yaml.safe_load(read("swe_default.yaml"))
    bundles = [b["path"] for b in cfg["agent"]["tools"]["bundles"]]
    assert bundles == ["tools/registry", "tools/edit_anthropic", "tools/review_on_submit_m"], bundles
    assert cfg["agent"]["tools"]["enable_bash_tool"] is True
    tools = []
    for b in bundles:
        conf = yaml.safe_load(read("swe_" + b.split("/")[1] + ".yaml")) or {}
        for name, c in (conf.get("tools") or {}).items():
            tools.append(swe_tool(name, c.get("docstring"), c.get("arguments")))
    # the default bash tool (sweagent/tools/commands.py BASH_COMMAND)
    mod = P.Module(read("swe_commands.py"), calls={"Command": lambda a, k: k, "Argument": lambda a, k: k})
    bash = mod.env["BASH_COMMAND"]
    tools.append(swe_tool(bash["name"], bash["docstring"], bash["arguments"]))
    return tools, "config/default.yaml: its three bundles, then the bash tool"


CONTINUE = [  # core/tools/index.ts, agent mode, a recommended agent model, not remote, no experimental tools
    ("readFile", "readFileTool"), ("createNewFile", "createNewFileTool"),
    ("runTerminalCommand", "runTerminalCommandTool"), ("globSearch", "globSearchTool"),
    ("viewDiff", "viewDiffTool"), ("readCurrentlyOpenFile", "readCurrentlyOpenFileTool"), ("ls", "lsTool"),
    ("createRuleBlock", "createRuleBlock"), ("fetchUrlContent", "fetchUrlContentTool"),
    ("requestRule", "requestRuleTool"), ("readSkill", "readSkillTool"), ("searchWeb", "searchWebTool"),
    ("multiEdit", "multiEditTool"), ("grepSearch", "grepSearchTool"),
]


def s_continue():
    index = read("continue_tools_index.ts")
    for _, var in CONTINUE:
        assert "toolDefinitions." + var in index, var
    base = J.env_of(read("continue_builtIn.ts"))
    base.update({k: v for k, v in J.env_of(read("continue_editFile.ts")).items()
                 if k == "NO_PARALLEL_TOOL_CALLING_INSTRUCTION"})
    base["PLATFORM_INFO"] = "Choose terminal commands and scripts optimized for darwin and arm64 and shell /bin/zsh."
    tools = []
    for f, _ in CONTINUE:
        src = read("continue_%s.ts" % f)
        if f == "requestRule":
            # getRequestRuleDescription([]): no agent-requested rules
            src = src.replace("getRequestRuleDescription(rules)", json.dumps(
                "Use this tool to retrieve additional 'rules' that contain more context/instructions based on "
                "their descriptions. Available rules:\nNo rules available."))
        if f == "readSkill":
            src = cut_subst(src, "skills.map(", "")   # no skills: [].map(...) is ""
        env = J.env_of(src, env=dict(base))
        i = src.index("function: {")
        tools.append({"type": "function", "function": J.literal_at(src, i + len("function: "), env)})
    return tools, ("core/tools/index.ts in agent mode for a recommended agent model, local, experimental "
                   "tools off, no rules and no skills; macOS arm64 zsh in the terminal tool")


def s_cookbook_weather():
    return cell_value("cookbook_How_to_call_functions_with_chat_models.ipynb", "tools"), \
        "the first tools list (weather); the notebook's second one embeds a database schema read at run time"


def s_cookbook_customer_service():
    return cell_value("cookbook_Using_tool_required_for_customer_service.ipynb", "tools"), ""


def s_cookbook_places():
    for src in notebook_cells("cookbook_Function_calling_finding_nearby_places.ipynb"):
        if "tools=[" in src:
            mod = P.Module(src)
            for n in ast.walk(mod.tree):
                if isinstance(n, ast.Call):
                    for k in n.keywords:
                        if k.arg == "tools":
                            return mod.ev(k.value), "the tools argument of the chat call, as written (a 'result' key included)"
    raise KeyError("tools")


def s_cookbook_arxiv():
    funcs = cell_value("cookbook_How_to_call_functions_for_knowledge_retrieval.ipynb", "arxiv_functions")
    return [{"type": "function", "function": f} for f in funcs], "legacy `functions`, sent here as `tools`"


def s_claude_customer_service():
    tools = cell_value("claude_customer_service_agent.ipynb", "tools")
    return [fn(t["name"], t["description"], t["input_schema"]) for t in tools], \
        "Anthropic tools (input_schema), sent here as OpenAI tools (parameters)"


def s_langchain_files():
    tools = []
    for f, cls in (("copy", "CopyFileTool"), ("delete", "DeleteFileTool"), ("file_search", "FileSearchTool"),
                   ("move", "MoveFileTool"), ("read", "ReadFileTool"), ("write", "WriteFileTool"),
                   ("list_dir", "ListDirectoryTool")):
        mod = P.Module(read("langchain_fm_%s.py" % f))
        a = class_attrs(mod, cls)
        schema_cls = next(n.name for n in mod.classes() if n.name.endswith("Input"))
        tools.append(langchain_tool(mod, cls, mod.model_schema(schema_cls)))
        assert a["name"] == tools[-1]["function"]["name"]
    return tools, "FileManagementToolkit's tools in its order, through convert_to_openai_tool"


def s_langchain_requests():
    mod = P.Module(read("langchain_requests.py"))
    tools = []
    for cls, arg in (("RequestsGetTool", "url"), ("RequestsPostTool", "text"), ("RequestsPatchTool", "text"),
                     ("RequestsPutTool", "text"), ("RequestsDeleteTool", "url")):
        run = next(f for f in ast.walk(next(c for c in mod.classes() if c.name == cls))
                   if isinstance(f, ast.FunctionDef) and f.name == "_run")
        assert run.args.args[1].arg == arg, (cls, run.args.args[1].arg)
        schema = {"properties": {arg: {"title": arg.title(), "type": "string"}}, "required": [arg], "type": "object"}
        tools.append(langchain_tool(mod, cls, schema))
    return tools, "RequestsToolkit's five tools; their args schema is inferred from _run(self, <arg>: str)"


def s_llamaindex_gmail():
    mod = P.Module(read("llama_gmail.py"))
    spec = next(c for c in mod.classes() if c.name == "GmailToolSpec")
    names = next(mod.ev(st.value) for st in spec.body
                 if isinstance(st, ast.Assign) and st.targets[0].id == "spec_functions")
    tools = []
    for name in names:
        f = next(n for n in spec.body if isinstance(n, ast.FunctionDef) and n.name == name)
        args = f.args.args[1:]
        defaults = [None] * (len(args) - len(f.args.defaults)) + list(f.args.defaults)
        sig, props, req = [], {}, []
        for a, d in zip(args, defaults):
            ann = ast.unparse(a.annotation) if a.annotation is not None else None
            sig.append(a.arg + (": " + ann if ann else "") + (" = " + ast.unparse(d) if d is not None else ""))
            p = {"title": P.title_of(a.arg)}
            m = re.fullmatch(r"Optional\[(.+)\]", ann or "")
            inner = m.group(1) if m else ann
            js = {"str": {"type": "string"}, "int": {"type": "integer"},
                  "List[str]": {"type": "array", "items": {"type": "string"}}}[inner]
            if m:
                p["anyOf"] = [js, {"type": "null"}]
            else:
                p.update(js)
            if d is not None:
                p["default"] = mod.ev(d)
            else:
                req.append(a.arg)
            props[a.arg] = p
        ret = " -> " + ast.unparse(f.returns) if f.returns is not None else ""
        doc = f.body[0].value.value if (f.body and isinstance(f.body[0], ast.Expr)
                                        and isinstance(f.body[0].value, ast.Constant)) else ""
        params = {"properties": props, "type": "object"}
        if req:
            params["required"] = req
        tools.append(fn(name, "%s(%s)%s\n%s" % (name, ", ".join(sig), ret, doc), params))
    return tools, ("GmailToolSpec.to_tool_list(): description = name + signature + docstring; the "
                   "signature is rendered from the source, so types may lack the module prefixes "
                   "inspect.signature would print")


def s_agents_triage():
    hand = read("agents_handoffs.py")
    assert 'f"Handoff to the {agent.name} agent to handle the request. "' in hand
    assert "f\"{agent.handoff_description or ''}\"" in hand
    strict = read("agents_strict_schema.py")
    empty = {"additionalProperties": False, "type": "object", "properties": {}, "required": []}
    assert '_EMPTY_SCHEMA = {\n    "additionalProperties": False,\n    "type": "object",\n    "properties": {},\n    "required": [],\n}' in strict
    tree = ast.parse(read("agents_customer_service.py"))
    agents = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and \
                ast.unparse(node.value.func).startswith("Agent"):
            kw = {k.arg: k.value for k in node.value.keywords}
            agents[node.targets[0].id] = (kw["name"].value, kw["handoff_description"].value, kw.get("handoffs"))
    tools = []
    for h in agents["triage_agent"][2].elts:
        kw = {k.arg: k.value for k in h.keywords}
        name, hdesc, _ = agents[kw["agent"].id]
        tools.append(fn(kw["tool_name_override"].value,
                        "Handoff to the %s agent to handle the request. %s" % (name, hdesc), dict(empty)))
    return tools, "the triage agent's request (the example's entry point): its two handoffs as tools"


SETS = [
    # id, kind, repo key, paths, builder
    ("mcp-filesystem", "mcp-reference", "mcp", ["src/filesystem/index.ts"], s_filesystem),
    ("mcp-fetch", "mcp-reference", "mcp", ["src/fetch/src/mcp_server_fetch/server.py"], s_fetch),
    ("mcp-git", "mcp-reference", "mcp", ["src/git/src/mcp_server_git/server.py"], s_git),
    ("mcp-memory", "mcp-reference", "mcp", ["src/memory/index.ts"], s_memory),
    ("mcp-sequentialthinking", "mcp-reference", "mcp", ["src/sequentialthinking/index.ts"], s_sequentialthinking),
    ("mcp-time", "mcp-reference", "mcp", ["src/time/src/mcp_server_time/server.py"], s_time),
    ("mcp-slack", "mcp-archived", "arch", ["src/slack/index.ts"], archived("arch_slack.ts")),
    ("mcp-puppeteer", "mcp-archived", "arch", ["src/puppeteer/index.ts"], archived("arch_puppeteer.ts")),
    ("mcp-brave-search", "mcp-archived", "arch", ["src/brave-search/index.ts"], archived("arch_brave-search.ts")),
    ("mcp-google-maps", "mcp-archived", "arch", ["src/google-maps/index.ts"], archived("arch_google-maps.ts")),
    ("mcp-redis", "mcp-archived", "arch", ["src/redis/src/index.ts"], archived("arch_redis.ts")),
    ("mcp-sqlite", "mcp-archived", "arch", ["src/sqlite/src/mcp_server_sqlite/server.py"], archived("arch_sqlite.py")),
    ("github-mcp", "mcp-vendor", "ghm", ["pkg/github/__toolsnaps__/*.snap", "README.md"], s_github),
    ("playwright-mcp", "mcp-vendor", "pw", ["README.md"], s_playwright),
    ("firecrawl-mcp", "mcp-vendor", "fc", ["src/index.ts"], s_firecrawl),
    ("tavily-mcp", "mcp-vendor", "tv", ["src/index.ts"], s_tavily),
    ("context7-mcp", "mcp-vendor", "c7", ["packages/mcp/src/index.ts", "packages/mcp/src/lib/tool-names.ts"], s_context7),
    ("exa-mcp", "mcp-vendor", "exa", ["src/tools/webSearch.ts", "src/tools/webFetch.ts"], s_exa),
    ("openhands-codeact", "coding-agent", "oh", ["openhands/agenthub/codeact_agent/tools/",
                                                 "openhands/agenthub/codeact_agent/codeact_agent.py",
                                                 "openhands/core/config/agent_config.py"], s_openhands),
    ("swe-agent", "coding-agent", "swe", ["config/default.yaml", "tools/edit_anthropic/config.yaml",
                                          "tools/review_on_submit_m/config.yaml", "sweagent/tools/commands.py"], s_sweagent),
    ("continue-agent", "coding-agent", "con", ["core/tools/index.ts", "core/tools/builtIn.ts",
                                               "core/tools/definitions/"], s_continue),
    ("cookbook-weather", "app-example", "ocb", ["examples/How_to_call_functions_with_chat_models.ipynb"], s_cookbook_weather),
    ("cookbook-customer-service", "app-example", "ocb",
     ["examples/Using_tool_required_for_customer_service.ipynb"], s_cookbook_customer_service),
    ("cookbook-nearby-places", "app-example", "ocb",
     ["examples/Function_calling_finding_nearby_places.ipynb"], s_cookbook_places),
    ("cookbook-arxiv", "app-example", "ocb",
     ["examples/How_to_call_functions_for_knowledge_retrieval.ipynb"], s_cookbook_arxiv),
    ("claude-cookbook-customer-service", "app-example", "ccb",
     ["tool_use/customer_service_agent.ipynb"], s_claude_customer_service),
    ("openai-agents-triage", "app-example", "oag", ["examples/customer_service/main.py",
                                                    "src/agents/handoffs/__init__.py",
                                                    "src/agents/strict_schema.py"], s_agents_triage),
    ("langchain-file-management", "framework", "lcc",
     ["libs/community/langchain_community/tools/file_management/"], s_langchain_files),
    ("langchain-requests", "framework", "lcc",
     ["libs/community/langchain_community/tools/requests/tool.py"], s_langchain_requests),
    ("llamaindex-gmail", "framework", "li",
     ["llama-index-integrations/tools/llama-index-tools-google/llama_index/tools/google/gmail/base.py"], s_llamaindex_gmail),
]


def main():
    global RAW
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default=RAW)
    ap.add_argument("--out", default="bench/datasets/tools-fp-v1.jsonl")
    a = ap.parse_args()
    RAW = a.raw
    with open(a.out, "w", encoding="utf-8") as w:
        for sid, kind, repo, paths, build in SETS:
            tools, notes = build()
            assert tools and all(t["type"] == "function" and t["function"].get("name") for t in tools), sid
            names = [t["function"]["name"] for t in tools]
            assert len(set(names)) == len(names), (sid, names)
            r, ref, lic = REPOS[repo]
            rec = {
                "id": sid, "kind": kind,
                "source": {"repo": r, "ref": ref, "paths": paths, "license": lic,
                           "urls": ["https://github.com/%s/blob/%s/%s" % (r, ref, p) for p in paths]},
                "n_tools": len(tools), "notes": notes,
                "body": {"model": MODEL, "messages": [{"role": "user", "content": MSG}], "tools": tools},
            }
            w.write(json.dumps(rec, ensure_ascii=False) + "\n")
            print("%-34s %3d tools %7d bytes" % (sid, len(tools), len(json.dumps(tools, ensure_ascii=False))))


if __name__ == "__main__":
    main()
