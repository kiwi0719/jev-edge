"""jev-edge as a LiteLLM proxy guardrail.

LiteLLM proxy is where a lot of LLM traffic actually flows. This guardrail
sends each request's text, in its original structure, to a running jev-edge
(``/_jev/authz``, the same endpoint Envoy and the recipes use) and blocks or
annotates the request with the verdict. No core port, no second set of
thresholds: jev-edge decides, this file only carries the answer.

config.yaml (the file sits next to it; LiteLLM loads ``<file>.<Class>`` from
the config's directory)::

    guardrails:
      - guardrail_name: jev-edge
        litellm_params:
          guardrail: jev_edge_guardrail.JevEdgeGuardrail
          mode: pre_call
          default_on: true

Without ``default_on: true`` LiteLLM runs the hook only for requests and keys
that name the guardrail; a warning is logged at startup. With it, nothing a
request, a key or a team sets (``disable_global_guardrail(s)``,
``opted_out_global_guardrails``) switches it off.

Every setting has an environment variable. LiteLLM 1.81.0 and later also
pass the keys under ``litellm_params`` to the class as keyword arguments,
which win over the environment; older versions pass only ``guardrail_name``,
``event_hook`` and ``default_on``, so there the environment is the only way:

    JEV_EDGE_URL             jev-edge's base URL (required)
    JEV_EDGE_ENFORCE         true (default) | false = monitor: never block
    JEV_EDGE_TIMEOUT         seconds, default 2.0; exceeded = fail open
    JEV_EDGE_PATH            the path jev-edge's L1 sees, default /v1/chat/completions
    JEV_EDGE_MAX_BODY_BYTES  largest body sent, default 1048576 (jev-edge's
                             max_body_bytes and nginx's client_max_body_size)
    JEV_EDGE_EXTRA_FIELDS    comma list of top-level keys also sent, for the
                             paths jev-edge's untrusted.fields names
    JEV_EDGE_UNJUDGED        pass (default) | block: what a request nobody
                             could judge gets

Contract: only an answer carrying ``X-Jev-Verdict`` is trusted. 200 with the
header is a decision; any status >= 400 with the header is a block (whatever
``policy.block_status`` is). An answer without the header below 500 other
than 429 (nginx refusing the request before jev-edge ran: 400, 413, 414, a
404 from something that is not jev-edge) means nobody judged it:
``verdict: skipped``, ``source: adapter``, reason ``unjudgeable: authz
answered <status>``, passed or blocked as ``unjudged`` says. A judge that is
not available (connection refused, timeout, a 5xx or a 429 without the
header) fails open with ``jev_verdict == {"verdict": "error", ...}``,
whatever ``unjudged`` says. Requires ``httpx``, which LiteLLM already
depends on.
"""

from __future__ import annotations

import contextvars
import importlib.util
import json
import logging
import math
import os
import re
import time
from typing import Any, Callable, Optional, Union
from urllib.parse import unquote_plus, urlsplit

import httpx

try:  # LiteLLM is the runtime; tests run without it.
    from litellm.integrations.custom_guardrail import CustomGuardrail  # type: ignore
except ImportError:  # pragma: no cover

    class CustomGuardrail:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            pass


try:
    from fastapi import HTTPException  # type: ignore
except ImportError:  # pragma: no cover
    HTTPException = None  # type: ignore[assignment]

log = logging.getLogger("jev_edge")

HEADER_NAMES = ("x-jev-verdict", "x-jev-score", "x-jev-source", "x-jev-reason", "x-jev-request-id")

MAX_BODY_BYTES = 1048576  # jev-edge's rules.max_body_bytes, nginx's default client_max_body_size
TAIL_BYTES = 65536        # jev-edge's rules.TAIL_BYTES: the tail scanned with the head of a larger body

# Tool definitions, sent first and unchanged: jev-edge judges them on their
# own, apart from the conversation. The Responses API's `text` is one when it
# is an object: its `format` is that API's response_format (a string `text`
# elsewhere is text).
DEFINITION_KEYS = ("tools", "functions", "response_format")
# Top-level keys that carry text, in the order they are sent: the
# conversation last, so the newest turn is in the tail of a body that has to
# be cut. `messages` / `input` keep their structure (roles, content parts,
# tool_result / tool_use blocks, function_call_output items) so jev-edge's
# untrusted judging finds tool results exactly as it does in-line. A system
# prompt (Anthropic's top-level `system`, the Responses API's `instructions`,
# Gemini's `systemInstruction`) is sent as the first `messages` entry, with
# role system: every jev-edge version reads messages[*].content, none reads
# a top-level `instructions`, and not every version reads `system`.
SYSTEM_KEYS = ("system", "instructions")
TEXT_KEYS = ("query", "text", "prompt", "input", "messages")

# Content parts that carry media: only their `type` (and any `text` or
# `content`, which jev-edge would read in-line too) is sent.
MEDIA_PARTS = frozenset({"image_url", "input_image", "image", "input_audio", "audio", "file", "input_file"})
# Keys whose values are media payloads wherever they appear (`bytes`: a
# Bedrock Converse image, document or video source).
MEDIA_KEYS = frozenset({"image_url", "input_audio", "file_data", "inline_data", "inlineData", "bytes"})
# Strings under these keys name structure, not text: a body with nothing else
# is not worth a round trip.
STRUCTURAL_KEYS = frozenset({"role", "type", "id", "call_id", "tool_call_id", "tool_use_id", "name",
                             "media_type", "status", "model", "cache_control"})
# Containers nested deeper than this below a top-level key are dropped.
# jev-edge reads tool definitions and tool-call arguments 1000 levels deep
# (its DEEP_DEPTH, which is cjson's nesting limit: a body nested deeper is one
# its decoder refuses, in-line too). The copy is made without recursion, so
# the depth is not bounded by Python's recursion limit.
MAX_DEPTH = 1000

# ---------------------------------------------------------------------------
# call types (LiteLLM passes the route's call type to async_pre_call_hook,
# sync and async names both seen)
# ---------------------------------------------------------------------------

# Not model input, and not watched by in-line jev-edge either: embeddings,
# moderation, audio, rerank, media generation, and search queries (a vector
# store's or a web search tool's; what they return reaches a model only in a
# later request, which is judged).
SKIP_CALLS = frozenset({
    "embedding", "aembedding", "embeddings",
    "moderation", "amoderation",
    "transcription", "atranscription", "audio_transcription",
    "speech", "aspeech",
    "rerank", "arerank",
    "image_generation", "aimage_generation", "image_edit", "aimage_edit",
    "image_variation", "aimage_variation",
    "video_generation", "avideo_generation", "create_video", "acreate_video",
    "video_remix", "avideo_remix", "video_edit", "avideo_edit", "video_extension", "avideo_extension",
    "vector_store_search", "avector_store_search", "search", "asearch",
})

# Calls whose prompts reach the model without passing through this hook's
# data: nothing to judge, so the request is unjudgeable.
NOT_VISIBLE_CALLS = {
    "create_batch": "the prompts are in the input file",
    "acreate_batch": "the prompts are in the input file",
    # the realtime WebSocket: audio and the session's instructions are never
    # judged; typed text is, one message at a time, through apply_guardrail
    # where LiteLLM calls it (see _ApplyGuardrailBase)
    "_arealtime": "realtime audio and session instructions are not visible to the guardrail",
    "arealtime_calls": "realtime (WebRTC) audio is not visible to the guardrail",
    "_aresponses_websocket": "the socket's messages are not visible to the guardrail",
}

# Pass-through routes. The Bedrock pass-through (/bedrock/..., call type
# allm_passthrough_route) nests the client's body, in Bedrock's own format,
# under `data`, next to LiteLLM's own keys. The generic pass-through
# (/anthropic, /openai, /gemini, /vertex_ai, /vllm, ..., and a config's
# pass_through_endpoints; call type pass_through_endpoint) hands the client's
# body itself with LiteLLM's logging object added, and a WebSocket
# pass-through (Vertex AI Live) an empty dict.
NESTED_PASSTHROUGH_CALLS = frozenset({"allm_passthrough_route", "llm_passthrough_route"})
PASSTHROUGH_CALL = "pass_through_endpoint"
# Keys LiteLLM adds next to a generic pass-through's body (its `metadata` is
# taken out before the body is sent on).
LITELLM_OWN_KEYS = frozenset({"litellm_logging_obj", "litellm_call_id", "proxy_server_request", "secret_fields",
                              "metadata", "litellm_metadata"})

# The routes whose proxy metadata LiteLLM keeps in `litellm_metadata` (their
# API has a `metadata` parameter of its own, which is the client's), from
# litellm.proxy.litellm_pre_call_utils._get_metadata_variable_name.
LITELLM_METADATA_ROUTES = ("thread", "assistant", "batches", "bedrock", "/v1/messages", "responses", "files")


def _thread_message(data: dict) -> dict:
    """add_message: one message, top-level role and content."""
    return {"messages": [{"role": data.get("role") or "user", "content": data.get("content")}]}


def _run(data: dict) -> dict:
    """run_thread: instructions and additional_instructions (system), then
    additional_messages."""
    msgs: list = []
    for key in ("instructions", "additional_instructions"):
        if data.get(key) is not None:
            msgs.append({"role": "system", "content": data[key]})
    extra = data.get("additional_messages")
    if isinstance(extra, list):
        msgs.extend(extra)
    return {"messages": msgs}


def _assistant(data: dict) -> dict:
    """create_assistants: the instructions every run of it starts with."""
    return {"messages": [{"role": "system", "content": data.get("instructions")}]}


_BATCH_SCAN: list = []


def _litellm_scans_batch_files() -> bool:
    """Whether this LiteLLM runs the pre-call guardrails over every line of a
    batch input file after the upload's own hook (litellm 1.99 and later:
    batch_guardrails.scan_batch_input_file). The upload's hook itself only
    sees the file's name, type and size."""
    if not _BATCH_SCAN:
        try:
            found = importlib.util.find_spec("litellm.proxy.openai_files_endpoints.batch_guardrails") is not None
        except Exception:  # no LiteLLM, or no proxy
            found = False
        _BATCH_SCAN.append(found)
    return _BATCH_SCAN[0]


# ---------------------------------------------------------------------------
# the body jev-edge judges
# ---------------------------------------------------------------------------

_DROP = object()


def _clean(node: Any, media: bool = True) -> Any:
    """A JSON-safe copy of `node` to MAX_DEPTH, without media payloads (with
    `media` false, everything JSON can carry is kept). Built with a stack of
    its own, so a client's nesting cannot exhaust Python's recursion limit;
    every container is placed when its parent is copied, so keys and items
    keep their order."""
    stack: list = []

    def start(v: Any, depth: int) -> Any:
        """A scalar as it is sent, an empty container queued to be filled,
        or _DROP."""
        if isinstance(v, str) or v is None or isinstance(v, (bool, int)):
            return v
        if isinstance(v, float):
            return v if math.isfinite(v) else _DROP
        if depth > MAX_DEPTH:
            return _DROP
        if not isinstance(v, (dict, list, tuple)) and callable(getattr(v, "model_dump", None)):
            try:  # a pydantic object LiteLLM put in the request
                v = v.model_dump()
            except Exception:
                return _DROP
        if isinstance(v, dict):
            out: Any = {}
        elif isinstance(v, (list, tuple)):
            out = []
        else:
            return _DROP
        stack.append((v, out, depth))
        return out

    root = start(node, 1)
    while stack:
        src, out, depth = stack.pop()
        if isinstance(out, list):
            for v in src:
                c = start(v, depth + 1)
                if c is not _DROP:
                    out.append(c)
            continue
        t = src.get("type") if media else None
        keep = None
        if t == "base64":  # Anthropic source: the bytes are the payload
            keep = ("type", "media_type")
        elif isinstance(t, str) and t in MEDIA_PARTS:
            keep = ("type", "text", "content")
        for k, v in src.items():
            k = str(k)
            if media and (k in MEDIA_KEYS or (keep is not None and k not in keep)):
                continue
            c = start(v, depth + 1)
            if c is not _DROP:
                out[k] = c
    return root


def _has_text(node: Any) -> bool:
    """Whether any string in `node` is text, not a structural name; without
    recursion, as _clean."""
    stack = [(node, "")]
    while stack:
        n, key = stack.pop()
        if isinstance(n, str):
            if n != "" and key not in STRUCTURAL_KEYS:
                return True
        elif isinstance(n, dict):
            stack.extend((v, k) for k, v in n.items())
        elif isinstance(n, list):
            stack.extend((v, key) for v in n)
    return False


def _system_messages(data: dict) -> list:
    """The request's system prompt as messages: Anthropic's top-level
    `system` (a string or text blocks), the Responses API's `instructions`
    and Gemini's `systemInstruction`, each with role system."""
    msgs: list = []
    for key in SYSTEM_KEYS:
        v = data.get(key)
        if v is not None and v != "":
            msgs.append({"role": "system", "content": v})
    si = data.get("systemInstruction", data.get("system_instruction"))
    if isinstance(si, dict):
        msgs.append({"role": "system", "content": si.get("parts")})
    elif isinstance(si, str):
        msgs.append({"role": "system", "content": si})
    return msgs


def _contents_as_messages(data: dict) -> list:
    """Gemini `contents` (generate_content, pass-through) as messages: each
    part's `text` is read by jev-edge's content-part rule."""
    msgs: list = []
    contents = data.get("contents")
    if isinstance(contents, str):
        contents = [contents]
    if isinstance(contents, list):
        for c in contents:
            if isinstance(c, dict):
                msgs.append({"role": c.get("role") or "user", "content": c.get("parts")})
            elif isinstance(c, str):
                msgs.append({"role": "user", "content": c})
    return msgs


def _top_key(field: str) -> str:
    """The top-level key of a path: documents[*].text -> documents."""
    return re.split(r"[.\[]", field.strip(), maxsplit=1)[0]


def _parse_fields(value: Any) -> tuple:
    if value is None:
        return ()
    items = value.split(",") if isinstance(value, str) else list(value)
    out = []
    for item in items:
        k = _top_key(str(item))
        if k and k not in out:
            out.append(k)
    return tuple(out)


def _is_definition(key: str, value: Any) -> bool:
    return key in DEFINITION_KEYS or (key == "text" and isinstance(value, dict))


# Every top-level key the body is built from (with the extra fields).
READ_KEYS = DEFINITION_KEYS + SYSTEM_KEYS + TEXT_KEYS + ("systemInstruction", "system_instruction", "contents")


def _body_dict(data: dict, extra_fields: tuple = ()) -> Optional[dict]:
    body: dict[str, Any] = {}
    for key in DEFINITION_KEYS + ("text",):
        value = data.get(key)
        if value is not None and _is_definition(key, value):
            c = _clean(value, media=False)
            if c is not _DROP:
                body[key] = c
    system = _system_messages(data)
    convo = data.get("messages")
    if convo is not None and not isinstance(convo, list):
        convo = [convo]
    gemini = _contents_as_messages(data)
    if gemini:
        convo = (convo or []) + gemini
    if system and convo is None:
        # no conversation under `messages` (the Responses API): the system
        # prompt goes first, before the input
        body["messages"] = _clean(system)
    taken = DEFINITION_KEYS + SYSTEM_KEYS + TEXT_KEYS
    for key in tuple(k for k in extra_fields if k not in taken) + TEXT_KEYS:
        value = data.get(key)
        if key == "messages":
            if convo is None:
                continue
            value = system + convo
        if value is None or _is_definition(key, value):
            continue
        c = _clean(value)
        if c is not _DROP:
            body[key] = c
    return body if _has_text(body) else None


# JSON string tokens in compact JSON bytes
_STRING_RE = re.compile(rb'"[^"\\]*(?:\\.[^"\\]*)*"', re.S)
_HEX = frozenset(b"0123456789abcdefABCDEF")


def _odd_backslashes_before(raw: bytes, i: int) -> bool:
    n = 0
    while i - 1 - n >= 0 and raw[i - 1 - n] == 0x5C:
        n += 1
    return n % 2 == 1


def _head_cut(raw: bytes, h: int) -> int:
    """`h` moved back to a UTF-8 character boundary that splits no JSON escape."""
    while h > 0 and 0x80 <= raw[h] < 0xC0:
        h -= 1
    j = h - 1
    while j >= max(0, h - 4) and raw[j] in _HEX:
        j -= 1
    if j >= 1 and raw[j] == ord("u") and h < j + 5 and _odd_backslashes_before(raw, j):
        return j - 1  # inside \uXXXX: cut before its backslash
    if _odd_backslashes_before(raw, h):
        return h - 1  # right after an escape's backslash
    return h


def _tail_cut(raw: bytes, t: int) -> int:
    """`t` moved forward to a UTF-8 character boundary that splits no JSON escape."""
    n = len(raw)
    j = t - 1
    while j >= max(0, t - 4) and raw[j] in _HEX:
        j -= 1
    if j >= 1 and raw[j] == ord("u") and t < j + 5 and _odd_backslashes_before(raw, j):
        t = j + 5  # inside \uXXXX: start after it
    elif t < n and _odd_backslashes_before(raw, t):
        t += 5 if raw[t] == ord("u") else 1  # the escaped character itself
    while t < n and 0x80 <= raw[t] < 0xC0:
        t += 1
    return min(t, n)


MAX_KEY_PREFIX = 64  # a longer key is sent as "text"


def bounded(raw: bytes, limit: int) -> bytes:
    """At most `limit` bytes of the compact JSON body `raw`, as jev-edge scans
    a body past its max_body_bytes: the head and the last TAIL_BYTES (the
    newest content), sent with X-Jev-Body-Partial. jev-edge's partial scanner
    reads the string values that follow a `"key":` it can see, so the join
    keeps that true on both sides of each cut: a string the head cuts is
    closed, and a value the tail starts inside, at, or just before (on its
    key or colon, or on the comma or bracket before an array element) is
    given its key again ("text" when it has none)."""
    tail_len = min(TAIL_BYTES, limit // 2)
    h = _head_cut(raw, limit - tail_len - (2 + MAX_KEY_PREFIX + 4))
    t = _tail_cut(raw, len(raw) - tail_len)
    in_head = False
    prev = cur = None  # the first string token that ends after t, and the one before it
    tokens = _STRING_RE.finditer(raw)
    for m in tokens:
        s, e = m.span()
        if s < h < e:
            in_head = True
        if e > t:
            cur = (s, e)
            break
        prev = (s, e)
    if cur is not None and cur[0] < t and raw[cur[1]:cur[1] + 1] == b":":
        # inside a key: start after it, on its colon, and look at what follows
        t, prev = cur[1], cur
        m = next(tokens, None)
        cur = m.span() if m else None
    prefix = b""
    if cur is not None:
        s, e = cur
        is_key = raw[e:e + 1] == b":"
        keyed = prev is not None and prev[1] == s - 1 and raw[s - 1:s] == b":"
        key = raw[prev[0]:prev[1]] if keyed and prev[1] - prev[0] <= MAX_KEY_PREFIX + 2 else b'"text"'
        if s < t < e:             # inside a value
            prefix = key + b':"'
        elif t == s and keyed:    # at a value's opening quote
            prefix = key + b":"
        elif t == s - 1 and keyed:  # at the colon before a value
            prefix = key
        elif t <= s and not is_key and not keyed:
            # at an array element's opening quote or anywhere in the
            # punctuation before it (`:[`, `,`): an unkeyed string the
            # scanner would not read
            t, prefix = s, b'"text":'
    return raw[:h] + (b'"' if in_head else b"0,") + prefix + raw[t:]


def _setting(value: Any, env: str, default: Any) -> Any:
    if value is not None:
        return value
    raw = os.environ.get(env)
    if raw is not None and raw.strip() != "":
        return raw.strip()
    return default


def _bool(name: str, value: Any) -> bool:
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"jev-edge guardrail: {name} must be true or false, got {value!r}")


def _number(name: str, value: Any, cast: Callable[[Any], Any], minimum: float) -> Any:
    try:
        n = cast(value)
    except (TypeError, ValueError):
        n = None
    if n is None or not math.isfinite(n) or not n >= minimum:
        raise ValueError(f"jev-edge guardrail: {name} must be a number >= {minimum}, got {value!r}")
    return n


def _proxy_path(data: dict) -> Optional[str]:
    """The path of the request as LiteLLM's proxy received it, from the
    proxy_server_request it builds (and overwrites, so a client cannot set
    it); None when the hook was called for something else (a batch line,
    code calling it directly)."""
    psr = data.get("proxy_server_request")
    url = psr.get("url") if isinstance(psr, dict) else None
    if not isinstance(url, str) or not url:
        return None
    try:
        return urlsplit(url).path
    except ValueError:
        return None


def _is_object(value: Any) -> bool:
    """Something no JSON body decodes to: a Python object the proxy put there."""
    return value is not None and not isinstance(value, (dict, list, tuple, str, int, float, bool))


def _metadata_key(data: dict) -> str:
    """Where LiteLLM keeps its own metadata for this request: the bag holding
    the proxy's UserAPIKeyAuth object (`user_api_key_auth`, which no client
    can send: it is not JSON). Without one, by the route, as LiteLLM decides
    it: `litellm_metadata` on the routes whose API has a `metadata`
    parameter (Responses, Anthropic messages, batches, files, assistants,
    and Bedrock on 1.102.1 but not on 1.80.11), `metadata` elsewhere. Either
    way the client's own `metadata` (sent on to the provider) or a
    `litellm_metadata` a client put in a chat request is never taken for the
    proxy's."""
    for key in ("metadata", "litellm_metadata"):
        bag = data.get(key)
        if isinstance(bag, dict) and _is_object(bag.get("user_api_key_auth")):
            return key
    path = _proxy_path(data)
    if path is not None:
        return "litellm_metadata" if any(r in path for r in LITELLM_METADATA_ROUTES) else "metadata"
    return "litellm_metadata" if isinstance(data.get("litellm_metadata"), dict) else "metadata"


# The client address of the proxy request being handled, for work LiteLLM
# does on its behalf without the request's data: a batch file's lines,
# realtime messages. Context-local, so it never crosses requests.
_CLIENT_IP: contextvars.ContextVar = contextvars.ContextVar("jev_edge_client_ip", default=None)


class JevEdgeBlocked(Exception):
    """Raised on a block when FastAPI is not installed (tests)."""

    def __init__(self, status_code: int, detail: Any) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _ApplyGuardrailBase(CustomGuardrail):
    """apply_guardrail, which LiteLLM calls with bare texts: the typed user
    messages and tool outputs of a realtime WebSocket session (LiteLLM's
    realtime bridge; 1.102 does, 1.80 does not) and the
    /guardrails/apply_guardrail test endpoint. It sits here, on a base
    class, and not on JevEdgeGuardrail itself: LiteLLM sends every hook of a
    class whose own ``__dict__`` defines apply_guardrail through its unified
    guardrail (the request flattened to texts, model responses judged too)
    instead of async_pre_call_hook, and realtime skips a guardrail with
    ``use_native_lifecycle_hooks``."""

    async def apply_guardrail(self, inputs: Any, request_data: dict, input_type: Any,
                              logging_obj: Optional[Any] = None) -> Any:
        return await self._judge_texts(inputs, input_type)  # type: ignore[attr-defined]


class JevEdgeGuardrail(_ApplyGuardrailBase):
    def __init__(
        self,
        jev_edge_url: Optional[str] = None,
        enforce: Optional[Union[bool, str]] = None,
        timeout: Optional[Union[float, str]] = None,
        path: Optional[str] = None,
        max_body_bytes: Optional[Union[int, str]] = None,
        extra_fields: Optional[Union[str, list]] = None,
        unjudged: Optional[str] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        url = str(_setting(jev_edge_url, "JEV_EDGE_URL", ""))
        if not url:
            raise ValueError("jev-edge guardrail: set JEV_EDGE_URL (or jev_edge_url)")
        self.base = url.rstrip("/")
        self.enforce = _bool("JEV_EDGE_ENFORCE", _setting(enforce, "JEV_EDGE_ENFORCE", True))
        self.timeout = _number("JEV_EDGE_TIMEOUT", _setting(timeout, "JEV_EDGE_TIMEOUT", 2.0), float, 0.001)
        p = str(_setting(path, "JEV_EDGE_PATH", "/v1/chat/completions"))
        self.path = p if p.startswith("/") else "/" + p
        self.max_body_bytes = _number("JEV_EDGE_MAX_BODY_BYTES",
                                      _setting(max_body_bytes, "JEV_EDGE_MAX_BODY_BYTES", MAX_BODY_BYTES), int, 1024)
        self.extra_fields = _parse_fields(_setting(extra_fields, "JEV_EDGE_EXTRA_FIELDS", None))
        self.unjudged = str(_setting(unjudged, "JEV_EDGE_UNJUDGED", "pass")).lower()
        if self.unjudged not in ("pass", "block"):
            raise ValueError(f"jev-edge guardrail: JEV_EDGE_UNJUDGED must be pass or block, got {self.unjudged!r}")
        self._client = httpx.AsyncClient(timeout=self.timeout, transport=transport)
        log.info("jev-edge guardrail: url=%s enforce=%s timeout=%s path=%s max_body_bytes=%d extra_fields=%s unjudged=%s",
                 self.base, self.enforce, self.timeout, self.path, self.max_body_bytes,
                 ",".join(self.extra_fields) or "-", self.unjudged)
        if "guardrail_name" in kwargs and kwargs.get("default_on") is not True:
            # LiteLLM built it from config.yaml without default_on: true
            log.warning("jev-edge guardrail %s: default_on is not true, so LiteLLM runs it only for requests and keys "
                        "that name it, and a request that leaves it out is never judged; set default_on: true "
                        "under litellm_params to judge every request", kwargs.get("guardrail_name"))

    def uses_apply_guardrail_interface(self) -> bool:
        # apply_guardrail only answers LiteLLM's direct calls (realtime text,
        # the test endpoint); every proxy hook stays async_pre_call_hook
        return False

    # A default_on jev-edge guardrail runs for every request: LiteLLM's
    # per-request switches are all ignored. What LiteLLM reads them from is
    # not the proxy's alone: 1.80 takes `disable_global_guardrail` from the
    # request body and metadata, and the key and team settings from metadata
    # names it never overwrites (`user_api_key_team_metadata`, a bag's
    # `disable_global_guardrails`), which a client can send; and a key's own
    # metadata is often set by whoever holds the key.

    def get_disable_global_guardrail(self, data: dict) -> Optional[bool]:
        """Never switched off for a request, whatever its body, its metadata,
        its key or its team says."""
        return False

    def get_opted_out_global_guardrails_from_metadata(self, data: dict) -> list:
        """No request, key or team opts out of it (recent LiteLLM, 1.102.1
        among them, reads `opted_out_global_guardrails` from key and team
        metadata)."""
        return []

    # ------------------------------------------------------------------
    # request -> the body jev-edge judges
    # ------------------------------------------------------------------

    @staticmethod
    def body_for(data: dict, extra_fields: Any = ()) -> Optional[str]:
        """The request's text as the compact JSON body jev-edge judges, in its
        original structure: the tool definitions (`tools`, `functions`,
        `response_format`, the Responses API's `text` object with its
        `format`) unchanged, the `extra_fields`, `query`, `text`,
        `prompt`, `input` and `messages`, with the system prompt (`system`,
        `instructions`, Gemini's `systemInstruction`) as the first message
        and Gemini `contents` joining `messages`, and media payloads removed.
        None when no value holds any text."""
        body = _body_dict(data, _parse_fields(extra_fields) if extra_fields else ())
        return None if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":"))

    def plan(self, data: dict, call_type: Any) -> tuple:
        """What to do with a call, by call type: ("judge", body or None),
        ("skip", reason) or ("unjudged", reason)."""
        name = str(getattr(call_type, "value", call_type) or "")
        if name in SKIP_CALLS:
            return "skip", f"call type {name} not judged"
        if name in NOT_VISIBLE_CALLS:
            return "unjudged", f"unjudgeable: call type {name}: {NOT_VISIBLE_CALLS[name]}"
        if name in NESTED_PASSTHROUGH_CALLS:
            inner = data.get("data")
            if isinstance(inner, dict):
                provider = data.get("custom_llm_provider") or "provider"
                return self._plan_passthrough(name, inner, f"{provider} body")
            if inner is None or inner in ("", b""):
                return "judge", None
            return "unjudged", f"unjudgeable: call type {name}: the body is not JSON the guardrail reads"
        if name == PASSTHROUGH_CALL:
            if not data:
                # a WebSocket pass-through hands an empty dict: its messages
                # go to the provider without passing through here
                return "unjudged", (f"unjudgeable: call type {name}: "
                                    "a WebSocket pass-through's messages are not visible to the guardrail")
            client = {k: v for k, v in data.items() if k not in LITELLM_OWN_KEYS}
            return self._plan_passthrough(name, client, "body")
        if name in ("create_file", "acreate_file"):
            # LiteLLM passes the file's name, type and size, not its content
            purpose = str(data.get("purpose") or "unknown")
            if purpose == "batch" and _litellm_scans_batch_files():
                return "skip", f"call type {name}: batch file lines are judged one by one as LiteLLM scans them"
            return "unjudged", f"unjudgeable: call type {name}: file purpose {purpose}: content not visible to the guardrail"
        # Thread messages, runs and assistants: no LiteLLM version checked
        # (1.80, 1.102) runs pre-call guardrails on these routes, but if one
        # does, their text is where these read it.
        if name in ("add_message", "a_add_message"):
            data = _thread_message(data)
        elif name in ("run_thread", "arun_thread", "run_thread_stream", "arun_thread_stream"):
            data = _run(data)
        elif name in ("create_assistants", "acreate_assistants"):
            data = _assistant(data)
        return "judge", _body_dict(data, self.extra_fields)

    def _plan_passthrough(self, name: str, body: dict, what: str) -> tuple:
        """A pass-through client's body, in the provider's own format: judged
        like any request's. One with none of the fields the guardrail reads
        (Titan's `inputText`, Cohere's `message`, a batch's `requests`, ...)
        is unjudgeable, not "no text": the format is not one it knows. An
        empty one (a GET) has no text."""
        judged = _body_dict(body, self.extra_fields)
        if judged is not None:
            return "judge", judged
        read = READ_KEYS + self.extra_fields
        if any(body.get(k) is not None for k in read):
            return "judge", None  # the fields it reads, holding no text (an image)
        if any(v is not None for v in body.values()):
            return "unjudged", f"unjudgeable: call type {name}: no field the guardrail reads in the {what}"
        return "judge", None

    @staticmethod
    def client_ip(data: dict) -> Optional[str]:
        """What jev-edge gets as X-Forwarded-For, from what LiteLLM's proxy
        itself recorded (the client can set neither): the request's whole
        X-Forwarded-For chain when it has one, else the proxy's own
        ``requester_ip_address``. The chain wins because with LiteLLM's
        ``use_x_forwarded_for`` on, requester_ip_address is the chain's
        leftmost entry, which is whatever the client sent; jev-edge's
        ``client_ip.trusted_hops`` picks the real hop from the whole chain."""
        psr = data.get("proxy_server_request")
        if not isinstance(psr, dict):
            return None
        headers = psr.get("headers")
        headers = headers if isinstance(headers, dict) else {}
        xff = next((v for k, v in headers.items() if str(k).lower() == "x-forwarded-for"), None)
        chain = ", ".join(p.strip() for p in str(xff).split(",") if p.strip()) if xff else ""
        if chain:
            return chain
        md = data.get(_metadata_key(data))
        ip = md.get("requester_ip_address") if isinstance(md, dict) else None
        return str(ip) if ip else None

    # ------------------------------------------------------------------
    # LiteLLM hooks
    # ------------------------------------------------------------------

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: Any,
    ) -> Optional[Union[Exception, str, dict]]:
        started = time.time()
        name = str(getattr(call_type, "value", call_type) or "")
        if name == PASSTHROUGH_CALL:
            # the data is the client's own body: a proxy_server_request in it
            # is the client's too, and LiteLLM recorded no address
            ip = None
        elif isinstance(data.get("proxy_server_request"), dict):
            ip = self.client_ip(data)
            _CLIENT_IP.set(ip)
        else:  # a batch file's line: the upload's client
            ip = _CLIENT_IP.get()
        kind, arg = self.plan(data, call_type)
        verdict: dict[str, Any]
        if kind == "skip":
            verdict = self._adapter("skipped", arg)
        elif kind == "unjudged":
            verdict = self._unjudged(arg)
        elif arg is None:
            verdict = self._adapter("skipped", "no text")
        else:
            verdict = await self.judge(arg, ip)

        key = _metadata_key(data)
        md = data.get(key)
        if not isinstance(md, dict):
            md = data[key] = {}
        md["jev_verdict"] = verdict
        blocks = verdict.get("action") == "block" and self.enforce
        self._log_verdict(key, md, data, verdict, started, blocks)
        if blocks:
            self._raise(verdict)
        return data

    async def _judge_texts(self, inputs: Any, input_type: Any) -> Any:
        """apply_guardrail: each text judged as a user message; only requests,
        jev-edge judges input."""
        if str(getattr(input_type, "value", input_type)) != "request" or not isinstance(inputs, dict):
            return inputs
        texts = [t for t in (inputs.get("texts") or []) if isinstance(t, str) and t]
        if texts:
            verdict = await self.judge({"messages": [{"role": "user", "content": t} for t in texts]}, _CLIENT_IP.get())
            if verdict.get("action") == "block" and self.enforce:
                self._raise(verdict)
        return inputs

    @staticmethod
    def _raise(verdict: dict) -> None:
        status = int(verdict.get("status") or 403)
        detail = {"error": "request rejected", "jev": verdict}
        if HTTPException is not None:
            raise HTTPException(status_code=status, detail=detail)
        raise JevEdgeBlocked(status, detail)

    def _log_verdict(self, key: str, md: dict, data: dict, verdict: dict, started: float, blocks: bool) -> None:
        """The verdict in LiteLLM's standard guardrail logging too, so it
        reaches callbacks and the spend logs' `guardrail_information`. Handed
        the proxy's own metadata only: LiteLLM 1.80 writes it to a request's
        `metadata` whenever there is one, the client's on the routes that
        send `metadata` on to the provider."""
        add = getattr(self, "add_standard_logging_guardrail_information_to_request_data", None)
        if add is None:
            return
        status = ("guardrail_intervened" if blocks else
                  "guardrail_failed_to_respond" if verdict.get("verdict") == "error" else "success")
        ended = time.time()
        try:
            add(guardrail_json_response=dict(verdict), request_data={key: md, "litellm_logging_obj": data.get("litellm_logging_obj")},
                guardrail_status=status, start_time=started, end_time=ended, duration=ended - started)
        except Exception as e:  # logging never costs a request
            log.debug("jev-edge: guardrail information not logged: %s", e)

    @staticmethod
    def _adapter(verdict: str, reason: str) -> dict[str, Any]:
        return {"verdict": verdict, "score": "0.00", "source": "adapter", "reason": reason, "action": "pass"}

    def _unjudged(self, reason: str) -> dict[str, Any]:
        """Nobody judged the request: skipped, passed or blocked as `unjudged`
        says (keep it equal to jev-edge's policy.unjudgeable)."""
        log.warning("jev-edge: %s (unjudged: %s)", reason, self.unjudged)
        v = self._adapter("skipped", reason)
        if self.unjudged == "block":
            v["action"] = "block"
            v["status"] = 403
        return v

    def encode(self, body: dict) -> tuple:
        """The UTF-8 compact JSON body and whether it had to be cut."""
        raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "replace")
        if len(raw) <= self.max_body_bytes:
            return raw, False
        log.info("jev-edge: body of %d bytes sent as head and tail (%d max)", len(raw), self.max_body_bytes)
        return bounded(raw, self.max_body_bytes), True

    async def judge(self, body: Union[dict, str, bytes], client_ip: Optional[str]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if isinstance(body, dict):
            content, partial = self.encode(body)
        else:
            content = body.encode("utf-8", "replace") if isinstance(body, str) else body
            partial = len(content) > self.max_body_bytes
            if partial:
                content = bounded(content, self.max_body_bytes)
        if partial:
            # jev-edge scans it as the head of a larger body, as it does for
            # Envoy's allow_partial_message; the reason ends in "(window)"
            headers["X-Jev-Body-Partial"] = "1"
        if client_ip:
            headers["X-Forwarded-For"] = client_ip
        try:
            res = await self._client.post(self.base + "/_jev/authz" + self.path, content=content, headers=headers)
        except httpx.HTTPError as e:  # connection refused, timeout, ...
            log.warning("jev-edge unreachable, failing open: %s", e)
            return {"verdict": "error", "score": "0.00", "source": "adapter", "reason": str(e), "action": "pass"}

        if "x-jev-verdict" not in res.headers:
            if res.status_code >= 500 or res.status_code == 429:
                # the judge is not available: the server, or a proxy or rate
                # limiter in front of it, failing or shedding load
                log.warning("jev-edge answered %s without X-Jev-Verdict, failing open", res.status_code)
                return {"verdict": "error", "score": "0.00", "source": "adapter",
                        "reason": f"http {res.status_code}", "action": "pass"}
            # refused before jev-edge ran (413 past client_max_body_size, 400
            # or 431 for headers, 414, a 404 from something else)
            return self._unjudged(f"unjudgeable: authz answered {res.status_code}")
        if res.status_code != 200 and res.status_code < 400:
            log.warning("jev-edge answered %s, failing open", res.status_code)
            return {"verdict": "error", "score": "0.00", "source": "adapter", "reason": f"http {res.status_code}", "action": "pass"}

        v = {k[6:].replace("-", "_"): res.headers.get(k, "") for k in HEADER_NAMES if res.headers.get(k) is not None}
        v.setdefault("score", "0.00")
        v.setdefault("source", "l2")
        if "reason" in v:
            v["reason"] = unquote_plus(v["reason"])
        if res.status_code >= 400:
            v["action"] = "block"
            v["status"] = res.status_code
        else:
            v["action"] = "pass"
        return v

    async def aclose(self) -> None:
        await self._client.aclose()
