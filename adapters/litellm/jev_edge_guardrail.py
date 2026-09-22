"""jev-edge as a LiteLLM proxy guardrail.

LiteLLM proxy is where a lot of LLM traffic actually flows. This guardrail
sends each request's messages to a running jev-edge (``/_jev/authz``, the same
endpoint Envoy and the recipes use) and blocks or annotates the request with
the verdict. No core port, no second set of thresholds: jev-edge decides,
this file only carries the answer.

config.yaml::

    guardrails:
      - guardrail_name: jev-edge
        litellm_params:
          guardrail: jev_edge_guardrail.JevEdgeGuardrail
          mode: pre_call
          jev_edge_url: http://jev-edge:8080      # or env JEV_EDGE_URL
          # optional
          enforce: true          # false = monitor: never block, only annotate
          timeout: 2.0           # seconds; exceeded = fail open
          path: /v1/chat/completions   # what jev-edge's L1 sees as the path

Contract: only an answer carrying ``X-Jev-Verdict`` is trusted. 200 with the
header is a decision; any status >= 400 with the header is a block (whatever
``policy.block_status`` is); anything else, and any error reaching jev-edge
(connection refused, timeout, a 5xx from something that is not jev-edge),
fails open: the request goes through with
``metadata.jev_verdict == {"verdict": "error", ...}``.

Put ``adapters/litellm`` on ``PYTHONPATH`` (or copy this file next to your
config). Requires ``httpx``, which LiteLLM already depends on.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional, Union
from urllib.parse import unquote_plus

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


class JevEdgeBlocked(Exception):
    """Raised on a block when FastAPI is not installed (tests)."""

    def __init__(self, status_code: int, detail: Any) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class JevEdgeGuardrail(CustomGuardrail):
    def __init__(
        self,
        jev_edge_url: Optional[str] = None,
        enforce: bool = True,
        timeout: float = 2.0,
        path: str = "/v1/chat/completions",
        transport: Optional[httpx.AsyncBaseTransport] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        url = jev_edge_url or os.environ.get("JEV_EDGE_URL", "")
        if not url:
            raise ValueError("jev-edge guardrail: set jev_edge_url or JEV_EDGE_URL")
        self.base = url.rstrip("/")
        self.enforce = bool(enforce)
        self.timeout = float(timeout)
        self.path = path if path.startswith("/") else "/" + path
        self._client = httpx.AsyncClient(timeout=self.timeout, transport=transport)

    # ------------------------------------------------------------------
    # request -> the body jev-edge judges
    # ------------------------------------------------------------------

    @staticmethod
    def _collect(node: Any, out: list, depth: int = 1) -> None:
        """Every string under a content value, the way core's extractor reads
        it (core/normalize.lua `collect`): plain strings, each part's `text`
        (chat `text`, Responses `input_text`), and `content` nested once more
        (Anthropic `tool_result`), to a bounded depth. Images and numbers add
        nothing, so the body stays small and under jev-edge's size cap."""
        if isinstance(node, str):
            out.append(node)
            return
        if depth > 4:
            return
        if isinstance(node, list):
            for item in node:
                JevEdgeGuardrail._collect(item, out, depth + 1)
        elif isinstance(node, dict):
            if isinstance(node.get("text"), str):
                out.append(node["text"])
            if node.get("content") is not None:
                JevEdgeGuardrail._collect(node["content"], out, depth + 1)

    @staticmethod
    def body_for(data: dict) -> Optional[str]:
        """The text of the request as a small JSON body jev-edge judges:
        chat `messages` (string or content-part contents), and `prompt` /
        `input` (a string, a list of strings, or Responses API input items).
        None when there is no text at all."""
        body: dict[str, Any] = {}
        msgs = data.get("messages")
        if isinstance(msgs, list):
            out = []
            for m in msgs:
                if not isinstance(m, dict):
                    continue
                parts: list = []
                JevEdgeGuardrail._collect(m.get("content"), parts)
                text = "\n".join(p for p in parts if p)
                if text:
                    out.append({"role": m.get("role", "user"), "content": text})
            if out:
                body["messages"] = out
        for key in ("prompt", "input"):
            parts = []
            JevEdgeGuardrail._collect(data.get(key), parts)
            text = "\n".join(p for p in parts if p)
            if text:
                body[key] = text
        return json.dumps(body) if body else None

    @staticmethod
    def client_ip(data: dict) -> Optional[str]:
        """What jev-edge gets as X-Forwarded-For: the request's whole
        X-Forwarded-For chain when it has one, else LiteLLM's
        ``requester_ip_address``. The chain wins because with LiteLLM's
        ``use_x_forwarded_for`` on, requester_ip_address is the chain's
        leftmost entry, which is whatever the client sent; jev-edge's
        ``client_ip.trusted_hops`` picks the real hop from the whole chain."""
        psr = data.get("proxy_server_request") or {}
        headers = psr.get("headers") or {}
        xff = next((v for k, v in headers.items() if str(k).lower() == "x-forwarded-for"), None)
        chain = ", ".join(p.strip() for p in str(xff).split(",") if p.strip()) if xff else ""
        if chain:
            return chain
        md = data.get("metadata") or {}
        ip = md.get("requester_ip_address")
        return str(ip) if ip else None

    # ------------------------------------------------------------------
    # LiteLLM hook
    # ------------------------------------------------------------------

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict,
        call_type: str,
    ) -> Optional[Union[Exception, str, dict]]:
        body = self.body_for(data)
        verdict: dict[str, Any]
        if body is None:
            verdict = {"verdict": "skipped", "score": "0.00", "source": "l1", "reason": "no text"}
        else:
            verdict = await self.judge(body, self.client_ip(data))

        data.setdefault("metadata", {})["jev_verdict"] = verdict

        if verdict.get("action") == "block" and self.enforce:
            status = int(verdict.get("status") or 403)
            detail = {"error": "request rejected", "jev": verdict}
            if HTTPException is not None:
                raise HTTPException(status_code=status, detail=detail)
            raise JevEdgeBlocked(status, detail)
        return data

    async def judge(self, body: str, client_ip: Optional[str]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if client_ip:
            headers["X-Forwarded-For"] = client_ip
        try:
            res = await self._client.post(self.base + "/_jev/authz" + self.path, content=body, headers=headers)
        except httpx.HTTPError as e:  # connection refused, timeout, ...
            log.warning("jev-edge unreachable, failing open: %s", e)
            return {"verdict": "error", "score": "0.00", "source": "adapter", "reason": str(e), "action": "pass"}

        if "x-jev-verdict" not in res.headers or res.status_code not in (200, *range(400, 600)):
            log.warning("jev-edge answered %s%s, failing open", res.status_code,
                        "" if "x-jev-verdict" in res.headers else " without X-Jev-Verdict")
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
