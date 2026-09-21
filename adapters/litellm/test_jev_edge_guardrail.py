"""Runs without LiteLLM: the hook is exercised against a fake /_jev/authz."""

import asyncio
import json

import httpx
import pytest

from jev_edge_guardrail import JevEdgeBlocked, JevEdgeGuardrail


def fake_authz(status: int = 200, verdict: str = "safe", score: str = "0.20", reason: str = "injection+0.20"):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["xff"] = request.headers.get("x-forwarded-for")
        seen["body"] = json.loads(request.content)
        headers = {"X-Jev-Verdict": verdict, "X-Jev-Score": score, "X-Jev-Source": "l2", "X-Jev-Reason": reason}
        body = '{"error":"request rejected"}' if status == 403 else ""
        return httpx.Response(status, headers=headers, content=body)

    return httpx.MockTransport(handler), seen


def run(coro):  # noqa: E302
    return asyncio.run(coro)


CHAT = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Please summarise the attached quarterly report."}],
        "metadata": {"requester_ip_address": "203.0.113.7"}}


def test_pass_annotates_and_forwards_ip_and_path():
    transport, seen = fake_authz()
    g = JevEdgeGuardrail(jev_edge_url="http://jev-edge:8080", transport=transport)
    out = run(g.async_pre_call_hook({}, None, dict(CHAT), "completion"))
    assert seen["path"] == "/_jev/authz/v1/chat/completions"
    assert seen["xff"] == "203.0.113.7"
    assert seen["body"] == {"messages": CHAT["messages"]}
    v = out["metadata"]["jev_verdict"]
    assert v["verdict"] == "safe" and v["score"] == "0.20" and v["action"] == "pass"
    assert v["reason"] == "injection 0.20"


def test_block_raises_403():
    transport, _ = fake_authz(status=403, verdict="malicious", score="0.95", reason="injection+0.95")
    g = JevEdgeGuardrail(jev_edge_url="http://jev-edge:8080", transport=transport)
    # fastapi.HTTPException when FastAPI is installed (the LiteLLM runtime), JevEdgeBlocked otherwise
    with pytest.raises(Exception) as ei:
        run(g.async_pre_call_hook({}, None, dict(CHAT), "completion"))
    assert isinstance(ei.value, JevEdgeBlocked) or type(ei.value).__name__ == "HTTPException"
    assert ei.value.status_code == 403
    assert ei.value.detail["jev"]["score"] == "0.95"


def test_monitor_mode_never_blocks():
    transport, _ = fake_authz(status=403, verdict="malicious", score="0.95")
    g = JevEdgeGuardrail(jev_edge_url="http://jev-edge:8080", enforce=False, transport=transport)
    out = run(g.async_pre_call_hook({}, None, dict(CHAT), "completion"))
    assert out["metadata"]["jev_verdict"]["action"] == "block"


def test_unreachable_fails_open():
    def boom(request):
        raise httpx.ConnectError("refused")

    g = JevEdgeGuardrail(jev_edge_url="http://jev-edge:8080", transport=httpx.MockTransport(boom))
    out = run(g.async_pre_call_hook({}, None, dict(CHAT), "completion"))
    v = out["metadata"]["jev_verdict"]
    assert v["verdict"] == "error" and v["action"] == "pass"


def test_5xx_fails_open():
    transport, _ = fake_authz(status=502)
    g = JevEdgeGuardrail(jev_edge_url="http://jev-edge:8080", transport=transport)
    out = run(g.async_pre_call_hook({}, None, dict(CHAT), "completion"))
    assert out["metadata"]["jev_verdict"]["verdict"] == "error"


def test_completion_prompt_and_multimodal_text_parts():
    assert json.loads(JevEdgeGuardrail.body_for({"prompt": "hello there"})) == {"prompt": "hello there"}
    body = JevEdgeGuardrail.body_for({"messages": [{"role": "user", "content": [{"type": "text", "text": "a"}, {"type": "image_url", "image_url": {}}]}]})
    assert json.loads(body) == {"messages": [{"role": "user", "content": "a"}]}
    assert JevEdgeGuardrail.body_for({"messages": [{"role": "user", "content": None}]}) is None


def test_no_text_is_skipped_without_a_call():
    calls = []
    transport = httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200))
    g = JevEdgeGuardrail(jev_edge_url="http://jev-edge:8080", transport=transport)
    out = run(g.async_pre_call_hook({}, None, {"model": "x"}, "completion"))
    assert calls == []
    assert out["metadata"]["jev_verdict"]["verdict"] == "skipped"


def test_url_from_env(monkeypatch):
    monkeypatch.setenv("JEV_EDGE_URL", "http://env-host:8080/")
    g = JevEdgeGuardrail(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    assert g.base == "http://env-host:8080"
    monkeypatch.delenv("JEV_EDGE_URL")
    with pytest.raises(ValueError):
        JevEdgeGuardrail()
