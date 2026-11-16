"""Grounded, read-only OpenStack question answering for the 3K1H Overview.

Uses the SAME read-only OpenStack backend as openstack_readonly_mcp.py, but
calls it in-process, with an allowlisted OpenAI-compatible tool protocol.
No arbitrary commands, no write tools, and no cloud credentials in prompts.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from openstack_readonly_core import lookup_openstack, OpenStackLookupError

MODEL_DEFAULT = os.environ.get("OPENSTACK_QA_MODEL", os.environ.get("QWEN_API_MODEL", "qwen3.6:35b"))
URL_DEFAULT = os.environ.get("QWEN_API_BASE_URL", "http://127.0.0.1:11434/v1")
# Read-only access is restricted to the project configured in the local environment.
PROJECT_ID_DEFAULT = os.environ.get("CTO_OPENSTACK_PROJECT_ID", "")
PROJECT_NAME_DEFAULT = os.environ.get("CTO_OPENSTACK_PROJECT_NAME", "")
TOOL_NAMES = (
    "get_openstack_user",
    "get_openstack_user_roles",
    "get_openstack_server",
    "get_openstack_security_group",
    "get_openstack_project_resources",
)

TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "get_openstack_user",
            "description": "Read live Keystone user details, enabled status. Takes a known user name or ID; do not guess names.",
            "parameters": {
                "type": "object", "properties": {
                    "user_id": {"type": "string", "description": "OpenStack username or user UUID"},
                }, "required": ["user_id"], "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_openstack_user_roles",
            "description": "Read live Keystone role assignments for a named user. A 403 means this reader lacks permission.",
            "parameters": {
                "type": "object", "properties": {
                    "user_id": {"type": "string", "description": "OpenStack username or UUID"},
                    "project_id": {"type": "string", "description": "Optional project UUID; omit for all visible assignments."},
                }, "required": ["user_id"], "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_openstack_server",
            "description": "Read details/state/IP of a specific Nova VM by exact name or UUID. For a VM list use get_openstack_project_resources.",
            "parameters": {
                "type": "object", "properties": {
                    "server_id": {"type": "string", "description": "VM name or VM UUID"},
                }, "required": ["server_id"], "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_openstack_security_group",
            "description": "Read live security group details and ALL ingress/egress rules, including remote_group_id. Use for security group exposure questions; `default` is an available security group name.",
            "parameters": {
                "type": "object", "properties": {
                    "security_group_id": {"type": "string", "description": "Security group name or UUID"},
                }, "required": ["security_group_id"], "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_openstack_project_resources",
            "description": "List currently visible VMs and security groups for the configured project. Use for 'how many VMs', 'VM list', 'project resources', 'security group list' questions. This is NOT an admin-wide cluster health check.",
            "parameters": {
                "type": "object", "properties": {
                    "project_id": {"type": "string", "description": "Project UUID (configured project UUID is supplied in system context)."},
                }, "required": ["project_id"], "additionalProperties": False,
            },
        },
    },
]


def _endpoint() -> str:
    value = os.environ.get("OPENSTACK_QA_URL") or os.environ.get("BASELINE_OLLAMA_URL") or URL_DEFAULT
    value = value.rstrip("/")
    if value.endswith("/chat/completions"):
        return value
    if value.endswith("/v1"):
        return value + "/chat/completions"
    return value + "/v1/chat/completions"


def _model_request(messages: list[dict[str, Any]], *, tools: bool, timeout: int = 120) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": os.environ.get("OPENSTACK_QA_MODEL", MODEL_DEFAULT),
        "messages": messages,
        "stream": False,
        "think": False,
        "options": {"num_predict": 850},
        "temperature": 0,
    }
    if tools:
        body["tools"] = TOOL_SPECS
        body["tool_choice"] = "auto"
    req = urllib.request.Request(
        _endpoint(),
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Qwen API HTTP {exc.code} 오류") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError("Qwen API 연결 실패 또는 응답 시간 초과") from exc
    except (ValueError, KeyError) as exc:
        raise RuntimeError("Qwen API 응답 형식이 올바르지 않습니다.") from exc
    choices = result.get("choices") or []
    if not choices or not isinstance(choices[0].get("message"), dict):
        raise RuntimeError("Qwen API에서 유효한 메시지를 받지 못했습니다.")
    return choices[0]["message"]


def _is_inquiry(question: str) -> bool:
    # Never allow changes through this interface. Read-only questions containing
    # "삭제되었나?" etc can still be answered; actual execution remains allowlisted.
    return bool(question.strip())


def _safe_args(name: str, arguments: Any, *, default_project: str) -> tuple[str, str]:
    if name not in TOOL_NAMES:
        raise OpenStackLookupError("허용되지 않은 조회 도구 요청입니다.")
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except ValueError as exc:
            raise OpenStackLookupError("도구 인자 JSON이 올바르지 않습니다.") from exc
    if not isinstance(arguments, dict):
        raise OpenStackLookupError("도구 인자 형식 오류")
    field = {
        "get_openstack_user": "user_id",
        "get_openstack_user_roles": "user_id",
        "get_openstack_server": "server_id",
        "get_openstack_security_group": "security_group_id",
        "get_openstack_project_resources": "project_id",
    }[name]
    identifier = str(arguments.get(field) or "").strip()
    if name == "get_openstack_project_resources" and not identifier:
        identifier = default_project
    optional_project = str(arguments.get("project_id") or "").strip() if name == "get_openstack_user_roles" else ""
    if not identifier:
        raise OpenStackLookupError(f"조회할 {field}가 지정되지 않았습니다.")
    return identifier, optional_project


def _safe_evidence(name: str, identifier: str, result: dict[str, Any]) -> dict[str, Any]:
    # Never allow huge structured contexts to silently overflow Qwen input.
    text = json.dumps(result, ensure_ascii=False, default=str)
    if len(text) > 18000:
        text = text[:18000] + "... [TRUNCATED: some results omitted]"
    return {"action": name, "identifier": identifier, "data": result, "model_context": text}


def _public_lookup_error(message: str) -> str:
    """Do not send internal Nova API URLs or policy tokens to Qwen or to the UI."""
    low = str(message).lower()
    if "403" in low or "forbidden" in low or "policy doesn't allow" in low:
        return "권한 제한(403): 현재 계정에서 이 정보를 조회할 수 없습니다."
    if "401" in low or "unauthorized" in low:
        return "인증 오류(401): OpenStack 인증 설정을 확인해 주세요."
    if "404" in low or "not found" in low:
        return "조회 대상이 없거나 접근할 수 없습니다(404)."
    if "시간 초과" in low or "timeout" in low:
        return "API 조회 시간이 초과되었습니다."
    if "프로젝트에 한정" in str(message):
        return "조회 범위 제한: 설정된 프로젝트 밖의 정보는 제공할 수 없습니다."
    if "최대 api 조회" in low:
        return "한 번에 조회할 수 있는 정보량을 초과했습니다. 질문을 나누어 주세요."
    return "일부 OpenStack 정보를 확인하지 못했습니다. 조회 대상과 권한을 확인해 주세요."


def _history_summary(history: list[dict[str, str]]) -> str:
    lines = []
    for h in history[-4:]:
        role = str(h.get("role", ""))
        content = str(h.get("content", ""))[:480]
        if role in ("user", "assistant") and content:
            lines.append(f"{role}: {content}")
    return "\n".join(lines)[:1600]


def _fallback_query(question: str, project_id: str) -> tuple[str, str] | None:
    """Fallback only for unambiguous, common informational questions."""
    s = question.lower()
    if any(k in s for k in ("보안그룹", "security group", "security_group")):
        if "default" in s or "기본" in s:
            return "get_openstack_security_group", "default"
        return "get_openstack_project_resources", project_id
    if any(k in s for k in ("가상머신", "vm ", "vm은", "vm이", "vm들", "vm 목록", "인스턴스", "server list", "서버 목록", "프로젝트 자원")):
        return "get_openstack_project_resources", project_id
    if (username := os.environ.get("OPENSTACK_USERNAME", "").casefold()) and username in s.casefold():
        if any(k in s for k in ("권한", "역할", "role")):
            return "get_openstack_user_roles", os.environ.get("OPENSTACK_USERNAME", "")
        return "get_openstack_user", os.environ.get("OPENSTACK_USERNAME", "")
    return None


def answer_openstack_question(question: str, history: list[dict[str, str]] | None = None) -> dict[str, Any]:
    """Answer from live, permitted API data only. No successful tool => no factual answer."""
    started = time.perf_counter()
    question = question.strip()
    if not _is_inquiry(question) or len(question) > 1600:
        raise ValueError("질문을 1~1600자로 입력하세요.")
    project_id = os.environ.get("CTO_OPENSTACK_PROJECT_ID", PROJECT_ID_DEFAULT)
    project_name = os.environ.get("CTO_OPENSTACK_PROJECT_NAME", PROJECT_NAME_DEFAULT)
    messages = [
        {
            "role": "system",
            "content": (
                "너는 OpenStack 환경 상태를 실제 API로 확인하는 읽기 전용 어시스턴트다. "
                "현재 질문은 live OpenStack 조회로만 답한다. "
                "항상 도구를 먼저 호출하고 결과가 없는 사실은 절대로 지어내지 마라. "
                "이 환경의 계정은 설정된 읽기 전용 계정이며 조회 범위는 설정된 프로젝트뿐이다. "
                f"조회 가능한 기본 프로젝트 이름={project_name}, UUID={project_id}. "
                "가상머신 목록/수/프로젝트 자원은 get_openstack_project_resources, "
                "개별 보안그룹의 인바운드/아웃바운드 규칙은 get_openstack_security_group을 사용하라. "
                "다른 프로젝트나 호스트/하이퍼바이저 서비스 전체 상태는 현재 도구로 확인할 수 없다. "
                "보안그룹 외부 개방 판단은 direction=ingress와 remote_ip_prefix, "
                "remote_group_id를 확인하고 egress ::/0나 0.0.0.0/0만으로 인바운드 개방이라 하지 마라. "
                "읽기 전용 조회 도구 5개 외의 도구 사용을 요구하거나 실제 변경을 요청해도 실행하지 말고 안내만 하라. "
                "로그/과거 공격과 현재 리소스 상태는 다른 데이터다. 필요하면 조회 대상을 추가로 물어라. "
                "짧고 명료한 한국어로 답하되, 최신 사실은 실제 도구 결과만 근거로 삼아라."
            ),
        },
    ]
    prior = _history_summary(history or [])
    if prior:
        messages.append({"role": "user", "content": "[이전 질문의 문맥. 여기에 적힌 과거 답변은 현 상태의 증거가 아님]\n" + prior})
    messages.append({"role": "user", "content": question})

    evidence: list[dict[str, Any]] = []
    errors: list[str] = []
    cache: dict[tuple[str, str, str], dict[str, Any]] = {}
    latest_content = ""
    calls = 0

    for round_no in range(3):
        msg = _model_request(messages, tools=True, timeout=125)
        tool_calls = msg.get("tool_calls") or []
        latest_content = str(msg.get("content") or "").strip()
        if not tool_calls:
            break

        messages.append({
            "role": "assistant",
            "content": latest_content,
            "tool_calls": tool_calls,
        })
        for i, tool in enumerate(tool_calls):
            tool_id = tool.get("id") or f"call_{round_no}_{i}"
            fn = tool.get("function") or {}
            name = str(fn.get("name") or "")
            try:
                if calls >= 8:
                    raise OpenStackLookupError("한 질문의 최대 API 조회 횟수(8회)를 초과했습니다.")
                identifier, extra_project = _safe_args(
                    name, fn.get("arguments") or {}, default_project=project_id
                )
                key = (name, identifier, extra_project)
                if key in cache:
                    datum = cache[key]
                else:
                    datum = lookup_openstack(name, identifier, extra_project)
                    cache[key] = datum
                    evidence.append(_safe_evidence(name, identifier, datum))
                    calls += 1
                result_msg: dict[str, Any] = {"ok": True, "result": datum}
            except (OpenStackLookupError, ValueError) as exc:
                public_error = _public_lookup_error(str(exc))
                errors.append(f"{name or '조회 도구'}: {public_error}")
                result_msg = {"ok": False, "error": public_error}
            context = json.dumps(result_msg, ensure_ascii=False, default=str)
            if len(context) > 16000:
                context = context[:16000] + '...[일부 생략]'
            messages.append({
                "role": "tool",
                "tool_call_id": tool_id,
                "name": name or "unrecognized",
                "content": context,
            })

    # If the LLM abstained from tools for an unambiguous intent, execute a
    # allowlisted API lookup ourselves so unsupported model claims are not shown.
    if not evidence and not errors:
        fallback = _fallback_query(question, project_id)
        if fallback:
            name, identifier = fallback
            try:
                datum = lookup_openstack(name, identifier)
                evidence.append(_safe_evidence(name, identifier, datum))
            except OpenStackLookupError as exc:
                errors.append(_public_lookup_error(str(exc)))

    if evidence:
        # Final answer is generated in a tool-free pass to avoid loops.
        # This pass sees only the verified API results, not Hermes/Neo4j claims.
        raw_evidence = [e["model_context"] for e in evidence]
        final_msg = _model_request([
            {"role": "system", "content": (
                "너는 읽기 전용 OpenStack API 증거로만 답하는 분석가다. "
                "주어진 도구 조회 JSON 밖의 구체적 상태를 추측하지 말 것. "
                "조회 실패가 있으면 누락 범위를 밝힐 것. 프로젝트 reader 범위 밖의 전체 클러스터 상태는 모른다고 하라. "
                "현재 상태를 과거 공격 증거라고 말하지 마라. 3~10문장 한국어로 직접 답하라."
            )},
            {"role": "user", "content": (
                f"사용자 질문:\n{question}\n\n실제 조회 결과 JSON:\n"
                + "\n".join(raw_evidence)[:24000]
                + "\n\n조회 오류:\n" + "\n".join(errors)
            )},
        ], tools=False, timeout=125)
        answer = str(final_msg.get("content") or "").strip()
        if not answer:
            answer = "API 조회는 성공했지만 Qwen이 요약 답변을 생성하지 못했습니다. 아래 실제 조회 결과를 확인하세요."
    else:
        answer = (
            "현재 연결된 OpenStack API로 확인할 수 있는 정보가 없습니다. "
            "조회 대상이 구체적인지, 설정된 프로젝트의 reader 권한 범위에 있는지 확인해 주세요."
            if not errors else
            "OpenStack 실제 상태를 조회하지 못했습니다. 조회 오류를 확인해 주세요."
        )

    return {
        "question": question,
        "answer": answer,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "model": os.environ.get("OPENSTACK_QA_MODEL", MODEL_DEFAULT),
        "elapsed_sec": round(time.perf_counter() - started, 1),
        "evidence": [{"action": e["action"], "identifier": e["identifier"], "data": e["data"]} for e in evidence],
        "errors": errors,
        "scope": f"{project_name} 프로젝트 (reader)",
    }
