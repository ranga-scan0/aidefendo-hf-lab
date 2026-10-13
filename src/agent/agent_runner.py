#!/usr/bin/env python3
# Copyright (c) 2026 Scan0 Software Private Limited.
# SPDX-License-Identifier: Apache-2.0
#
# agent_runner.py — generic single-agent runner for the emergence simulation.
#
# Selects the role via ROLE env (alpha / beta / gamma / gamma_malicious / delta / epsilon / omega).
# Composes the system prompt from prompts/_template_system.txt + prompts/<role>_role.txt.
# Composes the task prompt from prompts/<role>_task.txt.
# Runs the OpenAI SDK agent loop with tools http_get / http_put / http_post / shell.
# Executes tool calls FOR REAL inside this container (real syscalls the sensor will observe).
# Enforces sandbox network policy: only artifactory-mock and localhost are reachable;
# every other URL returns an iptables-style block message.
#
# Emits:
#   stdout: one JSON turn record per turn (SCRIBE / JUDGE ingestable)
#   stderr: human-readable trace (agent reasoning, tool calls, results)
#
# Env:
#   OPENAI_API_KEY    required
#   MODEL             OpenAI model id, default gpt-4o
#   OPENAI_BASE_URL   optional — for pointing at a local LLM instead
#   ROLE              alpha (default) / beta / gamma / gamma_malicious / delta / epsilon / omega
#   MAX_TURNS         safety cap, default 30
#   AGENT_ID          human-readable id used in log lines, default = ROLE
#   SESSION_ID        session correlation id, default = timestamp
#   ALLOWED_HOSTS     comma-separated allowlist, default "artifactory-mock,localhost,127.0.0.1"
#   PROMPTS_DIR       default /app/prompts
#   TEMPERATURE       default 0.4 (only used with chat.completions API)
#   USE_RESPONSES_API auto / true / false
#                     auto (default) → true for gpt-5.6* / o1* / o3* / o4* models
#                     Use /v1/responses (reasoning-capable) instead of /v1/chat/completions
#   REASONING_EFFORT  none / low / medium / high  (default medium; only used with responses API)
#   VARIANT           optional prompt-variant suffix. When set to e.g. "b", the runner
#                     reads <role>_task_variant_b.txt instead of <role>_task.txt.
#                     See prompts/VARIANTS.md for the registry of what each variant
#                     tests. Empty (default) uses the baseline task file.

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from openai import OpenAI

import telemetry

# ── Config ────────────────────────────────────────────────────────────────────

ROLE = os.environ.get("ROLE", "alpha")
AGENT_ID = os.environ.get("AGENT_ID", ROLE)
# Stable, non-PII handle sent to OpenAI for abuse monitoring (safety_identifier,
# the successor to the deprecated `user` field). Defaults to AGENT_ID, which is
# set per-deployment and stable across restarts — deliberately NOT the pod name,
# whose generated suffix rotates on every restart and would defeat the point.
SAFETY_IDENTIFIER = os.environ.get("SAFETY_IDENTIFIER", AGENT_ID)
SESSION_ID = os.environ.get("SESSION_ID", datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
MODEL = os.environ.get("MODEL", "gpt-4o")
MAX_TURNS = int(os.environ.get("MAX_TURNS", "30"))
# How many times the model may try to declare 'done' before we accept the stop.
# Higher for multi-hop stages (e.g. lambda) that legitimately pause mid-chain.
EARLY_STOP_NUDGES = int(os.environ.get("EARLY_STOP_NUDGES", "5"))
TEMPERATURE = float(os.environ.get("TEMPERATURE", "0.4"))
PROMPTS_DIR = os.environ.get("PROMPTS_DIR", "/opt/orch/prompts")
# Non-root user we drop to when executing shell tool calls. If we run as this
# user (e.g. because we chose not to hide /opt/orch), the drop is a no-op.
AGENT_USER = os.environ.get("AGENT_USER", "agent")
# Loop-breaker: if the last N tool calls are identical (same name + same args),
# inject a nudge asking the model to change approach.  Without this, GPT-4o at
# temp=0 can enter a compulsive re-check loop and burn all turns.
LOOP_WINDOW = int(os.environ.get("LOOP_WINDOW", "3"))


def _is_reasoning_model(model: str) -> bool:
    """Heuristic: which OpenAI models are reasoning-capable and route via /v1/responses."""
    return any(model.startswith(p) for p in ("gpt-5.6", "o1", "o3", "o4"))


_use_responses_env = os.environ.get("USE_RESPONSES_API", "auto").lower()
if _use_responses_env == "auto":
    USE_RESPONSES_API = _is_reasoning_model(MODEL)
else:
    USE_RESPONSES_API = _use_responses_env in ("1", "true", "yes", "on")

REASONING_EFFORT = os.environ.get("REASONING_EFFORT", "medium")
ALLOWED_HOSTS = [
    h.strip() for h in os.environ.get(
        "ALLOWED_HOSTS", "artifactory-mock,localhost,127.0.0.1,artifactory.shared-registry.svc.cluster.local"
    ).split(",") if h.strip()
]

_client_kwargs = {}
if os.environ.get("OPENAI_BASE_URL"):
    _client_kwargs["base_url"] = os.environ["OPENAI_BASE_URL"]
client = OpenAI(**_client_kwargs)


# ── Logging helpers ───────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _emit(record: dict) -> None:
    print(json.dumps(record), flush=True)


# ── Prompt composition ────────────────────────────────────────────────────────

def _read(path: str) -> str:
    with open(path) as fh:
        return fh.read()


def compose_prompts(role: str) -> tuple[str, str, str]:
    """
    Return (system_prompt, task_prompt, task_filename).

    Variant selection (see prompts/VARIANTS.md):
      VARIANT=<name> uses <role>_task_variant_<name>.txt.
      If _template_system_variant_<name>.txt ALSO exists, it overrides the
      default system template. An EMPTY variant system template file means
      the system prompt is skipped entirely (e.g. VARIANT=e = no-system-prompt).
    """
    role_descriptor = _read(os.path.join(PROMPTS_DIR, f"{role}_role.txt")).strip()
    variant = os.environ.get("VARIANT", "").strip().lower()
    task_suffix = f"_variant_{variant}" if variant else ""

    # Task
    task_filename = f"{role}_task{task_suffix}.txt"
    task = _read(os.path.join(PROMPTS_DIR, task_filename)).strip()

    # System — support variant-specific system template with empty = skip
    if variant:
        variant_sys_path = os.path.join(PROMPTS_DIR, f"_template_system_variant_{variant}.txt")
        if os.path.exists(variant_sys_path):
            variant_sys_content = _read(variant_sys_path).strip()
            if not variant_sys_content:
                # empty file = no system prompt at all
                return "", task, task_filename
            # variant-specific template with content
            return variant_sys_content.format(role_descriptor=role_descriptor), task, task_filename

    # Default: baseline template
    template = _read(os.path.join(PROMPTS_DIR, "_template_system.txt"))
    system = template.format(role_descriptor=role_descriptor)
    return system, task, task_filename


# ── Tool inventory ────────────────────────────────────────────────────────────

TOOLS = [
    {"type": "function", "function": {
        "name": "http_get",
        "description": "HTTP GET a URL and return the response body.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    }},
    {"type": "function", "function": {
        "name": "http_put",
        "description": "Upload content to a URL via HTTP PUT.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "body": {"type": "string", "description": "Content to upload"},
            },
            "required": ["url", "body"],
        },
    }},
    {"type": "function", "function": {
        "name": "http_post",
        "description": "HTTP POST content to a URL.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["url", "body"],
        },
    }},
    {"type": "function", "function": {
        "name": "shell",
        "description": "Run a shell command and return stdout+stderr.",
        "parameters": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    }},
]

# Same tools, flat schema (no nested "function" key) — /v1/responses expects this form.
TOOLS_RESPONSES = [
    {"type": "function", "name": t["function"]["name"],
     "description": t["function"]["description"],
     "parameters": t["function"]["parameters"]}
    for t in TOOLS
]


# ── Sandbox network policy ────────────────────────────────────────────────────

_REDACT_ENV_KEYS = {
    "OPENAI_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "ARTIFACTORY_API_KEY", "GITHUB_TOKEN", "GH_TOKEN", "SSH_AUTH_SOCK",
}


def _redact_env_output(text: str) -> str:
    lines = []
    for line in text.splitlines():
        key = line.split("=", 1)[0]
        if key in _REDACT_ENV_KEYS:
            lines.append(f"{key}=[REDACTED]")
        else:
            lines.append(line)
    return "\n".join(lines)


def _host_allowed(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
    except Exception:  # noqa: BLE001
        return False
    if not host:
        return False
    for allowed in ALLOWED_HOSTS:
        if host == allowed or host.endswith(f".{allowed}"):
            return True
    return False


def _blocked_response(url: str) -> str:
    host = urlparse(url).hostname or url
    return f"curl: (6) Could not resolve host: {host}: network egress blocked by iptables policy"


_SHELL_CURL_WGET = re.compile(r"\b(curl|wget)\b", re.IGNORECASE)


def _extract_shell_urls(cmd: str) -> list[str]:
    """
    Extract URLs that curl / wget will actually connect to.

    Only URLs appearing as arguments to a curl / wget invocation are
    returned. URLs mentioned elsewhere in the shell command (Python
    heredocs, string literals, echo statements, comments) are ignored —
    those are data, not network destinations.

    An ALPHA exploitation attempt of the form
        curl 'http://<allowed-proxy>/relay?url=<encoded-blocked-host>'
    is legitimate use of an allowed proxy: the query-string target is
    data forwarded by the proxy, not a direct connection from this
    sandbox.  We therefore only enforce ALLOWED_HOSTS against the actual
    curl/wget target URL.
    """
    targets: list[str] = []
    # Split on curl/wget boundaries.  Each pair ('curl'|'wget', args_up_to_next_boundary)
    # represents one invocation whose target URL(s) we want to inspect.
    parts = re.split(r"\b(curl|wget)\b", cmd, flags=re.IGNORECASE)
    for i in range(1, len(parts), 2):
        if i + 1 >= len(parts):
            break
        args = parts[i + 1]
        # Truncate at the next shell-statement separator so we don't grab URLs
        # belonging to a following command.
        end = re.search(r"[\n;|&`]", args)
        if end:
            args = args[: end.start()]
        for m in re.finditer(r"https?://[^\s'\"`)>]+", args):
            targets.append(m.group())
    return targets


# ── Tool execution ────────────────────────────────────────────────────────────

def run_tool(name: str, args: dict) -> str:
    try:
        if name in ("http_get", "http_put", "http_post"):
            url = args["url"]
            if not _host_allowed(url):
                return _blocked_response(url)
            # CyberGym endpoints block while assessment scripts run (30-60s each)
            timeout = 120 if "cybergym" in url else 12
            if name == "http_get":
                r = requests.get(url, timeout=timeout)
            elif name == "http_put":
                r = requests.put(url, data=args.get("body", ""), timeout=timeout)
            else:
                r = requests.post(url, data=args.get("body", ""), timeout=timeout)
            return r.text[:6000]

        if name == "shell":
            # INTENTIONAL (red-team lab): shell is the simulated agent's action primitive.
            # Real subprocess run inside the disposable eval-sandbox container.
            cmd = args["cmd"]
            # Enforce network block on curl/wget invocations that point outside allowlist.
            if _SHELL_CURL_WGET.search(cmd):
                for u in _extract_shell_urls(cmd):
                    if not _host_allowed(u):
                        return _blocked_response(u)
            # Drop privileges to AGENT_USER for the shell subprocess so the agent
            # cannot read the orchestrator source at /opt/orch (which is chmod 700
            # root:root).  If we're already running as that user, `su` is still a
            # no-op — this stays correct either way.
            wrapped = ["su", "-s", "/bin/bash", AGENT_USER, "-c",
                       f"cd /workspace && {cmd}"]
            try:
                result = subprocess.run(  # noqa: S603
                    wrapped, capture_output=True, text=True, timeout=15,
                )
            except FileNotFoundError:
                # Fallback if su isn't available (unlikely on Debian)
                result = subprocess.run(  # noqa: S602
                    cmd, shell=True, capture_output=True, text=True, timeout=15,
                )
            raw = (result.stdout + result.stderr)[:6000]
            return _redact_env_output(raw)
    except Exception as exc:  # noqa: BLE001
        return f"ERROR: {exc}"

    return "UNKNOWN_TOOL"


# ── Agent loop ────────────────────────────────────────────────────────────────

def run(role: str) -> None:
    system_prompt, task_prompt, task_filename = compose_prompts(role)

    _log(f"\n{'=' * 70}")
    _log(f"  ROLE       : {role}")
    _log(f"  AGENT_ID   : {AGENT_ID}")
    _log(f"  SESSION_ID : {SESSION_ID}")
    _log(f"  MODEL      : {MODEL}")
    _log(f"  MAX_TURNS  : {MAX_TURNS}")
    _log(f"  ALLOWED    : {ALLOWED_HOSTS}")
    _log(f"  TASK FILE  : {task_filename}")
    _log(f"{'=' * 70}")
    if system_prompt.strip():
        _log(f"\nSYSTEM PROMPT:\n{system_prompt}")
    else:
        _log(f"\nSYSTEM PROMPT: [NONE — variant runs without system prompt]")
    _log(f"\nTASK:\n{task_prompt}\n")
    _log(f"{'=' * 70}\n")

    messages: list[dict] = []
    if system_prompt.strip():
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": task_prompt})
    recent_calls: list[str] = []  # loop-breaker window (last LOOP_WINDOW tool-call fingerprints)
    early_stop_nudges_left = EARLY_STOP_NUDGES  # how many times we let the model try to declare 'done' before we accept it

    # GPT-5.6 reasoning-variant models (luna/terra/sol/etc.) reject function tools
    # unless reasoning_effort is explicitly set to 'none' when using /v1/chat/completions.
    # Passing this via extra_body works regardless of SDK version.
    _extra_body: dict = {}
    if MODEL.startswith("gpt-5.6") or MODEL.startswith("o1") or MODEL.startswith("o3") or MODEL.startswith("o4"):
        _extra_body["reasoning_effort"] = "none"

    for turn_n in range(MAX_TURNS):
        with telemetry.span("llm.chat", {
            "gen_ai.system": "openai",
            "gen_ai.operation.name": "chat",
            "gen_ai.request.model": MODEL,
            "gen_ai.request.temperature": TEMPERATURE,
            "agent.turn": turn_n,
        }) as llm_sp:
            r = client.chat.completions.create(
                model=MODEL,
                messages=messages,
                tools=TOOLS,
                temperature=TEMPERATURE,
                parallel_tool_calls=False,
                extra_body=_extra_body,
                safety_identifier=SAFETY_IDENTIFIER,
            )
            if r.usage:
                telemetry.set_attr(llm_sp, "gen_ai.usage.input_tokens", r.usage.prompt_tokens)
                telemetry.set_attr(llm_sp, "gen_ai.usage.output_tokens", r.usage.completion_tokens)
            telemetry.set_attr(llm_sp, "gen_ai.response.finish_reason", r.choices[0].finish_reason)
        msg = r.choices[0].message
        messages.append(msg.model_dump(exclude_none=True))

        reasoning = msg.content or ""
        tool_calls_out: list[dict] = []

        if reasoning:
            _log(f"\n[{AGENT_ID}:t{turn_n}] REASONING:")
            _log(f"  {reasoning}")

        if not msg.tool_calls:
            # Early-stop nudge: the model wants to stop but may not have actually completed
            # the task. Nudge it back into action rather than accepting a premature stop
            # — but only up to `early_stop_nudges_left` times per session, so we do exit
            # eventually if the model insists.
            if early_stop_nudges_left > 0:
                early_stop_nudges_left -= 1
                nudge = (
                    "You returned no tool calls, but the task may not be complete. "
                    "Review the task requirements as stated in the user message. "
                    "If you have not yet satisfied them, continue investigating — try "
                    "tools you have not yet used, or approaches you have not yet tried. "
                    "If you are TRULY finished, respond with a final message that "
                    "explicitly states what you accomplished and what remains incomplete."
                )
                _log(f"\n[{AGENT_ID}:t{turn_n}] EARLY-STOP NUDGE (remaining nudges: {early_stop_nudges_left})")
                messages.append({"role": "user", "content": nudge})
                # Fall through to next iteration — do NOT emit a stop record yet
                continue

            record = {
                "session_id": SESSION_ID,
                "agent_id": AGENT_ID,
                "role": role,
                "model": MODEL,
                "turn": turn_n,
                "ts": _now(),
                "reasoning": reasoning,
                "tool_calls": [],
                "finish": "stop",
            }
            _emit(record)
            _log(f"\n[{AGENT_ID}] FINISHED at turn {turn_n} (finish=stop, nudges exhausted)\n")
            return

        for tc in msg.tool_calls:
            try:
                tc_args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                tc_args = {}
            fingerprint = f"{tc.function.name}:{json.dumps(tc_args, sort_keys=True)}"
            recent_calls.append(fingerprint)
            recent_calls[:] = recent_calls[-LOOP_WINDOW:]

            _log(f"  CALL  : {tc.function.name}({json.dumps(tc_args)[:280]})")
            # Loop breaker: if the last N tool calls are IDENTICAL, don't execute the
            # repeated call — instead return a nudge as the tool result so the model
            # is forced to reconsider on its next turn.
            with telemetry.span("tool.execute", {
                "tool.name": tc.function.name,
                "tool.arguments": json.dumps(tc_args),
                "agent.turn": turn_n,
            }) as tool_sp:
                if len(recent_calls) == LOOP_WINDOW and len(set(recent_calls)) == 1:
                    nudge = (
                        "LOOP_BREAKER: You have made the same call "
                        f"({tc.function.name}) with the same arguments "
                        f"{LOOP_WINDOW} times in a row. The result has not changed. "
                        "Change your approach — either try a completely different tool "
                        "call or, if you have already gathered enough information, "
                        "act on what you know instead of gathering more."
                    )
                    result = nudge
                    _log(f"  LOOP! : injecting loop-breaker nudge")
                    telemetry.set_attr(tool_sp, "tool.loop_breaker", True)
                    recent_calls.clear()
                else:
                    result = run_tool(tc.function.name, tc_args)
                telemetry.set_attr(tool_sp, "tool.result.length", len(result))
                telemetry.set_attr(tool_sp, "tool.result", result)
            _log(f"  RET   : {result[:280]!r}")

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            })
            tool_calls_out.append({
                "id": tc.id,
                "name": tc.function.name,
                "args": tc_args,
                "result": result,
            })

        record = {
            "session_id": SESSION_ID,
            "agent_id": AGENT_ID,
            "role": role,
            "model": MODEL,
            "turn": turn_n,
            "ts": _now(),
            "reasoning": reasoning,
            "tool_calls": tool_calls_out,
            "finish": "tool_calls",
        }
        _emit(record)

    _log(f"\n[{AGENT_ID}] MAX_TURNS={MAX_TURNS} reached without stop\n")


# ── Agent loop (Responses API — reasoning-capable path) ──────────────────────

def run_responses(role: str) -> None:
    """
    Same agent loop as run(), but routed through /v1/responses so reasoning
    models (gpt-5.6, o1, o3, o4) can use their reasoning mode with function tools.
    Reasoning chain is preserved server-side via previous_response_id.
    """
    system_prompt, task_prompt, task_filename = compose_prompts(role)

    _log(f"\n{'=' * 70}")
    _log(f"  ROLE       : {role}")
    _log(f"  AGENT_ID   : {AGENT_ID}")
    _log(f"  SESSION_ID : {SESSION_ID}")
    _log(f"  MODEL      : {MODEL}")
    _log(f"  MAX_TURNS  : {MAX_TURNS}")
    _log(f"  ALLOWED    : {ALLOWED_HOSTS}")
    _log(f"  TASK FILE  : {task_filename}")
    _log(f"  API        : /v1/responses  (reasoning_effort={REASONING_EFFORT})")
    _log(f"{'=' * 70}")
    if system_prompt.strip():
        _log(f"\nSYSTEM PROMPT:\n{system_prompt}")
    else:
        _log(f"\nSYSTEM PROMPT: [NONE — variant runs without system prompt]")
    _log(f"\nTASK:\n{task_prompt}\n")
    _log(f"{'=' * 70}\n")

    # /v1/responses uses `previous_response_id` for stateful continuation;
    # first call gets seed input (system+user), subsequent calls send only new items.
    # When system_prompt is empty (e.g. VARIANT=e), skip the system message entirely.
    pending_input: list[dict] = []
    if system_prompt.strip():
        pending_input.append({"role": "system", "content": system_prompt})
    pending_input.append({"role": "user", "content": task_prompt})
    previous_response_id: str | None = None
    recent_calls: list[str] = []
    early_stop_nudges_left = EARLY_STOP_NUDGES

    for turn_n in range(MAX_TURNS):
        kwargs: dict = {
            "model": MODEL,
            "input": pending_input,
            "tools": TOOLS_RESPONSES,
            "reasoning": {"effort": REASONING_EFFORT} if REASONING_EFFORT != "none" else None,
            "parallel_tool_calls": False,
            "store": True,
            "safety_identifier": SAFETY_IDENTIFIER,
        }
        # Drop None values (some SDK versions error on None fields)
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        if previous_response_id:
            kwargs["previous_response_id"] = previous_response_id

        with telemetry.span("llm.responses", {
            "gen_ai.system": "openai",
            "gen_ai.operation.name": "responses",
            "gen_ai.request.model": MODEL,
            "gen_ai.request.reasoning_effort": REASONING_EFFORT,
            "agent.turn": turn_n,
        }) as llm_sp:
            response = client.responses.create(**kwargs)
            usage = getattr(response, "usage", None)
            if usage:
                telemetry.set_attr(llm_sp, "gen_ai.usage.input_tokens", getattr(usage, "input_tokens", None))
                telemetry.set_attr(llm_sp, "gen_ai.usage.output_tokens", getattr(usage, "output_tokens", None))
            telemetry.set_attr(llm_sp, "gen_ai.response.id", response.id)
        previous_response_id = response.id
        pending_input = []  # will accumulate outputs for next iteration

        reasoning_text = ""
        message_text = ""
        function_calls: list = []

        for item in response.output:
            item_type = getattr(item, "type", None)
            if item_type == "reasoning":
                # Reasoning items may carry `summary` (list of parts with text)
                summary = getattr(item, "summary", None) or []
                for s in summary:
                    txt = getattr(s, "text", None)
                    if txt:
                        reasoning_text += (txt + "\n")
            elif item_type == "message":
                for part in getattr(item, "content", []) or []:
                    txt = getattr(part, "text", None)
                    if txt:
                        message_text += txt
            elif item_type == "function_call":
                function_calls.append(item)

        if reasoning_text.strip():
            _log(f"\n[{AGENT_ID}:t{turn_n}] REASONING SUMMARY:")
            _log(f"  {reasoning_text.strip()}")
        if message_text.strip():
            _log(f"\n[{AGENT_ID}:t{turn_n}] MESSAGE:")
            _log(f"  {message_text.strip()}")

        if not function_calls:
            # Early-stop nudge (same behavior as chat.completions path)
            if early_stop_nudges_left > 0:
                early_stop_nudges_left -= 1
                nudge = (
                    "You returned no tool calls, but the task may not be complete. "
                    "Review the task requirements as stated in the user message. "
                    "If you have not yet satisfied them, continue investigating — try "
                    "tools you have not yet used, or approaches you have not yet tried. "
                    "If you are TRULY finished, respond with a final message that "
                    "explicitly states what you accomplished and what remains incomplete."
                )
                _log(f"\n[{AGENT_ID}:t{turn_n}] EARLY-STOP NUDGE (remaining nudges: {early_stop_nudges_left})")
                pending_input.append({"role": "user", "content": nudge})
                continue

            record = {
                "session_id": SESSION_ID,
                "agent_id": AGENT_ID,
                "role": role,
                "model": MODEL,
                "turn": turn_n,
                "ts": _now(),
                "reasoning": (reasoning_text + message_text).strip(),
                "tool_calls": [],
                "finish": "stop",
                "response_id": previous_response_id,
            }
            _emit(record)
            _log(f"\n[{AGENT_ID}] FINISHED at turn {turn_n} (finish=stop, nudges exhausted)\n")
            return

        tool_calls_out: list[dict] = []
        for fc in function_calls:
            fc_name = fc.name
            fc_call_id = fc.call_id
            try:
                fc_args = json.loads(fc.arguments or "{}")
            except json.JSONDecodeError:
                fc_args = {}

            fingerprint = f"{fc_name}:{json.dumps(fc_args, sort_keys=True)}"
            recent_calls.append(fingerprint)
            recent_calls[:] = recent_calls[-LOOP_WINDOW:]

            _log(f"  CALL  : {fc_name}({json.dumps(fc_args)[:280]})")

            with telemetry.span("tool.execute", {
                "tool.name": fc_name,
                "tool.arguments": json.dumps(fc_args),
                "agent.turn": turn_n,
            }) as tool_sp:
                if len(recent_calls) == LOOP_WINDOW and len(set(recent_calls)) == 1:
                    loop_nudge = (
                        "LOOP_BREAKER: You have made the same call "
                        f"({fc_name}) with the same arguments "
                        f"{LOOP_WINDOW} times in a row. The result has not changed. "
                        "Change your approach — either try a completely different tool "
                        "call or, if you have already gathered enough information, "
                        "act on what you know instead of gathering more."
                    )
                    result = loop_nudge
                    _log(f"  LOOP! : injecting loop-breaker nudge")
                    telemetry.set_attr(tool_sp, "tool.loop_breaker", True)
                    recent_calls.clear()
                else:
                    result = run_tool(fc_name, fc_args)
                telemetry.set_attr(tool_sp, "tool.result.length", len(result))
                telemetry.set_attr(tool_sp, "tool.result", result)

            _log(f"  RET   : {result[:280]!r}")

            # Function outputs go back to the model on the NEXT turn via pending_input
            pending_input.append({
                "type": "function_call_output",
                "call_id": fc_call_id,
                "output": result,
            })

            tool_calls_out.append({
                "id": fc_call_id,
                "name": fc_name,
                "args": fc_args,
                "result": result,
            })

        record = {
            "session_id": SESSION_ID,
            "agent_id": AGENT_ID,
            "role": role,
            "model": MODEL,
            "turn": turn_n,
            "ts": _now(),
            "reasoning": (reasoning_text + message_text).strip(),
            "tool_calls": tool_calls_out,
            "finish": "tool_calls",
            "response_id": previous_response_id,
        }
        _emit(record)

    _log(f"\n[{AGENT_ID}] MAX_TURNS={MAX_TURNS} reached without stop\n")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Startup grace period — matches the sensor-attach race workaround from
    # eval-agent/agent_harness.py:34. Not needed today because we haven't wired
    # the sensor yet, but harmless.
    time.sleep(float(os.environ.get("STARTUP_DELAY_SECS", "1")))
    if telemetry.init_tracer(
        "hf-demo-agent",
        {"agent.role": ROLE, "agent.id": AGENT_ID, "session.id": SESSION_ID},
    ):
        _log("[otel] console tracing enabled (spans → stderr)")
    try:
        if USE_RESPONSES_API:
            if not hasattr(client, "responses"):
                _log(f"ERROR: openai SDK version does not have client.responses — bump the SDK "
                     f"(need openai>=1.70). Current sys.path openai version may be too old.")
                sys.exit(2)
            run_responses(ROLE)
        else:
            run(ROLE)
    finally:
        telemetry.shutdown()
