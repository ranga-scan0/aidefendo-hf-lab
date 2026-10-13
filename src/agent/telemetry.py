#!/usr/bin/env python3
# Copyright (c) 2026 Scan0 Software Private Limited.
# SPDX-License-Identifier: Apache-2.0
#
# telemetry.py — optional OpenTelemetry tracing for the agent loop.
#
# Emits one span per LLM call and one child span per tool call, so an operator
# can see the full reason -> call -> result chain as structured OTel records.
#
# Export is console-only (spans print to stderr), chosen so the agent needs no
# network egress beyond its locked-down NetworkPolicy. Tracing is OFF unless
# OTEL_TRACES_EXPORTER is set to "console" (or "stdout"); set OTEL_SDK_DISABLED
# to force it off. If the opentelemetry SDK is not installed, every call here is
# a no-op, so the agent runs unchanged.

import os
import sys
from contextlib import contextmanager

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False

_TRACER = None
_PROVIDER = None
_ATTR_MAX = 1024  # truncate long attribute values (prompts, tool results)


def init_tracer(service_name: str, resource_attrs: dict | None = None) -> bool:
    """Configure a console-exporting tracer if requested. Returns True if enabled."""
    global _TRACER, _PROVIDER
    if not _OTEL_AVAILABLE:
        return False
    if os.environ.get("OTEL_SDK_DISABLED", "").lower() in ("1", "true", "yes"):
        return False
    if os.environ.get("OTEL_TRACES_EXPORTER", "").lower() not in ("console", "stdout"):
        return False

    resource = Resource.create({"service.name": service_name, **(resource_attrs or {})})
    _PROVIDER = TracerProvider(resource=resource)
    # Spans go to stderr so the agent's structured-JSON stdout stream stays clean.
    # SimpleSpanProcessor flushes each span synchronously — no spans lost on exit.
    _PROVIDER.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter(out=sys.stderr)))
    _TRACER = _PROVIDER.get_tracer("hf-demo.agent")
    return True


def _truncate(value) -> str:
    s = value if isinstance(value, str) else str(value)
    return s if len(s) <= _ATTR_MAX else s[:_ATTR_MAX] + "…[truncated]"


@contextmanager
def span(name: str, attributes: dict | None = None):
    """Start a span if tracing is enabled, else yield a no-op handle."""
    if _TRACER is None:
        yield _NoopSpan()
        return
    with _TRACER.start_as_current_span(name) as sp:
        if attributes:
            for k, v in attributes.items():
                sp.set_attribute(k, _truncate(v))
        yield sp


class _NoopSpan:
    def set_attribute(self, *_args, **_kwargs):
        pass


def set_attr(sp, key: str, value) -> None:
    """Set an attribute on a span handle (works for real and no-op spans)."""
    if sp is not None:
        sp.set_attribute(key, _truncate(value))


def shutdown() -> None:
    """Flush and shut down the provider (safe to call when disabled)."""
    if _PROVIDER is not None:
        _PROVIDER.shutdown()
