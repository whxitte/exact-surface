"""Tests for the subprocess runner using real short-lived python subprocesses
(no external recon tools needed)."""

from __future__ import annotations

import sys

import pytest

from core.errors import ToolNotFound, ToolTimeout
from modules.exec import iter_jsonl, run_tool, run_tool_jsonl


async def test_run_tool_captures_stdout():
    run = await run_tool(sys.executable, ["-c", "print('hello')"], timeout=10)
    assert run.ok and run.stdout.strip() == "hello"


async def test_missing_binary_raises_tool_not_found():
    with pytest.raises(ToolNotFound):
        await run_tool("definitely-not-a-real-binary-xyz", [], timeout=5)


async def test_timeout_kills_and_raises():
    sleeper = ["-c", "import time; time.sleep(30)"]
    with pytest.raises(ToolTimeout):
        await run_tool(sys.executable, sleeper, timeout=0.3)


async def test_stdin_is_passed():
    code = "import sys; print(sys.stdin.read().upper())"
    run = await run_tool(sys.executable, ["-c", code], timeout=10, stdin="abc")
    assert run.stdout.strip() == "ABC"


def test_iter_jsonl_skips_garbage():
    text = '{"a": 1}\nnot json\n\n{"b": 2}\n[1,2,3]\n'
    objs = list(iter_jsonl(text))
    assert objs == [{"a": 1}, {"b": 2}]  # array line skipped (not a dict)


async def test_run_tool_jsonl_parses_stream():
    code = (
        r"print('{\"host\": \"a.com\"}'); print('warning: ignore me'); "
        r"print('{\"host\": \"b.com\"}')"
    )
    objs = await run_tool_jsonl(sys.executable, ["-c", code], timeout=10)
    assert [o["host"] for o in objs] == ["a.com", "b.com"]
