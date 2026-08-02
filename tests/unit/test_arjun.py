"""modules.scanning.arjun: the arjun wrapper for hidden-parameter discovery.

No test file existed for this module before. Written alongside the fix for a real
production symptom: a 1200s arjun timeout produced nothing in the logs but the final
"killed after 1200s timeout" line, because the module ran arjun through the buffered
`run_tool` -- whose `proc.communicate()` under `asyncio.wait_for` returns nothing at
all when the wait itself times out. Switched to `stream_tool`, which logs output as it
arrives and survives the kill. These tests pin that the fake runner's streaming
callbacks are actually wired and exercised, and that every failure mode still degrades
to `{}` rather than raising -- arjun is one signal among several, never the stage.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.errors import ToolNotFound
from modules.scanning.arjun import find_params


async def test_no_urls_short_circuits_without_running_anything():
    async def runner(*a, **k):
        raise AssertionError("must not run arjun with no URLs")

    assert await find_params([], 10, runner=runner) == {}


async def test_parses_the_written_json_on_success():
    async def runner(binary, args, *, timeout, on_stdout=None, on_stderr=None, stdin=None):
        out_path = Path(args[args.index("-oJ") + 1])
        out_path.write_text(json.dumps({"https://x.com/a": {"params": ["debug", "id"]}}))
        if on_stdout:
            on_stdout("[+] found 2 param(s) on https://x.com/a")
        return (0, [], "", False)

    result = await find_params(["https://x.com/a"], 30, runner=runner)
    assert result == {"https://x.com/a": ["debug", "id"]}


async def test_missing_binary_degrades_to_empty_dict():
    async def runner(*a, **k):
        raise ToolNotFound("arjun")

    assert await find_params(["https://x.com/a"], 30, runner=runner) == {}


async def test_timeout_degrades_to_empty_dict_and_surfaces_what_streamed():
    """The actual regression: a hung arjun must still report how much it streamed
    before being killed, not vanish into a single opaque timeout line."""
    from loguru import logger as loguru_logger

    seen: list[str] = []
    logged: list[str] = []
    sink_id = loguru_logger.add(lambda msg: logged.append(msg.record["message"]))

    async def runner(binary, args, *, timeout, on_stdout=None, on_stderr=None, stdin=None):
        # Simulate arjun printing something, then hanging until the kill -- exactly
        # what stream_tool's real contract guarantees: partial output survives.
        if on_stderr:
            on_stderr("[!] probing https://x.com/a is taking a while...")
            seen.append("streamed one line before the timeout")
        return (-9, [], "", True)  # stream_tool's shape for a killed process

    try:
        result = await find_params(["https://x.com/a"], 5, runner=runner)
    finally:
        loguru_logger.remove(sink_id)

    assert result == {}
    assert seen == ["streamed one line before the timeout"]
    assert any("arjun:" in m and "probing" in m for m in logged), (
        "the streamed line must be logged as it arrives, not discarded"
    )
    assert any("killed after" in m and "1 line" in m for m in logged), (
        "the timeout message must report how much streamed before the kill"
    )


async def test_a_crash_never_propagates_out_of_find_params():
    async def runner(*a, **k):
        raise RuntimeError("boom")

    assert await find_params(["https://x.com/a"], 30, runner=runner) == {}


async def test_missing_output_file_is_empty_not_an_error():
    async def runner(binary, args, *, timeout, on_stdout=None, on_stderr=None, stdin=None):
        return (0, [], "", False)  # exits clean but never wrote -oJ

    assert await find_params(["https://x.com/a"], 30, runner=runner) == {}


async def test_unparseable_output_is_empty_not_an_error():
    async def runner(binary, args, *, timeout, on_stdout=None, on_stderr=None, stdin=None):
        Path(args[args.index("-oJ") + 1]).write_text("not json")
        return (0, [], "", False)

    assert await find_params(["https://x.com/a"], 30, runner=runner) == {}


async def test_nonzero_exit_with_a_valid_file_still_returns_results():
    """arjun has been observed exiting non-zero on a run that still wrote usable
    results -- the JSON file is authoritative, not the exit code."""

    async def runner(binary, args, *, timeout, on_stdout=None, on_stderr=None, stdin=None):
        Path(args[args.index("-oJ") + 1]).write_text(json.dumps({"https://x.com/a": ["debug"]}))
        return (1, [], "", False)

    result = await find_params(["https://x.com/a"], 30, runner=runner)
    assert result == {"https://x.com/a": ["debug"]}


@pytest.mark.parametrize(
    "shape,expected",
    [
        ({"https://x.com/a": {"params": ["b", "a"]}}, {"https://x.com/a": ["a", "b"]}),
        ({"https://x.com/a": {"parameters": ["z"]}}, {"https://x.com/a": ["z"]}),
        ({"https://x.com/a": ["x", "x", "y"]}, {"https://x.com/a": ["x", "y"]}),
        ({"https://x.com/a": {"params": []}}, {}),
        ({"not a dict": "at all"}, {}),
    ],
)
async def test_normalise_accepts_shapes_arjun_has_shipped(shape, expected):
    async def runner(binary, args, *, timeout, on_stdout=None, on_stderr=None, stdin=None):
        Path(args[args.index("-oJ") + 1]).write_text(json.dumps(shape))
        return (0, [], "", False)

    assert await find_params(["https://x.com/a"], 30, runner=runner) == expected


async def test_urls_are_capped_at_max_urls():
    from modules.scanning.arjun import MAX_URLS

    captured: dict[str, list[str]] = {}

    async def runner(binary, args, *, timeout, on_stdout=None, on_stderr=None, stdin=None):
        in_path = Path(args[args.index("-i") + 1])
        captured["lines"] = in_path.read_text().splitlines()
        return (0, [], "", False)

    many = [f"https://x.com/{i}" for i in range(MAX_URLS + 20)]
    await find_params(many, 30, runner=runner)
    assert len(captured["lines"]) == MAX_URLS
