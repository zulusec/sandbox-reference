"""The payload that runs inside the sandbox, and how its output is read.

The payload is plain source text piped to a Python interpreter inside the
target. It has no imports beyond the standard library and no knowledge of
the harness, because it runs in an environment the harness does not control.

It prints one marked line so the harness can find its result among whatever
else the target's exec wrapper decides to write to stdout.
"""

from __future__ import annotations

import json

MARKER = "@@SANDBOX_PROBE@@"


class InnerProtocolError(Exception):
    """The inner payload did not return a readable result."""


def parse_inner(stdout: str) -> dict:
    for line in stdout.splitlines():
        if not line.startswith(MARKER):
            continue
        raw = line[len(MARKER):].strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise InnerProtocolError(f"inner result was not valid JSON: {error}") from error
    raise InnerProtocolError("inner payload produced no marked result line")


def emit(source_body: str) -> str:
    """Wrap a payload body so its `result` dict comes back on the marked line."""
    return (
        "import json, os, socket, sys\n"
        f"MARKER = {MARKER!r}\n"
        "result = {}\n"
        f"{source_body}\n"
        "print(MARKER + ' ' + json.dumps(result, sort_keys=True))\n"
    )
