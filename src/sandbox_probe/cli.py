"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from sandbox_probe import __version__, render

# Importing the probe modules is what registers them. Nothing else in the
# codebase imports them, so leaving one out means that probe silently never
# runs even though the report still looks complete.
from sandbox_probe.probes import (  # noqa: F401  (imported for registration)
    all_probes,
    attribution,
    bounds,
    credentials,
    detection,
    filesystem,
    network,
)
from sandbox_probe.result import EXIT_CANNOT_START
from sandbox_probe.runner import run_all
from sandbox_probe.target import TargetConfigError, load_target

_DESCRIPTION = (
    "Containment probes for agent sandboxes. Run this only against sandboxes "
    "you own or are authorized to assess."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sandbox-probe", description=_DESCRIPTION)
    parser.add_argument("--target", default="reference/target.json",
                         help="path to the target config (default: the reference sandbox)")
    parser.add_argument("--probe", action="append", default=None,
                         help="run only the named probe; repeatable")
    parser.add_argument("--list-probes", action="store_true",
                         help="list the registered probes and exit")
    parser.add_argument("--json", action="store_true",
                         help="emit JSON instead of a table")
    return parser


def target_problem(error: Exception, path: str) -> str:
    """One line a reader can act on, in place of a traceback."""
    if isinstance(error, TargetConfigError):
        return str(error)
    return f"could not load the target config at {path} ({type(error).__name__})."


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    registered = all_probes()

    if args.list_probes:
        for probe in registered:
            sys.stdout.write(f"{probe.probe_id}\n")
        return 0

    try:
        target = load_target(args.target)
    except TargetConfigError as error:
        sys.stderr.write(f"sandbox-probe: {target_problem(error, args.target)}\n")
        return EXIT_CANNOT_START

    selected = registered
    if args.probe:
        known = {probe.probe_id for probe in registered}
        unknown = sorted(set(args.probe) - known)
        if unknown:
            sys.stderr.write(
                f"sandbox-probe: unknown probe: {', '.join(unknown)}. "
                f"Known probes: {', '.join(sorted(known))}.\n"
            )
            return EXIT_CANNOT_START
        selected = [probe for probe in registered if probe.probe_id in set(args.probe)]

    report = run_all(target, selected)
    metadata = {
        "target": target.name,
        "probes": [probe.probe_id for probe in selected],
        "tool_version": __version__,
    }
    if args.json:
        sys.stdout.write(render.to_json(report, metadata))
    else:
        sys.stdout.write(render.to_table(report))
    return report.exit_code


def run() -> None:
    raise SystemExit(main())
