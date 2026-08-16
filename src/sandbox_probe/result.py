"""Run aggregation, and the rule that an unseen thing is never a pass.

A containment harness fails dangerously if a probe that could not run is
indistinguishable from a probe that ran and found nothing. Both produce an
empty finding list. Only the error list and the positive control tell them
apart, so both travel with the findings everywhere they go.

A probe that never ran at all produces neither, which is why the report also
carries the ids of the probes that actually produced an outcome. Coverage is
a measurement taken from the run, never an assumption carried over from
whatever the caller intended to run: an intention that is never reconciled
against the run is exactly how "every probe ran" gets printed under a run
where none did.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from sandbox_probe.finding import Finding, sort_findings

EXIT_OK = 0
EXIT_CANNOT_START = 1
EXIT_INCOMPLETE = 2
EXIT_FINDINGS = 3


@dataclass(frozen=True)
class ProbeError:
    probe_id: str
    subject: str
    operation: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "probe_id": self.probe_id,
            "subject": self.subject,
            "operation": self.operation,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ProbeOutcome:
    """What one probe produced.

    control_ok is the positive control: True when it ran and held, False
    when it ran and did not. A network probe that reports no egress because
    the harness could not reach the target at all has proved nothing, and
    must not be counted as containment.

    None is the third answer, and it is not a synonym for True. It means
    this probe has no positive control at all, which is a defensible design
    decision for a probe whose measurement is directly observable, but it is
    a different claim from "the control ran and passed". Reporting the
    second where the first is true is how a report ends up asserting a
    confirmation nobody performed.
    """

    findings: list[Finding] = field(default_factory=list)
    errors: list[ProbeError] = field(default_factory=list)
    control_ok: bool | None = True


@dataclass(frozen=True)
class RunReport:
    findings: list[Finding]
    errors: list[ProbeError]
    controls_failed: list[str]
    controls_absent: list[str] = field(default_factory=list)
    """Probes that report having no positive control, sorted.

    Separate from controls_failed because they mean opposite things: a
    failed control makes the run incomplete, while an absent one is a
    property of the probe's design. Kept out of the completeness rule and
    reported anyway, so a reader of the JSON can tell the two apart instead
    of being handed a True that reads as a confirmation.
    """
    probes_ran: list[str] = field(default_factory=list)
    """The ids of the probes that produced an outcome, sorted.

    Not the ids of the probes somebody meant to run. A caller that wants to
    know whether its selection was covered asks `covers`, which compares its
    intention against this list rather than against itself.
    """

    @property
    def complete(self) -> bool:
        return not self.errors and not self.controls_failed

    def covers(self, expected: Iterable[str]) -> bool:
        """Did every probe that was supposed to run produce an outcome.

        Equality, not containment in either direction. A run short of what
        was asked for is not a full assessment, and a run carrying an
        outcome from a probe nobody selected is a harness this report has no
        business vouching for either.
        """
        return set(expected) == set(self.probes_ran)

    @property
    def exit_code(self) -> int:
        if not self.complete:
            return EXIT_INCOMPLETE
        return EXIT_FINDINGS if self.findings else EXIT_OK


def merge_outcomes(outcomes: dict[str, ProbeOutcome]) -> RunReport:
    findings: list[Finding] = []
    errors: list[ProbeError] = []
    controls_failed: list[str] = []
    controls_absent: list[str] = []
    for probe_id in sorted(outcomes):
        outcome = outcomes[probe_id]
        findings.extend(outcome.findings)
        errors.extend(outcome.errors)
        # Identity, not truthiness. None is falsy in Python, and reading it
        # as a failure here would turn "this probe has no control" into
        # "this probe's control did not hold" for every run.
        if outcome.control_ok is False:
            controls_failed.append(probe_id)
        elif outcome.control_ok is None:
            controls_absent.append(probe_id)
    return RunReport(
        findings=sort_findings(findings),
        errors=errors,
        controls_failed=controls_failed,
        controls_absent=controls_absent,
        probes_ran=sorted(outcomes),
    )
