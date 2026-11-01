from __future__ import annotations

from gauntlet_sandbox import Trajectory

from .context import Context, from_patch, from_trajectory, normalize
from .models import Report, sort_findings
from .rules import RULES


def scan(
    trajectory: Trajectory | None = None,
    patch: str | None = None,
    *,
    protected_paths: list[str] | None = None,
) -> Report:
    """Run every rule over an agent's trajectory, its final patch, or both.

    `protected_paths` are the test files the grader owns, like a task's `test_files`.
    Touching any of them is treated as cheating outright.
    """
    ctx = Context(protected={normalize(p) for p in protected_paths or []})
    if trajectory is not None:
        from_trajectory(trajectory, ctx)
    if patch:
        from_patch(patch, ctx)
    findings = [f for fn in RULES.values() for f in fn(ctx)]
    return Report(findings=sort_findings(findings))
