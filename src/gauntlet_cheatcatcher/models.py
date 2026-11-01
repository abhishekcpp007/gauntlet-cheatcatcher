from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, computed_field

Severity = Literal["high", "medium", "low"]
Verdict = Literal["clean", "suspicious", "cheating"]

_ORDER = {"high": 0, "medium": 1, "low": 2}


class Finding(BaseModel):
    rule: str
    severity: Severity
    message: str
    step: int | None = None
    file: str | None = None
    evidence: str = ""


class Report(BaseModel):
    findings: list[Finding] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verdict(self) -> Verdict:
        severities = {f.severity for f in self.findings}
        if "high" in severities:
            return "cheating"
        if "medium" in severities:
            return "suspicious"
        return "clean"

    def counts(self) -> dict[str, int]:
        out = {"high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def by_step(self) -> dict[int, list[str]]:
        """Step index -> short messages, for pinning findings onto a trajectory timeline."""
        out: dict[int, list[str]] = {}
        for f in self.findings:
            if f.step is not None:
                out.setdefault(f.step, []).append(f"[{f.severity}] {f.message}")
        return out

    def to_markdown(self) -> str:
        c = self.counts()
        lines = [
            f"**Verdict: {self.verdict}** ({c['high']} high, {c['medium']} medium, {c['low']} low)",
        ]
        if not self.findings:
            lines.append("\nNo findings.")
            return "\n".join(lines)
        lines += ["", "| Severity | Rule | Where | What | Evidence |", "|---|---|---|---|---|"]
        for f in self.findings:
            where = " ".join(x for x in (f"step {f.step}" if f.step is not None else "", f.file or "") if x)
            evidence = f.evidence.replace("|", "\\|").replace("\n", " ")
            evidence = f"`{evidence}`" if evidence else ""
            lines.append(f"| {f.severity} | {f.rule} | {where} | {f.message} | {evidence} |")
        return "\n".join(lines)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (f.rule, f.severity, f.step, f.file, f.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return sorted(
        unique,
        key=lambda f: (_ORDER[f.severity], f.step if f.step is not None else -1, f.file or "", f.rule),
    )
