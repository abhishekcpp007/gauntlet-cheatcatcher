"""Turn a trajectory and/or a patch into one list of file changes and one list of shell commands.

Rules only ever look at these, so they don't care where a change came from.
"""

from __future__ import annotations

import base64
import re
import shlex
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Literal

from gauntlet_sandbox import Trajectory

from .diff import parse_patch

_TEST_DIRS = {"test", "tests", "testing"}
PYTEST_CONFIG_FILES = {"pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml"}


def is_test_path(path: str) -> bool:
    p = PurePosixPath(path)
    if p.name == "conftest.py" or any(part in _TEST_DIRS for part in p.parts[:-1]):
        return True
    return p.suffix == ".py" and (p.name.startswith("test_") or p.stem.endswith("_test"))


def normalize(path: str) -> str:
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


@dataclass
class Change:
    path: str
    added: list[str]
    removed: list[str]
    is_new: bool
    is_deleted: bool
    preexisting: bool  # we know the file was there before the agent touched it
    source: Literal["patch", "trajectory"]
    step: int | None = None
    baseline_known: bool = True  # False when we know it existed but never saw its old content

    @property
    def net_removed(self) -> list[str]:
        """Removed lines that didn't come straight back (diffs often remove and re-add context)."""
        added = Counter(self.added)
        out = []
        for ln in self.removed:
            if added[ln] > 0:
                added[ln] -= 1
            else:
                out.append(ln)
        return out

    @property
    def name(self) -> str:
        return PurePosixPath(self.path).name

    @property
    def is_test(self) -> bool:
        return is_test_path(self.path)


@dataclass
class Command:
    step: int
    command: str
    exit_code: int | None = None

    def segments(self) -> list[list[str]]:
        """Split on ; && || | and newlines, then shell-split each piece."""
        out = []
        for raw in re.split(r"\s*(?:&&|\|\||;|\||\n)\s*", self.command):
            if not raw.strip():
                continue
            try:
                out.append(shlex.split(raw, posix=True))
            except ValueError:
                out.append(raw.split())
        return out


@dataclass
class Context:
    changes: list[Change] = field(default_factory=list)
    commands: list[Command] = field(default_factory=list)
    protected: set[str] = field(default_factory=set)
    existing: set[str] = field(default_factory=set)  # paths seen in the repo before the agent wrote them
    workdir: str = ""

    def rel(self, path: str) -> str:
        path = normalize(path)
        if self.workdir and path.startswith(self.workdir + "/"):
            return path[len(self.workdir) + 1 :]
        return path

    def is_protected(self, path: str) -> bool:
        path = normalize(path)
        return any(path == q or path.endswith("/" + q) for q in self.protected)


def _decode(action: dict) -> str | None:
    content = action.get("content")
    if content is None:
        return None
    if action.get("encoding") == "base64":
        try:
            return base64.b64decode(content).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    return content


def _line_delta(old: str | None, new: str) -> tuple[list[str], list[str]]:
    new_lines = new.splitlines()
    if old is None:
        return new_lines, []
    old_c, new_c = Counter(old.splitlines()), Counter(new_lines)
    added = [ln for ln in new_lines if new_c[ln] > old_c.get(ln, 0)]
    removed = list((old_c - new_c).elements())
    return added, removed


_READERS = {"cat", "head", "tail", "less", "more", "nl", "wc"}


def from_trajectory(traj: Trajectory, ctx: Context) -> None:
    ctx.workdir = str(traj.header.config.get("workdir") or "").rstrip("/")
    rel = ctx.rel
    known: dict[str, str] = {}  # last content we saw for each path
    existed = ctx.existing  # seen before the agent first wrote it
    written: set[str] = set()

    for step in traj.steps:
        a, o = step.action, step.observation
        kind = a.get("type")
        if kind == "exec":
            cmd = Command(step=step.index, command=a.get("command", ""), exit_code=o.get("exit_code"))
            ctx.commands.append(cmd)
            if o.get("exit_code") == 0:
                segs = cmd.segments()
                for seg in segs:
                    redirected = any(tok.startswith((">", "<")) or ">" in tok for tok in seg)
                    if seg and PurePosixPath(seg[0]).name in _READERS and not redirected:
                        for tok in seg[1:]:
                            if not tok.startswith("-") and rel(tok) not in written:
                                existed.add(rel(tok))
                # a lone `cat file` shows us the whole file, good enough as a baseline
                if len(segs) == 1 and len(segs[0]) == 2 and segs[0][0] == "cat" and not o.get("truncated"):
                    known.setdefault(rel(segs[0][1]), o.get("stdout", ""))
        elif kind == "read_file" and o.get("ok"):
            path = rel(a.get("path", ""))
            if path not in written:
                existed.add(path)
            text = _decode(o)
            if text is not None and not o.get("truncated"):
                known[path] = text
        elif kind == "write_file":
            path = rel(a.get("path", ""))
            text = _decode(a)
            if text is None:
                continue
            added, removed = _line_delta(known.get(path), text)
            ctx.changes.append(
                Change(
                    path=path,
                    added=added,
                    removed=removed,
                    is_new=path not in existed and path not in written,
                    is_deleted=False,
                    preexisting=path in existed,
                    source="trajectory",
                    step=step.index,
                    baseline_known=path in known or path not in existed,
                )
            )
            known[path] = text
            written.add(path)


def from_patch(patch: str, ctx: Context) -> None:
    for fd in parse_patch(patch):
        ctx.changes.append(
            Change(
                path=normalize(fd.path),
                added=fd.added,
                removed=fd.removed,
                is_new=fd.is_new,
                is_deleted=fd.is_deleted,
                preexisting=not fd.is_new,
                source="patch",
            )
        )
