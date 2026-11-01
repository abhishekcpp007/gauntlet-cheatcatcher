"""A small unified diff parser. Enough to know which files changed and which lines came and went."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_GIT_HEADER = re.compile(r'^diff --git "?a/(.+?)"? "?b/(.+?)"?$')
_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


@dataclass
class FileDiff:
    old_path: str | None
    new_path: str | None
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    is_binary: bool = False
    _headers_done: bool = False

    @property
    def path(self) -> str:
        return self.new_path or self.old_path or "?"

    @property
    def is_new(self) -> bool:
        return self.old_path is None

    @property
    def is_deleted(self) -> bool:
        return self.new_path is None


def _clean(raw: str) -> str | None:
    p = raw.split("\t")[0].strip().strip('"')
    if p == "/dev/null":
        return None
    if p.startswith(("a/", "b/")):
        p = p[2:]
    return p


def parse_patch(text: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    old_left = new_left = 0

    for line in text.splitlines():
        if old_left > 0 or new_left > 0:  # inside a hunk, count lines so "--- x" in content is safe
            if cur is None:
                break
            if line.startswith("\\"):
                continue
            tag, body = line[:1], line[1:]
            if tag == "+":
                cur.added.append(body)
                new_left -= 1
            elif tag == "-":
                cur.removed.append(body)
                old_left -= 1
            else:  # context (some tools strip the leading space on blank lines)
                old_left -= 1
                new_left -= 1
            continue

        if line.startswith("diff --git "):
            m = _GIT_HEADER.match(line)
            cur = FileDiff(m.group(1) if m else None, m.group(2) if m else None)
            files.append(cur)
            continue
        if line.startswith("--- "):
            if cur is None or cur._headers_done:
                cur = FileDiff(None, None)
                files.append(cur)
            cur.old_path = _clean(line[4:])
            continue
        if line.startswith("+++ ") and cur is not None:
            cur.new_path = _clean(line[4:])
            cur._headers_done = True
            continue
        if cur is None:
            continue
        if line.startswith("new file mode"):
            cur.old_path = None
        elif line.startswith("deleted file mode"):
            cur.new_path = None
        elif line.startswith("rename from "):
            cur.old_path = line[len("rename from ") :]
        elif line.startswith("rename to "):
            cur.new_path = line[len("rename to ") :]
        elif line.startswith(("Binary files", "GIT binary patch")):
            cur.is_binary = True
        else:
            m = _HUNK.match(line)
            if m:
                old_left = int(m.group(1)) if m.group(1) is not None else 1
                new_left = int(m.group(2)) if m.group(2) is not None else 1
    return files
