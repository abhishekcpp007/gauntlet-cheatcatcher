from pathlib import Path

from gauntlet_cheatcatcher import parse_patch

EXAMPLES = Path(__file__).parent.parent / "examples"


def test_parses_git_diff_with_new_file():
    files = parse_patch((EXAMPLES / "honest_fix.diff").read_text())
    assert [f.path for f in files] == ["calc/ops.py", "tests/test_ops_extra.py"]
    ops, extra = files
    assert ops.removed == ["    return b - a"] and ops.added == ["    return a - b"]
    assert not ops.is_new and extra.is_new and not extra.is_deleted
    assert extra.added[-1] == "    assert sub(1, 3) == -2"


def test_deleted_and_renamed():
    patch = (
        "diff --git a/tests/test_a.py b/tests/test_a.py\n"
        "deleted file mode 100644\n"
        "--- a/tests/test_a.py\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-def test_a():\n"
        "-    assert 1\n"
        "diff --git a/old.py b/new.py\n"
        "similarity index 100%\n"
        "rename from old.py\n"
        "rename to new.py\n"
    )
    deleted, renamed = parse_patch(patch)
    assert deleted.is_deleted and deleted.path == "tests/test_a.py" and len(deleted.removed) == 2
    assert renamed.old_path == "old.py" and renamed.new_path == "new.py"


def test_content_that_looks_like_headers_stays_content():
    patch = "--- a/notes.md\n+++ b/notes.md\n@@ -1,2 +1,2 @@\n--- old heading\n+++ new heading\n same\n"
    (f,) = parse_patch(patch)
    assert f.removed == ["-- old heading"] and f.added == ["++ new heading"]


def test_plain_diff_without_git_headers_and_binary():
    patch = (
        "--- a/x.py\t2024-01-01\n+++ b/x.py\t2024-01-02\n@@ -1 +1 @@\n-a\n+b\n"
        "diff --git a/img.png b/img.png\nBinary files a/img.png and b/img.png differ\n"
    )
    x, img = parse_patch(patch)
    assert x.path == "x.py" and x.added == ["b"]
    assert img.is_binary


def test_empty():
    assert parse_patch("") == []
