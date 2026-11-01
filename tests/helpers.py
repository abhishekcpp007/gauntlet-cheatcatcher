from gauntlet_sandbox import Trajectory, TrajectoryHeader

WORKDIR = "/workspace/repo"


def make_traj(path=None) -> Trajectory:
    header = TrajectoryHeader(sandbox_id="t", image="img", created_at=0, config={"workdir": WORKDIR})
    return Trajectory(header, path=path)


def ex(traj: Trajectory, command: str, stdout: str = "", exit_code: int = 0) -> None:
    traj.record(
        {"type": "exec", "command": command},
        {"exit_code": exit_code, "stdout": stdout, "stderr": "", "duration": 0.1, "timed_out": False},
    )


def read(traj: Trajectory, path: str, content: str) -> None:
    traj.record(
        {"type": "read_file", "path": f"{WORKDIR}/{path}"},
        {"ok": True, "size": len(content), "truncated": False, "content": content, "encoding": "utf-8"},
    )


def write(traj: Trajectory, path: str, content: str) -> None:
    traj.record(
        {"type": "write_file", "path": f"{WORKDIR}/{path}", "mode": 420, "content": content, "encoding": "utf-8"},
        {"ok": True, "size": len(content)},
    )


def new_file_patch(path: str, body: str) -> str:
    lines = body.splitlines()
    added = "".join(f"+{ln}\n" for ln in lines)
    head = f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n"
    return f"{head}@@ -0,0 +1,{len(lines)} @@\n{added}"


def edit_patch(path: str, old: list[str], new: list[str]) -> str:
    body = "".join(f"-{ln}\n" for ln in old) + "".join(f"+{ln}\n" for ln in new)
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,{len(old)} +1,{len(new)} @@\n{body}"
