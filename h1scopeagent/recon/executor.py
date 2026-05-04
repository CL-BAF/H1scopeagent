"""Direct command executor — no approval blocks, full autonomy."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class ExecResult:
    command: str = ""
    output: str = ""
    exit_code: int = -1
    error: str = ""
    timeout: bool = False


def execute(command: str, timeout: int = 120, capture_stderr: bool = True) -> ExecResult:
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (proc.stdout or "")[:30000]
        if capture_stderr and proc.stderr:
            output += "\n[STDERR]\n" + (proc.stderr or "")[:8000]
        return ExecResult(
            command=command,
            output=output,
            exit_code=proc.returncode,
            error="" if proc.returncode == 0 else f"Exit {proc.returncode}",
        )
    except subprocess.TimeoutExpired:
        return ExecResult(
            command=command,
            output="",
            exit_code=-1,
            error=f"Timed out after {timeout}s",
            timeout=True,
        )
    except Exception as e:
        return ExecResult(
            command=command,
            output="",
            exit_code=-1,
            error=str(e),
        )
