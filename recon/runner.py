"""Safe command runner — executes commands only after guard approval.

Handles subprocess execution with timeout, output capture,
and complete audit logging.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

from h1scopeagent.logs.audit import AuditLogger


@dataclass
class CommandResult:
    command: str = ""
    output: str = ""
    exit_code: int = -1
    error: str = ""
    blocked: bool = False
    block_reason: str = ""
    timeout: bool = False


class CommandRunner:
    """Execute commands with guard checks and timeout protection."""

    def __init__(self, guard):
        self._guard = guard
        self._audit = AuditLogger()

    def run(
        self,
        command: str,
        approved: bool = False,
        timeout: int = 60,
    ) -> CommandResult:
        review = self._guard.review(command)

        if review.blocked:
            return CommandResult(
                command=command,
                blocked=True,
                block_reason=review.block_reason,
            )

        if review.requires_approval and not approved:
            return CommandResult(
                command=command,
                blocked=True,
                block_reason=f"Approval required: {review.approval_reason}",
            )

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            output = ""
            if result.stdout:
                output = result.stdout[:10000]  # Cap output to avoid memory issues
            if result.stderr:
                error_part = result.stderr[:5000]
                if output:
                    output += "\n[STDERR]\n" + error_part
                else:
                    output = error_part

            self._audit.log_command_output(
                command, result.returncode, output[:200]
            )

            return CommandResult(
                command=command,
                output=output,
                exit_code=result.returncode,
                error="" if result.returncode == 0 else f"Exit code: {result.returncode}",
            )

        except subprocess.TimeoutExpired:
            self._audit.log_error("command_timeout", f"Command timed out after {timeout}s")
            return CommandResult(
                command=command,
                output="",
                exit_code=-1,
                error=f"Command timed out after {timeout} seconds",
                timeout=True,
            )
        except Exception as e:
            self._audit.log_error("command_execution", str(e))
            return CommandResult(
                command=command,
                output="",
                exit_code=-1,
                error=str(e),
            )
