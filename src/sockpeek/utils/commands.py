from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    success: bool
    executable_found: bool


def run_command(
    args: list[str],
    timeout: float = 3.0,
) -> CommandResult:
    """Safely execute an external command without shell execution."""
    if not args:
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr="No command specified",
            success=False,
            executable_found=False,
        )

    executable = shutil.which(args[0])
    if not executable:
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr=f"Executable '{args[0]}' not found in PATH",
            success=False,
            executable_found=False,
        )

    try:
        res = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            returncode=res.returncode,
            stdout=res.stdout,
            stderr=res.stderr,
            success=(res.returncode == 0),
            executable_found=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr=str(e),
            success=False,
            executable_found=True,
        )