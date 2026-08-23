from __future__ import annotations

import os
from sockpeek.models import ServiceInfo
from sockpeek.utils.commands import run_command


def correlate_systemd(pid: int, proc_dir: str = "/proc") -> ServiceInfo | None:
    """Inspect PID's cgroup and attempt systemctl status resolution."""
    cgroup_path = os.path.join(proc_dir, str(pid), "cgroup")
    if not os.path.exists(cgroup_path):
        return None

    unit_name = ""
    try:
        with open(cgroup_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    path = parts[2]
                    path_segments = path.split("/")
                    for seg in path_segments:
                        if seg.endswith(".service") or seg.endswith(".socket"):
                            unit_name = seg
                            break
                if unit_name:
                    break
    except (PermissionError, OSError):
        return None

    if not unit_name:
        return None

    cmd_res = run_command(
        ["systemctl", "show", unit_name, "--property=ActiveState,LoadState,Description"],
        timeout=1.5,
    )

    active_state = "unknown"
    load_state = "unknown"
    description = ""

    if cmd_res.success and cmd_res.stdout:
        for line in cmd_res.stdout.splitlines():
            if line.startswith("ActiveState="):
                active_state = line.split("=", 1)[1]
            elif line.startswith("LoadState="):
                load_state = line.split("=", 1)[1]
            elif line.startswith("Description="):
                description = line.split("=", 1)[1]

    return ServiceInfo(
        unit_name=unit_name,
        active_state=active_state,
        load_state=load_state,
        description=description,
    )