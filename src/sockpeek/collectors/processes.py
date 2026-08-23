from __future__ import annotations

import os
import pwd
from sockpeek.models import ProcessInfo


def collect_processes(
    proc_dir: str = "/proc",
) -> tuple[dict[int, ProcessInfo], dict[int, list[int]], bool]:
    """Scan /proc to discover processes, their details, and socket inode ownership."""
    processes: dict[int, ProcessInfo] = {}
    inode_to_pids: dict[int, list[int]] = {}
    permission_denied = False

    if not os.path.isdir(proc_dir):
        return processes, inode_to_pids, permission_denied

    try:
        entries = os.listdir(proc_dir)
    except (PermissionError, OSError):
        return processes, inode_to_pids, True

    for entry in entries:
        if not entry.isdigit():
            continue

        pid = int(entry)
        pid_dir = os.path.join(proc_dir, entry)

        fd_dir = os.path.join(pid_dir, "fd")
        try:
            fd_entries = os.listdir(fd_dir)
            for fd in fd_entries:
                fd_path = os.path.join(fd_dir, fd)
                try:
                    target = os.readlink(fd_path)
                    if target.startswith("socket:[") and target.endswith("]"):
                        inode_str = target[8:-1]
                        if inode_str.isdigit():
                            inode = int(inode_str)
                            inode_to_pids.setdefault(inode, [])
                            if pid not in inode_to_pids[inode]:
                                inode_to_pids[inode].append(pid)
                    elif ":[" in target and target.endswith("]"):
                        parts = target.rstrip("]").split(":[")
                        if len(parts) == 2 and parts[1].isdigit():
                            inode = int(parts[1])
                            inode_to_pids.setdefault(inode, [])
                            if pid not in inode_to_pids[inode]:
                                inode_to_pids[inode].append(pid)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
        except PermissionError:
            permission_denied = True
            continue
        except (FileNotFoundError, OSError):
            continue

        try:
            comm_path = os.path.join(pid_dir, "comm")
            name = ""
            if os.path.exists(comm_path):
                with open(comm_path, "r", encoding="utf-8", errors="replace") as f:
                    name = f.read().strip()

            cmdline_path = os.path.join(pid_dir, "cmdline")
            cmdline = ""
            if os.path.exists(cmdline_path):
                with open(cmdline_path, "rb") as f:
                    raw_cmd = f.read()
                    cmdline = raw_cmd.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()

            if not name and cmdline:
                name = cmdline.split()[0].split("/")[-1]
            elif not name:
                name = f"PID-{pid}"

            exe = ""
            exe_path = os.path.join(pid_dir, "exe")
            if os.path.exists(exe_path):
                try:
                    exe = os.readlink(exe_path)
                except (PermissionError, OSError):
                    exe = ""

            cwd = ""
            cwd_path = os.path.join(pid_dir, "cwd")
            if os.path.exists(cwd_path):
                try:
                    cwd = os.readlink(cwd_path)
                except (PermissionError, OSError):
                    cwd = ""

            user = ""
            try:
                stat_info = os.stat(pid_dir)
                uid = stat_info.st_uid
                try:
                    user = pwd.getpwuid(uid).pw_name
                except KeyError:
                    user = str(uid)
            except (PermissionError, OSError):
                user = "unknown"

            ppid = 0
            status_path = os.path.join(pid_dir, "status")
            if os.path.exists(status_path):
                try:
                    with open(status_path, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            if line.startswith("PPid:"):
                                parts = line.split()
                                if len(parts) >= 2 and parts[1].isdigit():
                                    ppid = int(parts[1])
                                break
                except (PermissionError, OSError):
                    pass

            processes[pid] = ProcessInfo(
                pid=pid,
                name=name,
                user=user,
                exe=exe,
                cmdline=cmdline,
                cwd=cwd,
                ppid=ppid,
            )
        except (FileNotFoundError, ProcessLookupError, OSError):
            continue

    return processes, inode_to_pids, permission_denied