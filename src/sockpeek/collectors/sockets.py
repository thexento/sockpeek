from __future__ import annotations

import os
from sockpeek.models import SocketInfo
from sockpeek.utils.network import parse_proc_ipv4, parse_proc_ipv6

TCP_STATES = {
    "01": "LISTEN",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "ESTABLISHED",
    "05": "FIN_WAIT1",
    "06": "FIN_WAIT2",
    "07": "TIME_WAIT",
    "08": "CLOSE",
    "09": "CLOSE_WAIT",
    "0A": "LAST_ACK",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}


def collect_sockets_from_proc(proc_dir: str = "/proc") -> tuple[list[SocketInfo], list[str]]:
    """Read socket tables from /proc/net/tcp, tcp6, udp, udp6."""
    sockets: list[SocketInfo] = []
    warnings: list[str] = []

    net_files = [
        ("tcp", "ipv4", f"{proc_dir}/net/tcp"),
        ("tcp", "ipv6", f"{proc_dir}/net/tcp6"),
        ("udp", "ipv4", f"{proc_dir}/net/udp"),
        ("udp", "ipv6", f"{proc_dir}/net/udp6"),
    ]

    for protocol, family, filepath in net_files:
        if not os.path.exists(filepath):
            continue

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except (PermissionError, OSError) as err:
            warnings.append(f"Unable to read {filepath}: {err}")
            continue

        if not lines:
            continue

        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 10:
                continue

            hex_local = parts[1]
            hex_remote = parts[2]
            hex_state = parts[3].upper()

            try:
                inode = int(parts[9])
            except ValueError:
                continue

            try:
                if family == "ipv4":
                    local_addr, local_port = parse_proc_ipv4(hex_local)
                    remote_addr, remote_port = parse_proc_ipv4(hex_remote)
                else:
                    local_addr, local_port = parse_proc_ipv6(hex_local)
                    remote_addr, remote_port = parse_proc_ipv6(hex_remote)
            except ValueError:
                continue

            if protocol == "tcp":
                state = TCP_STATES.get(hex_state, f"UNKNOWN({hex_state})")
            else:
                if remote_port == 0:
                    state = "LISTEN" if hex_state in ("07", "01") else "UNCONN"
                else:
                    state = "ESTABLISHED"

            sockets.append(
                SocketInfo(
                    protocol=protocol,
                    family=family,
                    local_address=local_addr,
                    local_port=local_port,
                    remote_address=remote_addr,
                    remote_port=remote_port,
                    state=state,
                    inode=inode,
                )
            )

    return sockets, warnings