from __future__ import annotations

import argparse
import sys

from sockpeek import __version__
from sockpeek.collectors.docker import collect_docker_containers
from sockpeek.collectors.processes import collect_processes
from sockpeek.collectors.sockets import collect_sockets_from_proc
from sockpeek.collectors.systemd import correlate_systemd
from sockpeek.formatters.json import JsonFormatter
from sockpeek.formatters.terminal import TerminalFormatter
from sockpeek.models import InspectionResult
from sockpeek.utils.network import analyze_exposure


def check_platform() -> None:
    if sys.platform != "linux":
        sys.stderr.write("Error: sockpeek currently supports Linux systems only.\n")
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sockpeek",
        description="Linux Socket Diagnostic Tool — correlated socket, process, systemd & container insights.",
        epilog="Examples:\n  sockpeek 8080\n  sockpeek list\n  sockpeek list --wide\n  sockpeek pid 1821\n  sockpeek process nginx\n  sockpeek 8080 --json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output diagnostic results in JSON format"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable color output in terminal"
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    list_parser = subparsers.add_parser("list", help="List active listening sockets")
    list_parser.add_argument(
        "-w", "--wide", action="store_true", help="Display wide table layout"
    )

    pid_parser = subparsers.add_parser("pid", help="Inspect sockets owned by a PID")
    pid_parser.add_argument("pid_num", type=int, help="Target process PID")

    proc_parser = subparsers.add_parser(
        "process", help="Inspect sockets owned by process name"
    )
    proc_parser.add_argument("proc_name", type=str, help="Target process name")

    parser.add_argument(
        "port",
        nargs="?",
        type=str,
        help="Target port number to inspect (1-65535)",
    )

    return parser


def run_inspection(
    query_type: str,
    query_target: str,
    proc_dir: str = "/proc",
) -> InspectionResult:
    """Core correlation workflow."""
    sockets, sock_warnings = collect_sockets_from_proc(proc_dir=proc_dir)
    processes, inode_map, perm_denied = collect_processes(proc_dir=proc_dir)
    docker_containers = collect_docker_containers()

    for socket in sockets:
        if socket.inode in inode_map:
            socket.pids = inode_map[socket.inode]

    matched_sockets = []
    matched_pids = set()

    if query_type == "port":
        target_port = int(query_target)
        for s in sockets:
            if s.local_port == target_port:
                matched_sockets.append(s)
                matched_pids.update(s.pids)

    elif query_type == "pid":
        target_pid = int(query_target)
        if target_pid in processes:
            matched_pids.add(target_pid)
        for s in sockets:
            if target_pid in s.pids:
                matched_sockets.append(s)

    elif query_type == "process":
        target_name = query_target.lower()
        for pid, p in processes.items():
            if (
                target_name in p.name.lower()
                or target_name in p.exe.lower()
                or target_name in p.cmdline.lower()
            ):
                matched_pids.add(pid)

        for s in sockets:
            if any(p in matched_pids for p in s.pids):
                matched_sockets.append(s)

    elif query_type == "list":
        for s in sockets:
            if s.state == "LISTEN":
                matched_sockets.append(s)
                matched_pids.update(s.pids)

    services = {}
    for pid in matched_pids:
        svc = correlate_systemd(pid, proc_dir=proc_dir)
        if svc:
            services[pid] = svc

    exposures = {}
    for s in matched_sockets:
        exp_data = analyze_exposure(s.local_address, s.family)
        exposures[s.local_endpoint] = exp_data

    containers = {}
    for s in matched_sockets:
        if s.local_port in docker_containers:
            containers[s.local_port] = docker_containers[s.local_port]

    return InspectionResult(
        query_type=query_type,
        query_target=query_target,
        sockets=matched_sockets,
        processes={p: processes[p] for p in matched_pids if p in processes},
        services=services,
        containers=containers,
        exposures=exposures,
        warnings=sock_warnings,
        permission_denied=perm_denied,
    )


def main() -> int:
    check_platform()
    parser = build_parser()
    args = parser.parse_args()

    color_flag = False if args.no_color else None

    if args.command == "list":
        res = run_inspection(query_type="list", query_target="all")
        if args.json:
            print(JsonFormatter().format(res))
        else:
            print(TerminalFormatter(color=color_flag).format(res, wide=args.wide))
        return 0

    if args.command == "pid":
        res = run_inspection(query_type="pid", query_target=str(args.pid_num))
        if args.json:
            print(JsonFormatter().format(res))
        else:
            print(TerminalFormatter(color=color_flag).format(res))
        return 0

    if args.command == "process":
        res = run_inspection(query_type="process", query_target=args.proc_name)
        if args.json:
            print(JsonFormatter().format(res))
        else:
            print(TerminalFormatter(color=color_flag).format(res))
        return 0

    if args.port:
        if not args.port.isdigit():
            sys.stderr.write(f"Error: Port argument must be an integer, got '{args.port}'.\n")
            return 2

        port_num = int(args.port)
        if not (1 <= port_num <= 65535):
            sys.stderr.write(f"Error: Invalid port number {port_num}. Must be in range 1-65535.\n")
            return 2

        res = run_inspection(query_type="port", query_target=str(port_num))
        if args.json:
            print(JsonFormatter().format(res))
        else:
            print(TerminalFormatter(color=color_flag).format(res))
        return 0

    parser.print_help()
    return 0