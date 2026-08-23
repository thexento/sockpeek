from __future__ import annotations

import os
import sys
from sockpeek.models import InspectionResult


class TerminalFormatter:
    """Renders InspectionResult into clean terminal output."""

    def __init__(self, color: bool | None = None) -> None:
        if color is None:
            no_color = bool(os.environ.get("NO_COLOR"))
            self.color_enabled = sys.stdout.isatty() and not no_color
        else:
            self.color_enabled = color

    def _c(self, code: str, text: str) -> str:
        if not self.color_enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self._c("1", text)

    def cyan(self, text: str) -> str:
        return self._c("36", text)

    def green(self, text: str) -> str:
        return self._c("32", text)

    def yellow(self, text: str) -> str:
        return self._c("33", text)

    def dim(self, text: str) -> str:
        return self._c("2", text)

    def format(self, result: InspectionResult, wide: bool = False) -> str:
        if result.query_type == "list":
            return self._format_list(result, wide=wide)
        return self._format_detail(result)

    def _format_detail(self, result: InspectionResult) -> str:
        lines: list[str] = []

        if not result.sockets and not result.processes:
            lines.append(self.yellow(f"No socket or process matching '{result.query_target}' was found."))
            if result.permission_denied:
                lines.append(
                    self.dim("\nNote: Some system information was restricted. Try running with sudo for complete details.")
                )
            return "\n".join(lines)

        lines.append(self.bold(f"=== Socket Inspection: {result.query_target} ==="))
        lines.append("")

        for s in result.sockets:
            lines.append(self.bold("SOCKET"))
            lines.append(f"  Endpoint:     {self.cyan(s.local_endpoint)} ({s.protocol.upper()}/{s.family})")
            lines.append(f"  State:        {s.green(s.state) if s.state in ('LISTEN', 'ESTABLISHED') else s.dim(s.state)}")
            if s.remote_port > 0:
                lines.append(f"  Remote:       {s.remote_endpoint}")
            lines.append(f"  Inode:        {s.inode}")
            lines.append("")

            exp = result.exposures.get(s.local_endpoint)
            if exp:
                lines.append(self.bold("EXPOSURE"))
                scope_color = self.green if exp.scope == "loopback" else (self.yellow if exp.scope == "wildcard" else self.cyan)
                lines.append(f"  Scope:        {scope_color(exp.label)}")
                lines.append(f"  Description:  {exp.description}")
                lines.append(f"  Note:         {self.dim(exp.disclaimer)}")
                lines.append("")

            container = result.containers.get(s.local_port)
            if container:
                lines.append(self.bold("DOCKER CONTAINER"))
                lines.append(f"  Name:         {self.cyan(container.name)}")
                lines.append(f"  ID:           {container.container_id}")
                lines.append(f"  Image:        {container.image}")
                lines.append(f"  Port Mapping: {container.host_port} -> {container.container_port}")
                lines.append("")

            pids = s.pids
            if not pids:
                lines.append(self.bold("PROCESS"))
                lines.append(self.dim("  Ownership:    No process ownership found or permission restricted."))
                lines.append("")
            else:
                for pid in pids:
                    proc = result.processes.get(pid)
                    if proc:
                        lines.append(self.bold("PROCESS"))
                        lines.append(f"  Name:         {self.cyan(proc.name)}")
                        lines.append(f"  PID:          {proc.pid}")
                        lines.append(f"  User:         {proc.user}")
                        if proc.exe:
                            lines.append(f"  Executable:   {proc.exe}")
                        if proc.cmdline:
                            lines.append(f"  Command:      {proc.cmdline}")
                        lines.append("")

                    svc = result.services.get(pid)
                    if svc:
                        lines.append(self.bold("SYSTEMD SERVICE"))
                        lines.append(f"  Unit:         {self.cyan(svc.unit_name)}")
                        lines.append(f"  State:        {svc.active_state} ({svc.load_state})")
                        if svc.description:
                            lines.append(f"  Description:  {svc.description}")
                        lines.append("")

        if result.permission_denied:
            lines.append(
                self.dim("Notice: Process ownership details were restricted due to insufficient privileges.")
            )
            lines.append(self.dim("Run with 'sudo sockpeek ...' to reveal all system processes."))

        return "\n".join(lines).strip()

    def _format_list(self, result: InspectionResult, wide: bool = False) -> str:
        if not result.sockets:
            msg = "No active listening sockets found."
            if result.permission_denied:
                msg += " (Note: Permission restrictions applied. Try sudo)."
            return msg

        lines: list[str] = []

        if wide:
            header = f"{'PORT':<8} {'PROTO':<6} {'STATE':<10} {'LISTEN ADDRESS':<22} {'PROCESS':<16} {'PID':<8} {'USER':<12} {'SERVICE/CONTAINER':<20}"
            lines.append(self.bold(header))
            lines.append(self.dim("-" * len(header)))

            for s in result.sockets:
                port_str = str(s.local_port)
                proto_str = s.protocol.upper()
                state_str = s.state
                addr_str = s.local_address

                proc_name = "-"
                pid_str = "-"
                user_str = "-"
                svc_cnt = "-"

                if s.pids:
                    pid_str = ",".join(str(p) for p in s.pids)
                    p0 = result.processes.get(s.pids[0])
                    if p0:
                        proc_name = p0.name
                        user_str = p0.user

                cnt = result.containers.get(s.local_port)
                if cnt:
                    svc_cnt = f"docker:{cnt.name}"
                elif s.pids:
                    s0 = result.services.get(s.pids[0])
                    if s0:
                        svc_cnt = s0.unit_name

                lines.append(
                    f"{self.cyan(port_str):<17} {proto_str:<6} {state_str:<10} {addr_str:<22} {proc_name:<16} {pid_str:<8} {user_str:<12} {svc_cnt:<20}"
                )
        else:
            header = f"{'PORT':<8} {'PROTO':<6} {'LISTEN ADDRESS':<20} {'PROCESS':<16} {'PID':<8} {'SERVICE/CONTAINER':<20}"
            lines.append(self.bold(header))
            lines.append(self.dim("-" * len(header)))

            for s in result.sockets:
                port_str = str(s.local_port)
                proto_str = s.protocol.upper()
                addr_str = s.local_address

                proc_name = "-"
                pid_str = "-"
                svc_cnt = "-"

                if s.pids:
                    pid_str = str(s.pids[0])
                    p0 = result.processes.get(s.pids[0])
                    if p0:
                        proc_name = p0.name

                cnt = result.containers.get(s.local_port)
                if cnt:
                    svc_cnt = f"docker:{cnt.name}"
                elif s.pids:
                    s0 = result.services.get(s.pids[0])
                    if s0:
                        svc_cnt = s0.unit_name

                lines.append(
                    f"{self.cyan(port_str):<17} {proto_str:<6} {addr_str:<20} {proc_name:<16} {pid_str:<8} {svc_cnt:<20}"
                )

        if result.permission_denied:
            lines.append("")
            lines.append(
                self.dim("Note: Some process information was restricted. Run with sudo for complete details.")
            )

        return "\n".join(lines)