from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SocketInfo:
    protocol: str  # "tcp" or "udp"
    family: str  # "ipv4" or "ipv6"
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str  # e.g., "LISTEN", "ESTABLISHED", "UNCONN"
    inode: int
    pids: list[int] = field(default_factory=list)

    @property
    def local_endpoint(self) -> str:
        if self.family == "ipv6" and ":" in self.local_address:
            return f"[{self.local_address}]:{self.local_port}"
        return f"{self.local_address}:{self.local_port}"

    @property
    def remote_endpoint(self) -> str:
        if self.family == "ipv6" and ":" in self.remote_address:
            return f"[{self.remote_address}]:{self.remote_port}"
        return f"{self.remote_address}:{self.remote_port}"


@dataclass
class ProcessInfo:
    pid: int
    name: str
    user: str
    exe: str = ""
    cmdline: str = ""
    cwd: str = ""
    ppid: int = 0


@dataclass
class ServiceInfo:
    unit_name: str
    active_state: str = "unknown"
    load_state: str = "unknown"
    description: str = ""


@dataclass
class ContainerInfo:
    container_id: str
    name: str
    image: str
    host_port: int
    container_port: str
    protocol: str


@dataclass
class ExposureInfo:
    scope: str  # "loopback", "wildcard", "private", "public", "unknown"
    label: str
    description: str
    disclaimer: str


@dataclass
class InspectionResult:
    query_type: str  # "port", "pid", "process", "list"
    query_target: str
    sockets: list[SocketInfo] = field(default_factory=list)
    processes: dict[int, ProcessInfo] = field(default_factory=dict)
    services: dict[int, ServiceInfo] = field(default_factory=dict)
    containers: dict[int, ContainerInfo] = field(default_factory=dict)  # host_port -> ContainerInfo
    exposures: dict[str, ExposureInfo] = field(default_factory=dict)  # endpoint -> ExposureInfo
    warnings: list[str] = field(default_factory=list)
    permission_denied: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert inspection result into a clean, JSON-serializable dictionary."""
        return {
            "query": {
                "type": self.query_type,
                "target": self.query_target,
            },
            "sockets": [
                {
                    "protocol": s.protocol,
                    "family": s.family,
                    "local_address": s.local_address,
                    "local_port": s.local_port,
                    "local_endpoint": s.local_endpoint,
                    "remote_address": s.remote_address,
                    "remote_port": s.remote_port,
                    "remote_endpoint": s.remote_endpoint,
                    "state": s.state,
                    "inode": s.inode,
                    "pids": s.pids,
                }
                for s in self.sockets
            ],
            "processes": {
                str(pid): {
                    "pid": p.pid,
                    "name": p.name,
                    "user": p.user,
                    "exe": p.exe,
                    "cmdline": p.cmdline,
                    "cwd": p.cwd,
                    "ppid": p.ppid,
                }
                for pid, p in self.processes.items()
            },
            "services": {
                str(pid): {
                    "unit": s.unit_name,
                    "active_state": s.active_state,
                    "load_state": s.load_state,
                    "description": s.description,
                }
                for pid, s in self.services.items()
            },
            "containers": {
                str(port): {
                    "container_id": c.container_id,
                    "name": c.name,
                    "image": c.image,
                    "host_port": c.host_port,
                    "container_port": c.container_port,
                    "protocol": c.protocol,
                }
                for port, c in self.containers.items()
            },
            "exposures": {
                endpoint: {
                    "scope": exp.scope,
                    "label": exp.label,
                    "description": exp.description,
                    "disclaimer": exp.disclaimer,
                }
                for endpoint, exp in self.exposures.items()
            },
            "warnings": self.warnings,
            "permission_denied": self.permission_denied,
        }