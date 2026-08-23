from __future__ import annotations

import re
from sockpeek.models import ContainerInfo
from sockpeek.utils.commands import run_command


def collect_docker_containers() -> dict[int, ContainerInfo]:
    """Inspect running Docker containers and map published host ports to ContainerInfo."""
    containers: dict[int, ContainerInfo] = {}

    res = run_command(
        ["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}"],
        timeout=2.0,
    )

    if not res.success or not res.stdout:
        return containers

    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue

        cid, name, image, ports_str = parts[0], parts[1], parts[2], parts[3]
        if not ports_str:
            continue

        mappings = re.findall(r"(?:[\d\.\:\*]+:)?(\d+)->(\d+/(?:tcp|udp))", ports_str)
        for host_p_str, container_p_str in mappings:
            try:
                host_port = int(host_p_str)
                proto = "tcp"
                if "/udp" in container_p_str:
                    proto = "udp"

                containers[host_port] = ContainerInfo(
                    container_id=cid[:12],
                    name=name,
                    image=image,
                    host_port=host_port,
                    container_port=container_p_str,
                    protocol=proto,
                )
            except ValueError:
                continue

    return containers