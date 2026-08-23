from __future__ import annotations

from unittest.mock import patch, MagicMock
from sockpeek.collectors.docker import collect_docker_containers


def test_collect_docker_containers():
    docker_ps_output = (
        "3f8a21b8c0d1\tminecraft\titzg/minecraft-server\t0.0.0.0:25565->25565/tcp\n"
    )

    with patch("sockpeek.collectors.docker.run_command") as mock_run:
        mock_run.return_value = MagicMock(
            success=True,
            stdout=docker_ps_output,
        )

        containers = collect_docker_containers()
        assert 25565 in containers
        c = containers[25565]
        assert c.name == "minecraft"
        assert c.image == "itzg/minecraft-server"
        assert c.host_port == 25565
        assert c.container_port == "25565/tcp"