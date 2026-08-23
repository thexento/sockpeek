from __future__ import annotations

from unittest.mock import patch, MagicMock
from sockpeek.collectors.systemd import correlate_systemd


def test_correlate_systemd(tmp_path):
    proc_dir = tmp_path / "proc"
    pid_dir = proc_dir / "1821"
    pid_dir.mkdir(parents=True)

    cgroup_file = pid_dir / "cgroup"
    cgroup_file.write_text("0::/system.slice/api.service\n")

    with patch("sockpeek.collectors.systemd.run_command") as mock_run:
        mock_run.return_value = MagicMock(
            success=True,
            stdout="ActiveState=active\nLoadState=loaded\nDescription=API Service\n",
        )

        svc = correlate_systemd(1821, proc_dir=str(proc_dir))
        assert svc is not None
        assert svc.unit_name == "api.service"
        assert svc.active_state == "active"
        assert svc.load_state == "loaded"
        assert svc.description == "API Service"