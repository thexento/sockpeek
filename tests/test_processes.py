from __future__ import annotations

import os
import pytest
from sockpeek.collectors.processes import collect_processes


def test_collect_processes(tmp_path):
    proc_dir = tmp_path / "proc"
    pid_dir = proc_dir / "1821"
    fd_dir = pid_dir / "fd"
    fd_dir.mkdir(parents=True)

    (pid_dir / "comm").write_text("node\n")
    (pid_dir / "cmdline").write_bytes(b"node\x00/srv/server.js\x00")

    fd_3 = fd_dir / "3"
    try:
        os.symlink("socket:[12345]", fd_3)
    except OSError:
        pytest.skip("Symlinks not supported in testing environment")

    processes, inode_map, perm_denied = collect_processes(proc_dir=str(proc_dir))

    assert 1821 in processes
    proc = processes[1821]
    assert proc.name == "node"
    assert proc.cmdline == "node /srv/server.js"
    assert 12345 in inode_map
    assert inode_map[12345] == [1821]
    assert not perm_denied