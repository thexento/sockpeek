from __future__ import annotations

from sockpeek.collectors.sockets import collect_sockets_from_proc


def test_collect_sockets_from_proc(tmp_path):
    proc_dir = tmp_path / "proc"
    net_dir = proc_dir / "net"
    net_dir.mkdir(parents=True)

    tcp_file = net_dir / "tcp"
    tcp_content = (
        "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 -1\n"
    )
    tcp_file.write_text(tcp_content)

    sockets, warnings = collect_sockets_from_proc(proc_dir=str(proc_dir))
    assert len(sockets) == 1
    s = sockets[0]
    assert s.protocol == "tcp"
    assert s.family == "ipv4"
    assert s.local_address == "127.0.0.1"
    assert s.local_port == 80
    assert s.state == "LISTEN"
    assert s.inode == 12345
    assert not warnings