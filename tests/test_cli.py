from __future__ import annotations

from sockpeek.cli import build_parser, run_inspection


def test_cli_parser():
    parser = build_parser()

    args = parser.parse_args(["8080"])
    assert args.port == "8080"
    assert args.command is None

    args_list = parser.parse_args(["list", "--wide"])
    assert args_list.command == "list"
    assert args_list.wide is True

    args_pid = parser.parse_args(["pid", "1821"])
    assert args_pid.command == "pid"
    assert args_pid.pid_num == 1821

    args_proc = parser.parse_args(["process", "nginx"])
    assert args_proc.command == "process"
    assert args_proc.proc_name == "nginx"


def test_run_inspection_empty(tmp_path):
    proc_dir = tmp_path / "proc"
    (proc_dir / "net").mkdir(parents=True)

    result = run_inspection(query_type="port", query_target="8080", proc_dir=str(proc_dir))
    assert result.query_type == "port"
    assert result.query_target == "8080"
    assert len(result.sockets) == 0