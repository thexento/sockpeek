from __future__ import annotations

import json
from sockpeek.formatters.json import JsonFormatter
from sockpeek.formatters.terminal import TerminalFormatter
from sockpeek.models import InspectionResult, SocketInfo, ProcessInfo


def test_json_formatter():
    s = SocketInfo(
        protocol="tcp",
        family="ipv4",
        local_address="127.0.0.1",
        local_port=8080,
        remote_address="0.0.0.0",
        remote_port=0,
        state="LISTEN",
        inode=12345,
        pids=[1821],
    )
    p = ProcessInfo(pid=1821, name="node", user="deploy", cmdline="node server.js")

    res = InspectionResult(
        query_type="port",
        query_target="8080",
        sockets=[s],
        processes={1821: p},
    )

    formatted_json = JsonFormatter().format(res)
    parsed = json.loads(formatted_json)

    assert parsed["query"]["target"] == "8080"
    assert len(parsed["sockets"]) == 1
    assert parsed["sockets"][0]["local_port"] == 8080
    assert parsed["processes"]["1821"]["name"] == "node"


def test_terminal_formatter_no_color():
    res = InspectionResult(
        query_type="port",
        query_target="8080",
        sockets=[],
    )

    fmt = TerminalFormatter(color=False)
    output = fmt.format(res)
    assert "No socket or process matching '8080' was found." in output