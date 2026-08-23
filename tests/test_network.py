from __future__ import annotations

from sockpeek.utils.network import parse_proc_ipv4, parse_proc_ipv6, analyze_exposure


def test_parse_proc_ipv4():
    addr, port = parse_proc_ipv4("0100007F:0050")
    assert addr == "127.0.0.1"
    assert port == 80

    addr, port = parse_proc_ipv4("00000000:1F90")
    assert addr == "0.0.0.0"
    assert port == 8080


def test_parse_proc_ipv6():
    addr, port = parse_proc_ipv6("00000000000000000000000000000000:0050")
    assert addr == "::"
    assert port == 80

    addr, port = parse_proc_ipv6("0000000000000000000000000100007F:1F90")
    assert addr == "::1"
    assert port == 8080


def test_analyze_exposure():
    exp_loopback = analyze_exposure("127.0.0.1", "ipv4")
    assert exp_loopback["scope"] == "loopback"
    assert "Localhost" in exp_loopback["label"]

    exp_wildcard = analyze_exposure("0.0.0.0", "ipv4")
    assert exp_wildcard["scope"] == "wildcard"
    assert "Externally bound" in exp_wildcard["label"]

    exp_private = analyze_exposure("10.0.0.5", "ipv4")
    assert exp_private["scope"] == "private"

    exp_public = analyze_exposure("1.1.1.1", "ipv4")
    assert exp_public["scope"] == "public"