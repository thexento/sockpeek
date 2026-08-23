from __future__ import annotations

import ipaddress
import socket
import struct


def parse_proc_ipv4(hex_addr: str) -> tuple[str, int]:
    """Parse /proc/net/tcp address field like '0100007F:0050'."""
    try:
        addr_hex, port_hex = hex_addr.split(":")
        port = int(port_hex, 16)
        ip_int = int(addr_hex, 16)
        ip_bytes = struct.pack("<I", ip_int)
        ip_str = socket.inet_ntop(socket.AF_INET, ip_bytes)
        return ip_str, port
    except (ValueError, OSError, struct.error) as err:
        raise ValueError(f"Invalid proc IPv4 address format '{hex_addr}'") from err


def parse_proc_ipv6(hex_addr: str) -> tuple[str, int]:
    """Parse /proc/net/tcp6 address field like '0000000000000000000000000100007F:0050'."""
    try:
        addr_hex, port_hex = hex_addr.split(":")
        port = int(port_hex, 16)
        if len(addr_hex) != 32:
            raise ValueError(f"IPv6 hex must be 32 chars, got {len(addr_hex)}")

        words = [addr_hex[i : i + 8] for i in range(0, 32, 8)]
        ip_bytes = b"".join(struct.pack("<I", int(w, 16)) for w in words)
        ip_obj = ipaddress.IPv6Address(ip_bytes)

        if ip_obj.ipv4_mapped:
            return str(ip_obj.ipv4_mapped), port

        return str(ip_obj), port
    except (ValueError, OSError, struct.error) as err:
        raise ValueError(f"Invalid proc IPv6 address format '{hex_addr}'") from err


def analyze_exposure(address: str, family: str) -> dict[str, str]:
    """Categorize exposure scope based on IP address and family."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return {
            "scope": "unknown",
            "label": "Unknown Address",
            "description": f"Unable to parse IP address: {address}",
            "disclaimer": "Address validity could not be determined.",
        }

    if ip.is_unspecified:
        fam_str = "IPv4" if family == "ipv4" else ("IPv6" if family == "ipv6" else "IP")
        return {
            "scope": "wildcard",
            "label": f"Externally bound (All {fam_str} interfaces)",
            "description": f"Listening on wildcard address {address} (0.0.0.0 or ::). Accessible on any network interface.",
            "disclaimer": "Bound to all interfaces. External reachability depends on network firewalls, cloud security groups, and routing.",
        }

    if ip.is_loopback:
        return {
            "scope": "loopback",
            "label": "Localhost only",
            "description": f"Bound to loopback address {address}. Accessible only from this local machine.",
            "disclaimer": "Restricted to local connections unless forwarded by a local reverse proxy.",
        }

    if ip.is_private:
        return {
            "scope": "private",
            "label": "Internal network bound",
            "description": f"Bound to private IP address {address}. Accessible within the local/virtual network.",
            "disclaimer": "Private address scope. Reachable within local subnets or via configured routing.",
        }

    return {
        "scope": "public",
        "label": "Specific interface bound (Public IP)",
        "description": f"Bound directly to public IP address {address}.",
        "disclaimer": "Bound to specific external IP. Access depends on firewall and routing policies.",
    }