# sockpeek

Inspecting sockets, processes, ports, and service ownership in a simple Linux CLI.

[![PyPI](https://img.shields.io/pypi/v/sockpeek)](https://pypi.org/project/sockpeek/)
[![Python](https://img.shields.io/pypi/pyversions/sockpeek)](https://pypi.org/project/sockpeek/)
[![License](https://img.shields.io/github/license/thexento/sockpeek)](https://github.com/thexento/sockpeek)

sockpeek is a Linux socket diagnostic CLI that helps answer:

> What is using this socket, how is it exposed, and where does the traffic go?

It correlates Linux socket information with process ownership, process metadata,
systemd services, Docker containers, and basic exposure analysis so that common
networking problems can be investigated without manually combining several
system tools.

## Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Output](#output)
- [Exposure Analysis](#exposure-analysis)
- [Permissions](#permissions)
- [JSON Output](#json-output)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Security](#security)
- [Requirements](#requirements)
- [Development](#development)
- [Testing](#testing)
- [Project Scope](#project-scope)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Links](#links)

## Overview

Linux already provides excellent tools for inspecting sockets and processes:

```text
ss
lsof
fuser
ps
systemctl
docker
```

The difficulty is that a simple question such as:

```text
What is using port 8080?
```

can require several commands and manual correlation.

With sockpeek, the starting point is:

```bash
sockpeek 8080
```

The tool gathers relevant information and presents it as a single diagnostic
view.

sockpeek is not intended to replace the underlying Linux tools. Its purpose is
to provide a useful interpretation layer on top of the information they and
the Linux kernel already expose.

## Features

### Port inspection

Inspect a specific port:

```bash
sockpeek 8080
```

The inspection can include:

- protocol
- IPv4 or IPv6 family
- local address
- local port
- remote address and port when applicable
- socket state
- socket inode
- owning PID or PIDs
- process name
- process user
- executable
- command line
- working directory
- parent PID
- systemd service information
- Docker container information
- binding/exposure analysis

### Listening socket listing

List active listening sockets:

```bash
sockpeek list
```

Use the wide layout for additional process and ownership information:

```bash
sockpeek list --wide
```

### PID inspection

Inspect sockets associated with a process ID:

```bash
sockpeek pid 1821
```

### Process-name inspection

Search for sockets associated with a process by name:

```bash
sockpeek process nginx
```

The process search checks the process name, executable path, and command line.

### Exposure analysis

sockpeek categorizes the local address of a socket into useful scopes such as:

- localhost / loopback
- wildcard
- private/internal address
- specific public address
- unknown

The result is deliberately presented as an observation rather than a claim
about actual Internet reachability.

### systemd correlation

When a process belongs to a systemd service, sockpeek can inspect its cgroup
and correlate the process with the relevant service unit.

It can report:

- service unit
- active state
- load state
- service description

### Docker correlation

When Docker is installed and accessible, sockpeek can inspect running
containers and correlate published host ports with container ports.

It can report:

- container ID
- container name
- image
- host port
- container port
- protocol

Docker is optional and is not required for core socket inspection.

### JSON output

All inspection results can be rendered as structured JSON:

```bash
sockpeek 8080 --json
```

This makes sockpeek useful in shell scripts, automation, monitoring, and other
developer tooling.

### No heavy runtime dependencies

The current implementation uses Python's standard library for the core
application and does not require a runtime framework or external Python
dependency.

Development uses pytest for the test suite.

### Read-only diagnostics

The current command set is diagnostic and non-destructive.

sockpeek does not:

- kill processes
- stop services
- restart services
- change firewall rules
- modify network configuration
- stop containers

## Installation

### From PyPI

Install the published package with pip:

```bash
python -m pip install sockpeek
```

For a standalone CLI installation, pipx can also be used:

```bash
pipx install sockpeek
```

PyPI:

https://pypi.org/project/sockpeek/

### From source

Clone the repository:

```bash
git clone https://github.com/thexento/sockpeek.git
cd sockpeek
```

Install the package:

```bash
python -m pip install .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Quick Start

Inspect a port:

```bash
sockpeek 8080
```

List active listeners:

```bash
sockpeek list
```

Inspect a process:

```bash
sockpeek pid 1821
```

Search by process name:

```bash
sockpeek process nginx
```

Get JSON output:

```bash
sockpeek 8080 --json
```

Disable terminal colors:

```bash
sockpeek 8080 --no-color
```

Show help:

```bash
sockpeek --help
```

Show the installed version:

```bash
sockpeek --version
```

## Commands

### `sockpeek <port>`

Inspect sockets using a specific local port.

```bash
sockpeek 8080
```

The port must be an integer from `1` through `65535`.

Example:

```text
=== Socket Inspection: 8080 ===

SOCKET
  Endpoint:     127.0.0.1:8080 (TCP/ipv4)
  State:        LISTEN
  Inode:        48291

EXPOSURE
  Scope:        Localhost only
  Description:  Bound to loopback address 127.0.0.1. Accessible only from this local machine.
  Note:         Restricted to local connections unless forwarded by a local reverse proxy.

PROCESS
  Name:         node
  PID:          1821
  User:         deploy
  Executable:   /usr/bin/node
  Command:      node /srv/api/server.js

SYSTEMD SERVICE
  Unit:         api.service
  State:        active (loaded)
  Description:  Backend API Web Service
```

The actual output depends on the socket and information available on the
machine.

### `sockpeek list`

List active listening sockets:

```bash
sockpeek list
```

The normal layout focuses on the information most useful during a quick
inspection.

### `sockpeek list --wide`

Display a wider table containing additional ownership information:

```bash
sockpeek list --wide
```

The wide layout can include:

```text
PORT
PROTO
STATE
LISTEN ADDRESS
PROCESS
PID
USER
SERVICE/CONTAINER
```

### `sockpeek pid <pid>`

Inspect sockets owned by a process ID:

```bash
sockpeek pid 1821
```

This is useful when the process is already known and the question is:

```text
Which sockets does this process have?
```

### `sockpeek process <name>`

Inspect sockets associated with a process name:

```bash
sockpeek process nginx
```

Matching is case-insensitive and considers:

- process name
- executable path
- command line

### Global options

#### `--json`

Render the inspection result as JSON:

```bash
sockpeek 8080 --json
```

#### `--no-color`

Disable terminal color output:

```bash
sockpeek 8080 --no-color
```

The `NO_COLOR` environment variable is also respected when color is being
automatically detected.

#### `--version`

Display the installed version:

```bash
sockpeek --version
```

#### `--help`

Display command-line help:

```bash
sockpeek --help
```

## Output

sockpeek separates its output into diagnostic sections instead of presenting a
raw dump of kernel data.

A port inspection can contain sections such as:

```text
SOCKET
EXPOSURE
DOCKER CONTAINER
PROCESS
SYSTEMD SERVICE
```

The sections shown depend on what information is available.

For example, a local development server might produce information conceptually
similar to:

```text
=== Socket Inspection: 3000 ===

SOCKET
  Endpoint:     127.0.0.1:3000 (TCP/ipv4)
  State:        LISTEN
  Inode:        52184

EXPOSURE
  Scope:        Localhost only
  Description:  Bound to loopback address 127.0.0.1. Accessible only from this local machine.

PROCESS
  Name:         node
  PID:          2314
  User:         xento
  Executable:   /usr/bin/node
  Command:      node server.js
```

sockpeek intentionally avoids dumping every available field into the default
view. More information belongs in appropriate detailed or machine-readable
output.

## Exposure Analysis

One of the project's important principles is distinguishing **binding scope**
from **actual network reachability**.

For example:

```text
127.0.0.1:8080
```

is a loopback binding and is normally accessible only from the local machine.

A wildcard binding such as:

```text
0.0.0.0:8080
```

means that the socket is listening on all IPv4 interfaces.

Similarly:

```text
[::]:8080
```

is an IPv6 wildcard binding.

A wildcard binding does not automatically mean that the service is reachable
from the public Internet.

Actual reachability can also depend on:

- host firewall rules
- cloud security groups
- NAT
- routing
- upstream firewalls
- network topology
- container networking
- provider-level network controls

For that reason, sockpeek uses language such as:

```text
Bound to all interfaces.
External reachability depends on network firewalls, cloud security groups, and routing.
```

rather than claiming:

```text
This port is publicly accessible.
```

unless that fact can actually be established.

### Exposure categories

The current exposure analyzer recognizes:

| Scope | Meaning |
|---|---|
| `loopback` | Bound to a loopback address |
| `wildcard` | Bound to an unspecified/wildcard address |
| `private` | Bound to a private IP address |
| `public` | Bound to a specific public IP address |
| `unknown` | Address could not be classified |

These categories describe the socket's local binding. They are not a complete
firewall or Internet-reachability test.

## IPv4 and IPv6

sockpeek reads both IPv4 and IPv6 socket tables.

Examples:

```text
127.0.0.1:8080
0.0.0.0:8080
[::1]:8080
[::]:8080
```

IPv6 endpoints are formatted with brackets so that the address and port remain
unambiguous.

The implementation also handles IPv4-mapped IPv6 addresses when encountered in
the Linux socket tables.

## Permissions

sockpeek is designed to work as an unprivileged user wherever possible.

Some process information may be restricted by Linux permissions. In that case,
the tool continues with the information it can access and reports that some
ownership information was unavailable.

For example:

```text
Notice: Process ownership details were restricted due to insufficient privileges.
Run with 'sudo sockpeek ...' to reveal all system processes.
```

For a complete inspection on systems with restrictive `/proc` permissions:

```bash
sudo sockpeek 8080
```

Running as root is not a requirement for the basic command.

## JSON Output

JSON output is generated from the same normalized inspection data used by the
terminal formatter.

Example:

```bash
sockpeek 8080 --json
```

Example structure:

```json
{
  "query": {
    "type": "port",
    "target": "8080"
  },
  "sockets": [
    {
      "protocol": "tcp",
      "family": "ipv4",
      "local_address": "127.0.0.1",
      "local_port": 8080,
      "local_endpoint": "127.0.0.1:8080",
      "remote_address": "0.0.0.0",
      "remote_port": 0,
      "remote_endpoint": "0.0.0.0:0",
      "state": "LISTEN",
      "inode": 48291,
      "pids": [
        1821
      ]
    }
  ],
  "processes": {
    "1821": {
      "pid": 1821,
      "name": "node",
      "user": "deploy",
      "exe": "/usr/bin/node",
      "cmdline": "node /srv/api/server.js",
      "cwd": "/srv/api",
      "ppid": 1
    }
  },
  "services": {},
  "containers": {},
  "exposures": {},
  "warnings": [],
  "permission_denied": false
}
```

The JSON schema is intended for automation, but fields may evolve as the
project develops. Consumers should avoid assuming that future versions will
never add fields.

## How It Works

The current implementation uses Linux's `/proc` filesystem as the primary
source for socket and process information.

The general correlation flow is:

```text
/proc/net/tcp
/proc/net/tcp6
/proc/net/udp
/proc/net/udp6
        |
        v
Socket information
        |
        v
Socket inode
        |
        v
/proc/<pid>/fd
        |
        v
Process ownership
        |
        +-------------------+
        |                   |
        v                   v
/proc/<pid>/...         /proc/<pid>/cgroup
process metadata             |
                             v
                         systemd unit
        |
        +-------------------+
        |
        v
Docker published ports
        |
        v
Normalized inspection result
        |
        +----------------------+
        |                      |
        v                      v
Terminal formatter       JSON formatter
```

This approach avoids relying entirely on the human-readable output of tools
such as `ss` or `lsof`.

### Socket collection

sockpeek reads:

```text
/proc/net/tcp
/proc/net/tcp6
/proc/net/udp
/proc/net/udp6
```

It parses:

- local address
- local port
- remote address
- remote port
- protocol
- address family
- socket state
- inode

### Process correlation

Linux exposes socket file descriptors through process `/proc` entries.

sockpeek scans process file descriptors and maps socket inodes to PIDs.

It then reads process information such as:

```text
/proc/<pid>/comm
/proc/<pid>/cmdline
/proc/<pid>/exe
/proc/<pid>/cwd
/proc/<pid>/status
```

This allows a socket to be correlated with its owning process.

### systemd correlation

For a matched PID, sockpeek checks its cgroup information:

```text
/proc/<pid>/cgroup
```

When a relevant `.service` or `.socket` unit is found, sockpeek can query
systemd for:

- ActiveState
- LoadState
- Description

systemd is therefore an enrichment layer rather than a requirement for socket
inspection.

### Docker correlation

When Docker is available, sockpeek invokes the Docker CLI without shell
execution and inspects running containers.

Published host ports are then correlated with matching socket ports.

If Docker is missing, stopped, inaccessible, or returns no usable information,
the core socket inspection continues.

## Architecture

The project uses a small source layout with clear responsibilities:

```text
sockpeek/
├── pyproject.toml
├── LICENSE
├── README.md
├── src/
│   └── sockpeek/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── models.py
│       ├── collectors/
│       │   ├── __init__.py
│       │   ├── docker.py
│       │   ├── processes.py
│       │   ├── sockets.py
│       │   └── systemd.py
│       ├── formatters/
│       │   ├── __init__.py
│       │   ├── json.py
│       │   └── terminal.py
│       └── utils/
│           ├── __init__.py
│           ├── commands.py
│           └── network.py
└── tests/
    ├── __init__.py
    ├── test_cli.py
    ├── test_docker.py
    ├── test_formatters.py
    ├── test_network.py
    ├── test_processes.py
    ├── test_sockets.py
    └── test_systemd.py
```

The main components are:

### `models.py`

Defines normalized data structures such as:

- `SocketInfo`
- `ProcessInfo`
- `ServiceInfo`
- `ContainerInfo`
- `ExposureInfo`
- `InspectionResult`

### `collectors/`

Collects information from Linux and optional integrations.

### `formatters/`

Turns the normalized result into either:

- terminal output
- JSON

### `utils/network.py`

Handles Linux network address parsing and exposure categorization.

### `utils/commands.py`

Provides controlled external command execution.

External commands are executed using argument lists and without `shell=True`.

## Security

Security is important because sockpeek is intended for server administration
and troubleshooting.

The current implementation follows several principles.

### No unnecessary shell execution

External commands are invoked as argument arrays rather than interpolated shell
commands.

For example, the implementation uses the equivalent of:

```python
subprocess.run(
    args,
    ...
    shell=False,
)
```

This avoids unnecessarily passing user-controlled values through a shell.

### Input validation

Port arguments are validated before inspection.

Valid ports are:

```text
1-65535
```

Invalid input is rejected instead of being passed to system commands.

### Read-only behavior

The current application performs diagnostics only.

It does not modify:

- processes
- services
- containers
- firewall rules
- network configuration

### No automatic security conclusions

A listening socket is not automatically treated as a vulnerability.

sockpeek reports observable binding information and provides appropriate
context instead of pretending that it can prove complete network exposure from
a local socket table alone.

## Requirements

### Runtime

- Linux
- Python 3.10 or newer

The package currently declares no required Python runtime dependencies.

### Optional system components

The following are optional:

- systemd
- Docker

Their absence should not prevent core socket inspection.

### Development

The development test suite uses:

```text
pytest >= 7.0
```

## Supported Linux Environments

sockpeek targets Linux rather than attempting to provide cross-platform socket
diagnostics.

The implementation is intended for common Linux distributions including:

- Ubuntu
- Debian
- Fedora
- Arch Linux
- other distributions exposing the expected `/proc` interfaces

Distribution-specific behavior may still exist around permissions, systemd,
Docker, and kernel configuration.

## Development

Clone the repository:

```bash
git clone https://github.com/thexento/sockpeek.git
cd sockpeek
```

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install the package with development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the CLI:

```bash
sockpeek --help
```

Run it as a Python module:

```bash
python -m sockpeek --help
```

## Testing

Run the test suite:

```bash
pytest
```

The test suite covers the main data collection and correlation components,
including:

- IPv4 parsing
- IPv6 parsing
- exposure classification
- socket collection
- process collection
- socket-to-process mapping
- systemd correlation
- Docker correlation
- CLI argument parsing
- JSON formatting
- terminal formatting

The tests use temporary `/proc`-like structures and mocks where appropriate so
that core logic can be tested without depending entirely on the host system.

## Project Scope

sockpeek intentionally focuses on a narrow problem:

> Make Linux socket and service investigation easier.

It is not intended to become a complete server management platform.

### Not a replacement for `ss`

`ss` remains an excellent low-level socket inspection tool.

sockpeek adds correlation and interpretation rather than attempting to reproduce
every capability of `ss`.

### Not a replacement for `lsof`

`lsof` provides broad file and process inspection capabilities.

sockpeek focuses specifically on socket-oriented diagnostics.

### Not a process manager

sockpeek does not manage process lifecycles.

### Not a firewall manager

sockpeek does not configure firewall rules.

### Not a vulnerability scanner

Exposure analysis describes socket binding scope. It is not a vulnerability
assessment.

### Not a network monitoring system

The current release does not attempt to provide packet capture, bandwidth
monitoring, or full traffic analysis.

## Design Principles

The project is guided by a small set of principles.

### Simple questions should have simple answers

A command such as:

```bash
sockpeek 8080
```

should be enough to begin answering:

```text
What is using port 8080?
```

### Correlation is the value

The project should not become:

```text
ss with colors
```

The useful layer is the relationship between:

```text
socket -> process -> service -> container -> binding context
```

### Correctness over assumptions

If a relationship cannot be established reliably, sockpeek should report that
fact rather than inventing one.

### Graceful degradation

Optional information should not prevent the core inspection from working.

### Minimal dependencies

The standard library should be preferred when it provides a suitable solution.

### Fast and predictable

The CLI is designed for normal use over SSH and on server environments where
startup time and simple behavior matter.

### Human-readable by default

The default output is optimized for a person investigating a problem.

JSON is available when the consumer is another program.

## Roadmap

The project is intentionally developed incrementally.

### Current foundation

- [x] Port inspection
- [x] Socket information from `/proc`
- [x] TCP and UDP inspection
- [x] IPv4 and IPv6 support
- [x] Socket-to-process correlation
- [x] Process metadata
- [x] Binding/exposure analysis
- [x] systemd correlation
- [x] Docker port correlation
- [x] Human-readable output
- [x] JSON output
- [x] PID inspection
- [x] Process-name inspection
- [x] Listening socket listing
- [x] Wide list output
- [x] Permission-aware behavior
- [x] Basic test suite

### Planned

- [ ] Watch mode
- [ ] More advanced traffic-path explanation
- [ ] `doctor` diagnostic mode
- [ ] More robust Docker port correlation
- [ ] Nginx reverse-proxy correlation
- [ ] Network namespace inspection
- [ ] Firewall correlation
- [ ] Additional Linux-specific diagnostics

Planned features are intentionally not treated as requirements for the core
project. New functionality should be added only when it provides reliable,
practical diagnostic value.

## Contributing

Contributions are welcome.

Before implementing a feature, consider whether it fits the project's core
purpose and whether the behavior can be made reliable across Linux
environments.

### Guidelines

1. Keep changes focused.
2. Prefer simple implementations.
3. Add tests for new behavior.
4. Avoid unnecessary dependencies.
5. Preserve existing CLI behavior where practical.
6. Handle Linux permission restrictions.
7. Do not assume Docker is installed.
8. Do not assume systemd is available.
9. Keep terminal output readable.
10. Keep JSON output structured and predictable.
11. Avoid unnecessary abstractions.
12. Do not turn uncertain observations into definitive claims.

### Pull requests

A useful pull request should explain:

- what changed
- why it changed
- how it was tested
- whether the CLI output changed
- whether JSON output changed
- whether additional system dependencies are required

## License

sockpeek is licensed under the MIT License.

See [LICENSE](LICENSE) for the complete license text.

## Links

- PyPI: https://pypi.org/project/sockpeek
- Website: https://sockpeek.xento.us.kg
- GitHub: https://github.com/thexento/sockpeek

## Developer

**Xento**

GitHub: https://github.com/thexento

---

sockpeek

Inspecting sockets, processes, ports, and service ownership in a simple Linux CLI.
