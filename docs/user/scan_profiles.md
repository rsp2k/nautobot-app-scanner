# Scan Profiles

A `ScanProfile` is a reusable nmap argument template — name, scan type,
raw nmap flags, timing template, and an optional list of NSE scripts.
The same profile can be re-used by any agent for any target.

<figure markdown>
![Scan profiles list view](../images/profiles-list.png)
<figcaption>Scan profiles list — each row links to a detail/edit page; the **Add Scan Profile** button creates a new one.</figcaption>
</figure>

## Why profiles exist

You probably don't want operators typing nmap arguments into the Run
Scan job every time. Profiles let you curate a small set of vetted
recipes (`discovery-fast`, `tcp-full-vuln`, `udp-top-100`, etc.) and
let operators pick by name.

The `scan_type` field is a coarse classification used by table filters
and panel-rendering decisions — but `nmap_arguments` is always the
source of truth for what gets passed to the binary.

## Common profile recipes

### Host discovery (fastest)

| Field | Value |
|-------|-------|
| `scan_type` | `discovery` |
| `nmap_arguments` | `-sn` |
| `timing_template` | `T3` |

ARP scan on local subnets, ICMP/TCP-ACK on routed networks. No port
scan. Finishes a /24 in seconds.

### TCP top-1000 with service version

| Field | Value |
|-------|-------|
| `scan_type` | `version` |
| `nmap_arguments` | `-sS -sV --top-ports 1000` |
| `timing_template` | `T4` |

SYN scan of the most common 1000 TCP ports plus `-sV` service/version
detection. Populates `DiscoveredPort.product` / `version` / `extra_info`
/ `cpe`.

### Full TCP + OS fingerprint

| Field | Value |
|-------|-------|
| `scan_type` | `port` |
| `nmap_arguments` | `-sS -O -p-` |
| `timing_template` | `T4` |

All 65,535 TCP ports + OS detection. Slow. Populates
`DiscoveredHost.os_family` / `os_type` / `os_accuracy`.

### Vulnerability scripts (vulners)

| Field | Value |
|-------|-------|
| `scan_type` | `vuln` |
| `nmap_arguments` | `-sV --script vulners` |
| `timing_template` | `T3` |
| `enabled_scripts` | `["vulners"]` |

`-sV` first (vulners needs version output), then runs the `vulners`
NSE script to look up known CVEs against detected service versions.
Populates `VulnerabilityFinding` records hanging off each port.

### Topology / traceroute

| Field | Value |
|-------|-------|
| `scan_type` | `topology` |
| `nmap_arguments` | `-sn --traceroute` |
| `timing_template` | `T3` |

Host discovery + path tracing. Populates `TraceRouteHop` records per
host.

## What you cannot put in `nmap_arguments`

The backend appends targets to whatever you specify in
`nmap_arguments`. **Do not include target specifications** in the
profile — they come from the Scan's `target_prefixes` /
`target_ipaddresses` at dispatch time.

The backend also appends `-oX -` to capture XML output on stdout. **Do
not specify `-oX` or other output flags** in the profile — they'll
collide.

## NSE script-name validation

The `enabled_scripts` JSON field is informational — it's a hint for
operators about which scripts a profile uses. It does **not**
automatically get appended to the nmap command line. To run scripts,
include `--script <name>` in `nmap_arguments` explicitly.

## Timing templates

| Template | Meaning | Typical use |
|----------|---------|------------|
| `T0` | Paranoid | IDS evasion (~5 min per host) |
| `T1` | Sneaky | IDS evasion (~15 sec per port) |
| `T2` | Polite | Slow / quiet (default in some firewalls) |
| `T3` | Normal | Default — balanced |
| `T4` | Aggressive | Fast, modern networks — recommended |
| `T5` | Insane | Very fast, packet loss likely |
