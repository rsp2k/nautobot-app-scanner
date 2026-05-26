# DiscoveredPort

One port nmap reported on a `DiscoveredHost`. Fingerprint fields
(`product`, `version`, `extra_info`, `cpe`) live here directly rather
than on a separate `ServiceFingerprint` model — see
[ADR-008](../dev/architecture.md#adr-008-os_type-on-host-fingerprint-fields-on-port).

| Field | Description |
|-------|-------------|
| `discovered_host` | FK to `DiscoveredHost` (CASCADE) |
| `port` | PositiveIntegerField (1-65535) |
| `protocol` | CharField (choices=`ProtocolChoices`) — `tcp` / `udp` / `sctp` |
| `state` | CharField (choices=`PortStateChoices`) — `open` / `closed` / `filtered` / `unfiltered` / `open\|filtered` / `closed\|filtered` |
| `service_name` | CharField — nmap's identification (e.g. `http`, `ssh`, `microsoft-ds`) |
| `banner` | TextField — service banner if captured |
| `product` | CharField — vendor product string from `-sV` (e.g. `Apache httpd`) |
| `version` | CharField — version string from `-sV` (e.g. `2.4.41`) |
| `extra_info` | CharField — extra info from `-sV` (e.g. `(Ubuntu)`) |
| `cpe` | JSONField (list) — CPE strings from `-sV` (e.g. `["cpe:/a:apache:httpd:2.4.41"]`) |
| `state_reason` | CharField(64, db_indexed) — *why* nmap chose this state: `syn-ack` (open), `no-response` (filtered, packet vanished), `port-unreach` (closed via ICMP), `tcp-rst` (closed via RST). Filter on this to slice firewall-blocked from true-closed without parsing logs. |
| `state_reason_ttl` | PositiveSmallIntegerField (nullable) — TTL of the responding packet. Mismatched TTLs across ports on the same host hint at firewall interposition. |
| `state_reason_ip` | VarbinaryIPField (nullable) — IP that actually sent the response. Differs from the target IP when an intermediate firewall rewrites/responds on behalf of the host. |
| `tunnel` | CharField(16) — `ssl` for TLS-wrapped services (HTTPS on 443, SMTPS on 465, IMAPS on 993), empty for plain. Drives "is this port speaking TLS?" filters without parsing the service_name string — useful because nmap sometimes mis-labels the service while still correctly tagging the tunnel. |
| `service_fp` | TextField — raw nmap service fingerprint string. Useful when `service_name` is generic (`unknown`) and you want to submit the fingerprint upstream to nmap's signature database. |
| `service_method` | CharField(16) — how nmap identified the service: `table` (looked up the port number in `nmap-services` — fast but often wrong for non-standard ports), `probed` (actually fingerprinted via `-sV`). Calibrates how much to trust `service_name`. |
| `service_conf` | PositiveSmallIntegerField (nullable) — nmap's 1-10 confidence score for the service identification. Low values indicate the match was port-table-only or a partial fingerprint. Filterable to triage "definitely this service" (8-10) vs "guessing" (1-3). |

**Base class:** `BaseModel` (lightweight — no status/tags/change-log).

## Unique constraint

`(discovered_host, port, protocol)` — one row per port per protocol per
host per scan.

## Important relationships

| Direction | Field | Target |
|-----------|-------|--------|
| FK out | `discovered_host` | `DiscoveredHost` |
| Reverse FK | `vulnerabilities` | `NseFinding` (per-port scope — for host-scope NSE findings see [DiscoveredHost.host_findings](discoveredhost.md)) |

## Forensic fields — why they matter

The `state_reason` / `state_reason_ttl` / `state_reason_ip` / `tunnel`
fields capture data nmap reports natively but most scanner UIs throw
away. Operationally:

- **`state_reason='no-response'` vs `state_reason='tcp-rst'`** —
  same UI state (`filtered`), wildly different operational meaning.
  No-response = packet dropped by a firewall; tcp-rst = host
  actively rejecting. Filterable column means you can answer
  "which ports does our DMZ firewall silently drop?" without
  parsing logs.
- **`state_reason_ip != ip_address`** — an intermediate firewall is
  responding on behalf of the target. Common in DMZ / SCADA segments
  where the security appliance terminates probes before they reach
  the actual device. The `state_reason_ttl` then gives you the
  firewall's hop count, not the target's.
- **`tunnel='ssl'` on a port nmap thinks is "blackice-icecap"** —
  the service guess is wrong but the TLS detection is right. Use
  the `tunnel` filter to find "everything speaking TLS on
  non-standard ports" without trusting the `service_name` guess.

::: nautobot_scanner.models.DiscoveredPort
    options:
      show_root_heading: false
