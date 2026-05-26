"""Template extensions — inject scanner panels into existing Nautobot pages.

Three extensions hang off three core models. Each renders a panel on the
right side of the detail page so the scanner data is visible *where you
already are*, without forcing a user to dig into the Scanner section.

Match logic on Device and IPAddress is intentionally **wider than just
`linked_*` foreign keys**: a Device added after a scan ran won't have any
DiscoveredHost.linked_device pointing at it (the auto-link only fires at
ingest time). So we also match by IP-address equality. This means a scan
from yesterday will show up on a Device created today, as long as the
IPs line up — exactly what an operator expects.

The Prefix coverage stats are cached because computing them for a /16
means counting `2^16` possible host IPs against the actual DiscoveredHost
table. TTL is tunable via PLUGINS_CONFIG['nautobot_scanner']
['prefix_coverage_cache_ttl_seconds'] (default 300).
"""

from __future__ import annotations

from django.conf import settings
from django.core.cache import cache
from django.db.models import Q
from nautobot.apps.ui import TemplateExtension

from nautobot_scanner import models


def _device_ip_targets(device) -> list[str]:
    """Pull both v4 and v6 primary IPs off a Device as plain strings.

    Returns empty list if neither is set. Handles the Nautobot
    IPAddress -> .host path that returns the bare IP without mask.
    """
    ips: list[str] = []
    if device.primary_ip4_id:
        ips.append(str(device.primary_ip4.host))
    if device.primary_ip6_id:
        ips.append(str(device.primary_ip6.host))
    return ips


class DeviceScans(TemplateExtension):  # pylint: disable=abstract-method
    """Adds a 'Scanner activity' panel to dcim.Device detail pages."""

    model = "dcim.device"

    def right_page(self):
        """Render the panel on the right side of the Device detail page."""
        device = self.context["object"]
        ips = _device_ip_targets(device)

        # Match either by the explicit FK or by IP equality — covers the
        # "Device added after scan ran" case where linked_device is None.
        if ips:
            qs = models.DiscoveredHost.objects.filter(
                Q(linked_device=device) | Q(ip_address__in=ips),
            )
        else:
            qs = models.DiscoveredHost.objects.filter(linked_device=device)

        hosts = list(qs.select_related("scan", "scan__profile").order_by("-scan__started_at")[:10])

        return self.render(
            "nautobot_scanner/inc/device_scans.html",
            extra_context={
                "discovered_hosts": hosts,
                "device_ips": ips,
            },
        )


class IPAddressScans(TemplateExtension):  # pylint: disable=abstract-method
    """Adds a 'Scanner activity' panel to ipam.IPAddress detail pages."""

    model = "ipam.ipaddress"

    def right_page(self):
        """Render scan history for this specific IP."""
        ipaddress = self.context["object"]
        # Match by explicit FK OR by IP equality. The host portion strips
        # the prefix mask off the IPAddress.address value.
        host_str = str(ipaddress.host)
        qs = models.DiscoveredHost.objects.filter(
            Q(linked_ipaddress=ipaddress) | Q(ip_address=host_str),
        )
        hosts = list(qs.select_related("scan", "scan__profile").order_by("-scan__started_at")[:10])

        # Count distinct open ports across all scans of this IP — a quick
        # security summary at the top of the panel.
        port_count = models.DiscoveredPort.objects.filter(
            discovered_host__in=qs,
            state="open",
        ).count()
        # Counts both port-scope findings (vulners on a port) and host-scope
        # findings (smb-os-discovery on the host). The "vuln" naming is kept
        # for template compat; semantically it's "NSE findings of any kind".
        vuln_count = (
            models.NseFinding.objects.filter(discovered_port__discovered_host__in=qs).count()
            + models.NseFinding.objects.filter(discovered_host__in=qs).count()
        )

        return self.render(
            "nautobot_scanner/inc/ipaddress_scans.html",
            extra_context={
                "discovered_hosts": hosts,
                "open_port_count": port_count,
                "vuln_count": vuln_count,
            },
        )


class PrefixScans(TemplateExtension):  # pylint: disable=abstract-method
    """Adds a 'Scan coverage' panel to ipam.Prefix detail pages.

    Coverage = (distinct IPs in this prefix that show up as DiscoveredHost
    records) / (total host capacity of the prefix). Computation can be
    expensive for /8s and /16s so the result is cached per-prefix.
    """

    model = "ipam.prefix"

    def right_page(self):
        """Render scan-coverage stats for this prefix."""
        prefix = self.context["object"]
        ttl = settings.PLUGINS_CONFIG.get("nautobot_scanner", {}).get(
            "prefix_coverage_cache_ttl_seconds", 300,
        )
        cache_key = f"scanner:prefix_coverage:{prefix.pk}"

        data = cache.get(cache_key)
        if data is None:
            data = self._compute_coverage(prefix)
            cache.set(cache_key, data, ttl)

        return self.render(
            "nautobot_scanner/inc/prefix_scans.html",
            extra_context=data,
        )

    @staticmethod
    def _compute_coverage(prefix) -> dict:
        """Compute scan-coverage stats for a Prefix.

        Returns a dict suitable for unpacking into the template's
        ``extra_context``: ``recent_scans``, ``coverage_pct``,
        ``ips_scanned``, ``ips_in_prefix``, ``hosts_up``.
        """
        # Recent scans that targeted this prefix directly. We can't easily
        # match "scans whose target_prefixes contained any IP of this
        # prefix" without subnet arithmetic, so we focus on direct
        # target_prefixes membership.
        recent_scans = list(
            models.Scan.objects.filter(target_prefixes=prefix)
            .select_related("agent", "profile")
            .order_by("-started_at")[:5],
        )

        # `prefix.prefix` is a netaddr.IPNetwork — its size attr gives total
        # IPs (including network + broadcast for IPv4). NOT `.num_addresses`,
        # that's the stdlib ipaddress.IPv4Network attribute; netaddr uses .size.
        net = prefix.prefix
        total = int(net.size)

        # For prefixes >1M IPs (/12 and wider for IPv4, /108 and wider for
        # IPv6), don't materialize the IP set — fall back to "count distinct
        # DiscoveredHosts that came from a scan targeting this prefix". This
        # misses hosts discovered by overlapping scans of different prefixes
        # but is the only sane choice memory-wise.
        if total > 1_000_000:
            scoped = models.DiscoveredHost.objects.filter(scan__target_prefixes=prefix)
            ips_scanned = scoped.values("ip_address").distinct().count()
            hosts_up = scoped.filter(host_state="up").count()
        else:
            # Build the stringified IP set once and reuse for both counts.
            prefix_str_ips = {str(ip) for ip in net}
            scoped = models.DiscoveredHost.objects.filter(ip_address__in=prefix_str_ips)
            ips_scanned = scoped.values("ip_address").distinct().count()
            hosts_up = scoped.filter(host_state="up").count()

        coverage_pct = (ips_scanned / total * 100) if total else 0

        return {
            "recent_scans": recent_scans,
            "coverage_pct": round(coverage_pct, 1),
            "ips_scanned": ips_scanned,
            "ips_in_prefix": total,
            "hosts_up": hosts_up,
        }


template_extensions = [DeviceScans, IPAddressScans, PrefixScans]
