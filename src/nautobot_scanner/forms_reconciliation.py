"""Filter form for the IPAM reconciliation report.

Lives in its own module so the reconciliation slice (view + template +
tests) can land as an isolated, self-contained pull request. The main
``forms.py`` module stays untouched until the maintainer's integration
commit re-exports these names or moves the class inline.

The shape mirrors the proposal at
``docs/agent-threads/ipam-reconciliation-report/
20260705T182313Z-scanner-maintainer-recon-proposal.md`` section
"Filter form" — six knobs the operator sees on the standalone
reconciliation surface, all optional, safe defaults geared toward
"what's undocumented on my private network right now?".
"""

from __future__ import annotations

from django import forms
from nautobot.apps.forms import (
    DynamicModelMultipleChoiceField,
    NautobotFilterForm,
)
from nautobot.ipam.models import Namespace, VRF


# Choice tuple lives at module level so the view (and any future JSON
# schema surface) can share it without repeating the string values.
SCOPE_CHOICES: tuple[tuple[str, str], ...] = (
    ("rfc1918", "RFC1918 only"),
    ("all", "All ranges"),
)


class ReconciliationFilterForm(NautobotFilterForm):
    """Sidebar-style filter form for the reconciliation report.

    Not backed by a Model — it drives a pure-function query engine
    (``nautobot_scanner.reconciliation.build_reconciliation``) rather
    than a queryset filter, so ``NautobotFilterForm`` is used only for
    its rendering polish (search-input styling, dynamic-model widgets,
    the tag-input UX). ``model`` is intentionally omitted; the parent
    handles that gracefully for detached filter forms.

    All fields are ``required=False`` — an empty submit is the default
    "current beliefs, RFC1918, no reserved noise" report.
    """

    # RFC1918-only is the safe default per the proposal (see section
    # "Feasibility summary — what's genuinely new", item 1). Excluding
    # public + IANA-reserved ranges before rendering kills the phantom-
    # ARP swamp before it hits the UI.
    scope = forms.ChoiceField(
        choices=SCOPE_CHOICES,
        initial="rfc1918",
        required=False,
        help_text=(
            "RFC1918 only keeps 10/8, 172.16/12, 192.168/16 — the noise-"
            "controlled default. Switch to All to include public prefixes."
        ),
    )

    # DynamicModel* widgets give the operator the same searchable
    # dropdown Nautobot uses everywhere else. Multi-select so an operator
    # can hand-pick "just the clinical VLANs" or "everything except guest".
    namespaces = DynamicModelMultipleChoiceField(
        queryset=Namespace.objects.all(),
        required=False,
        help_text="Restrict both the discovered-host and IPAM sides to these namespaces.",
    )
    vrfs = DynamicModelMultipleChoiceField(
        queryset=VRF.objects.all(),
        required=False,
        help_text="Restrict IPAM lookups to these VRFs.",
    )

    # Anti-noise defaults. ``exclude_reserved`` drops IANA special-use
    # ranges (6to4, TEST-NET, benchmarking, multicast) — the specific
    # phantom-full-block case bingham-ops flagged.
    exclude_reserved = forms.BooleanField(
        initial=True,
        required=False,
        help_text=(
            "Drop IANA special-use ranges (6to4 relay, TEST-NET, "
            "benchmarking, multicast). On by default; turn off for "
            "forensic dives."
        ),
    )

    # Off by default because the "stale IPAM" question is the less-
    # common one and computing it doubles the query cost.
    include_stale_ipam = forms.BooleanField(
        initial=False,
        required=False,
        help_text=(
            "Also show the inverse direction: IPAM records that no live "
            "host has matched at the current anchor."
        ),
    )

    # Bitemporal recording-time anchor. Empty means "current beliefs";
    # an ISO-8601 timestamp reproduces the report as it appeared then.
    # Matches the ``diff_scans`` convention so the two bitemporal
    # surfaces feel identical to the operator.
    as_of = forms.DateTimeField(
        required=False,
        help_text=(
            "ISO-8601 recording-time anchor (e.g. 2026-07-01T12:00:00Z). "
            "Empty renders current beliefs; a past timestamp reproduces "
            "the report as it appeared then."
        ),
    )
