# Sanitizing Screenshots Before Capture

The scanner UI shows discovered hostnames, IPs, MAC addresses, and OUI
vendor strings — all of which can be **PII** when captured against a
real production network and committed to a public repo.

JPEGs are pixel data. There is no `grep -r` for an image after the
fact. Once a screenshot lands in a commit with `nas2.acmecorp.com`
visible, that customer name is permanent — it ships to PyPI in the
sdist, gets archived by `archive.org`, indexes into Google's image
search, and persists across history rewrites unless every blob is
purged.

**Rule:** sanitize the DOM in the browser **before** clicking capture.
Refresh the page to restore real data. The captured image carries only
documentation-safe placeholders.

## The sanitizer

Paste this into the browser DevTools console (F12 → Console) on any
scanner page before taking a screenshot. It walks every text node,
applies a documentation-safe regex pass, and updates the `<title>`
(which appears in the browser tab if your screenshot tool includes
window chrome).

```javascript
(() => {
  const replacements = [
    // RFC 1918 ranges → RFC 5737 documentation ranges (last octet preserved
    // for visual differentiation between rows).
    { re: /\b192\.168\.\d+\.(\d+)\b/g, to: '198.51.100.$1' },
    { re: /\b172\.(1[6-9]|2[0-9]|3[01])\.\d+\.(\d+)\b/g, to: '203.0.113.$2' },
    { re: /\b10\.\d+\.\d+\.(\d+)\b/g, to: '192.0.2.$1' },

    // MAC OUI → IANA documentation OUI 00:00:5E; keep last 3 octets so
    // rows remain visually distinct.
    {
      re: /\b[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})\b/g,
      to: '00:00:5E:$1',
    },

    // Domain suffixes → IANA-reserved example.* TLDs.
    { re: /\.\w+\.(com|net|org)\b/g, to: '.example.$1' },

    // Add project-specific hostname rewrites here. Example:
    // { re: /\bcustomername\b/g, to: 'tenant-01' },
  ];

  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode: (n) => {
      const tag = n.parentNode?.tagName;
      return tag === 'SCRIPT' || tag === 'STYLE'
        ? NodeFilter.FILTER_REJECT
        : NodeFilter.FILTER_ACCEPT;
    },
  });

  let touched = 0;
  for (let n; (n = walker.nextNode()); ) {
    const before = n.nodeValue;
    let after = before;
    for (const { re, to } of replacements) after = after.replace(re, to);
    if (after !== before) {
      n.nodeValue = after;
      touched++;
    }
  }

  let title = document.title;
  for (const { re, to } of replacements) title = title.replace(re, to);
  document.title = title;

  return { touched, title };
})();
```

The function returns `{ touched: <int>, title: <string> }` so you can
glance at the console and confirm the sanitizer found things to replace.

## Replacement conventions

The patterns above are deliberately aligned with established
documentation-safe ranges so screenshots can be quoted without raising
"is that real?" questions:

| Class | Real PII | Documentation placeholder | Source |
|---|---|---|---|
| IPv4 (private) | `10/8`, `172.16/12`, `192.168/16` | `192.0.2/24`, `203.0.113/24`, `198.51.100/24` | RFC 5737 |
| MAC OUI | Real OUI prefix | `00:00:5E` | RFC 7042 |
| Domain | `acmecorp.com` | `example.com`, `.example.net`, `.example.org` | RFC 2606 |
| Hostnames | `acme-printer-01` | `tenant-01`, `printer-01` | project-defined |

For project-specific names (customer slugs, internal app codenames),
add entries to the `replacements` array in your local copy of the
snippet — keep it project-specific rather than baking site identity
into a shared utility.

## Workflow

1. Open the scanner page you want to capture.
2. F12 → Console.
3. Paste the snippet, press Enter.
4. Verify the page now shows placeholders (IPs, hostnames, MACs all
   rewritten).
5. Take the screenshot.
6. Refresh the page (`Cmd/Ctrl + R`) to restore real data.

## Why DOM-rewrite over fixture data

A fixture-DB approach (seed a separate "demo" database with fake
hostnames) drifts: every new model field needs a fixture entry, every
new panel needs demo data, and you lose the visual fidelity of "this
panel actually rendered against a real scan run." The DOM-rewrite
approach captures the production layout with sanitized text — the
screenshot looks indistinguishable from "what an operator actually
sees" except the strings are docs-safe.

## What to do with screenshots you forgot to sanitize

If real-PII screenshots are already committed:

1. **Pre-push**: delete the files, recreate with the sanitizer, commit
   the replacement (no force-push needed since nothing's published).
2. **Post-push to private repo**: low urgency. Replace at your
   convenience; nobody outside your collaborators sees them.
3. **Post-push to public repo**: rewrite history with `git filter-repo
   --invert-paths --path artifacts/screenshots/<file>.png`, then
   force-push. Note that GitHub still caches the old blob via the SHA
   for ~90 days unless you contact support.

For belt-and-suspenders, `artifacts/` is gitignored at the repo root
by default. Screenshots only enter the docs build via `docs/images/`
(intentionally tracked) — those are the ones that need to be
sanitized before adding.
