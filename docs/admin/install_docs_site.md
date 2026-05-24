# Publishing the Docs Site

The repo is configured to publish to [Read the Docs](https://readthedocs.org)
via the `.readthedocs.yaml` config at the repo root. This page covers
the one-time RTD-side wiring once the repo is on GitHub / Gitea.

## Build configuration (already in the repo)

| File | Role |
|------|------|
| `.readthedocs.yaml` | RTD v2 build spec (Python 3.12, ubuntu-24.04, mkdocs.yml + fail_on_warning) |
| `docs/requirements.txt` | Docs-only deps (mkdocs-material, mkdocstrings[python], etc.). Doesn't pull in nautobot — griffe AST-parses our source without needing to import it |
| `mkdocs.yml` | Material theme config + nav + plugins (mkdocstrings, validation block) |

## Building locally

```bash
pip install -r docs/requirements.txt
mkdocs serve
```

Then visit `http://127.0.0.1:8001/` (the `dev_addr` configured in
`mkdocs.yml`). Live-reload on save.

To produce a static build for CI / preview:

```bash
mkdocs build --strict
```

The output goes to `src/nautobot_scanner/static/nautobot_scanner/docs/`
(per `site_dir` in `mkdocs.yml`) — that way Nautobot's static-file
machinery serves the built docs in-app if you want.

## One-time RTD setup

1. **Create RTD account** at <https://readthedocs.org/accounts/signup/>
2. **Import project**:
   - Dashboard > **Import a Project**
   - Pick your fork / mirror of `nautobot-app-scanner`
   - **Default branch**: `main`
   - **Documentation type**: `MkDocs` (auto-detected from `.readthedocs.yaml`)
3. **Verify the first build** under the **Builds** tab. Expected build
   time: ~10–15 seconds (no nautobot install needed).
4. **Webhook**: RTD auto-installs a GitHub webhook at import time —
   pushes to `main` will trigger rebuilds. Verify under **Admin >
   Integrations**.

## Custom domain (optional)

Default URL is `https://nautobot-app-scanner.readthedocs.io/`. To use
your own domain (e.g. `scanner.docs.example.com`):

1. **RTD: Admin > Domains > Add Domain**, enter the hostname
2. Create a CNAME in your DNS pointing to
   `<your-rtd-project>.readthedocs.io`
3. Wait for cert provisioning (~5 min)

## Editing tips

- Strict mode (`fail_on_warning: true`) catches broken cross-links and
  invalid frontmatter at build time — keep this on so the production
  build can't silently regress
- mkdocstrings will auto-generate code reference blocks if you add
  `::: nautobot_scanner.models.Scan` (or any other dotted path) to a
  markdown page — see the model pages under `docs/models/` for examples
- The `markdown_version_annotations` extension renders `+++ "X.Y" Note`
  blocks as nice green/orange/red admonitions for version-added /
  -changed / -removed notes
