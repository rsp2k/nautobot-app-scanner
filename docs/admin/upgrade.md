# Upgrade

Standard Nautobot app upgrade flow.

## Stop services

```bash
systemctl stop nautobot nautobot-worker
```

## Upgrade the package

```bash
pip install --upgrade nautobot-app-scanner
```

## Run migrations

```bash
nautobot-server migrate
nautobot-server collectstatic --noinput
```

## Restart

```bash
systemctl start nautobot nautobot-worker
```

## Check the version in the UI

**Apps > Installed Apps > Scanner** — verify the version matches what
you just installed.

## Rolling back

The app uses CalVer (`YYYY.MM.DD`) — pin an earlier version to roll
back:

```bash
pip install nautobot-app-scanner==2026.5.24
```

Then re-run migrations — but **`migrate` only goes forward**. To
actually undo a schema change you'd need `migrate nautobot_scanner
<previous_migration_name>` and then re-`migrate` after downgrading.
This is generally messy; we try to keep migrations additive (new
columns are nullable / have defaults).

## Breaking-change announcements

Breaking changes (model removal, FK renames, etc.) are announced in:

- The release notes (TODO once we cut a versioned release)
- The git commit log under the `BREAKING:` prefix
- A warning admonition at the top of [Compatibility Matrix](compatibility_matrix.md)

For pre-alpha versions (`2026.x.x`) the policy is "every release may
break" — pin a specific version in production.
