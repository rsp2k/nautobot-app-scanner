# Uninstall

Stop services, drop tables, remove the package.

## 1. Stop services

```bash
systemctl stop nautobot nautobot-worker
```

## 2. Decide what to do with the data

The app's tables hold scan results that may be useful even after
uninstall (historical scan data, vulnerability history). Options:

| Approach | Steps |
|----------|-------|
| **Keep the data** (e.g. for compliance) | Just remove the package; leave the tables in place. The data is queryable via raw SQL but the Django ORM and UI won't expose it. |
| **Export then drop** | `nautobot-server dumpdata nautobot_scanner > scanner-backup.json` then proceed to drop |
| **Drop everything** | Skip ahead to the migration rollback below |

## 3. Drop the app's tables (optional)

```bash
nautobot-server migrate nautobot_scanner zero
```

This reverses every migration the app has applied — drops all
nautobot_scanner_* tables and removes any FKs pointing into them. The
`raw_xml` files on disk under `media/scanner/xml/` are NOT removed by
this — clean them up manually if you want:

```bash
rm -rf <NAUTOBOT_MEDIA_ROOT>/scanner/
```

## 4. Remove the package

Edit `nautobot_config.py` to remove `"nautobot_scanner"` from `PLUGINS`,
then:

```bash
pip uninstall nautobot-app-scanner
```

## 5. Restart

```bash
systemctl start nautobot nautobot-worker
```

The **Scanner** nav menu disappears; jobs are unregistered.

## Remote agents

If you had remote agents running, stop them too — they'll start failing
their checkin POSTs the moment the app is gone. The per-agent
`auth.User` records are NOT automatically deleted; remove them manually
from **Admin > Users** if you don't want them lingering.
