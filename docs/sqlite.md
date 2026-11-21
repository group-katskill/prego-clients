# SQLite snapshots with `prego sqlite`

From prego 1.2.0. SQLite snapshots need `prego` 1.2.0 or later and Prego registry 1.26.0 or later.

Use SQLite snapshots to share a SQLite database with your machines, your agents and other developers. Save a
snapshot from one machine. Restore it on many machines. Many machines can also save their databases to one
place. Your machines and agents save and restore snapshots with the identity that they have now. They do not
keep a key.

> **We are not your backup. We are for sharing.** Prego does not give point-in-time recovery and does not
> promise a recovery time. Keep your own backups of data that you must not lose.

This guide uses tenant `acme`, namespace `fleet` and database `lookup`. Replace them with your own.

## What you get

- Each save makes a snapshot. You cannot change a snapshot after you save it.
- Each snapshot has a number and a hash. The same database always gives the same hash.
- Prego checks that each snapshot is a SQLite database file. Prego refuses other files and encrypted files.
- Each snapshot shows the machine or agent that saved it, the size, the page count, the `user_version` of the
  database and the result of the check that `prego` ran before the save.
- A tag keeps a snapshot until you remove it.
- Prego removes old snapshots without a tag. You set how many snapshots and how many days Prego keeps. Prego
  always keeps the newest snapshot.
- You give other machines, agents and tenants access with a grant, and you can remove the grant at any time.

## Before you start

- Your plan must have SQLite snapshots: Trial, Org and Publisher save. Consumer restores through grants.
- You need a grant with the type "SQLite snapshots" (or "any"). Use `read` to restore, `publish` to save, tag
  and change settings, and `delete` to remove snapshots. No grant gives `404`: Prego does not tell whether the
  database exists.
- `prego` uses the same identity sources as the other tools: GitLab or GitHub OIDC, SPIFFE, an API key, or
  `prego login` (use `prego login --publish` to save from a laptop).

## References

A reference is `<tenant>/<database>` (namespace `default`) or `<tenant>/<namespace>/<database>`. A database name
follows the snippet name rule: 1 to 128 characters from `a-z`, `0-9`, `.`, `_` and `-`, starting with a
letter or a digit.

Add `@<snapshot>` to select a snapshot: `latest` (the default), a number (`@42`), a tag (`@2026-11-20`) or a
hash (`@sha256:<hex>`).

## Save a snapshot

```sh
prego sqlite save ./app.db acme/fleet/lookup --message "Daily build"
```

- `prego` makes the snapshot with SQLite. It does not copy the database file: it saves SQLite's own copy. Your
  application can continue to use the database while the command runs. A file that SQLite can read but that is
  damaged at the end (cut short, or with extra bytes) is saved in the form that SQLite reads, which is a valid
  database. A file of 0 bytes is not saved.
- `prego` opens the database read-only. A WAL-mode database that no program has open (no `-wal` and no `-shm`
  file) is opened with write access instead, so that SQLite removes the `-wal` and `-shm` files that it makes.
  When the command closes the database, SQLite checkpoints the WAL into the database file, as any SQLite client
  does. The data does not change. If `prego` cannot open the database with write access, it opens it
  read-only.
- Then `prego` runs `PRAGMA quick_check` on the snapshot. If the check fails, nothing is sent and the exit code
  is 5. `--check full` runs `PRAGMA integrity_check` (slower, more complete). `--check none` does no check.
  Prego shows the result with the snapshot.
- `--compact` makes a smaller snapshot without free pages (with `VACUUM INTO`). The hash is not the same as the
  hash of a save without `--compact`.
- `--label key=value` (at most 16, as in Context), `--message <text>` (at most 200 characters) and
  `--tag <tag>` add metadata. Label keys that start with `prego.` are kept for Prego.
- If the snapshot has the same hash as the latest snapshot, `prego` sends nothing: it prints
  `no change, snapshot <n> is the latest` and exits with 0. So you can run the same save again at any time, also
  within the one-save-per-minute limit. With `--tag`, the latest snapshot gets the tag.
- A save of different data within one minute of the last save is refused (`429 rate_limited`, exit code 4); the
  error shows how many seconds to wait.
- When a save takes the database over its `keep_count`, Prego removes the oldest snapshot without a tag, and
  `prego` prints its number.
- If Prego refuses the save, `prego` shows the error and the exit code is 4.

The command needs free disk space for one copy of the database, in the temporary folder (`TMPDIR`). It removes
the copy at the end.

**Do not copy a database file while an application uses it.** The copy can be damaged. Always use
`prego sqlite save`.

`prego sqlite hash ./app.db` prints the snapshot hash that a save would give, offline. Add `--compact` for the
hash of `save --compact`.

## Restore a snapshot

```sh
prego sqlite restore acme/fleet/lookup ./data/lookup.db
prego sqlite restore acme/fleet/lookup@42 ./data/lookup.db
prego sqlite restore acme/fleet/lookup@2026-11-20 ./data/lookup.db --expect sha256:<hash>
```

1. `prego` writes the snapshot to a new file next to the target, `./data/lookup.db.prego-tmp`.
2. It checks the snapshot hash and the `sha256` of the file, and runs `PRAGMA quick_check`.
3. Then it renames the file to the target. If a check fails, the target does not change and the new file is
   removed. A failed `quick_check` gives exit code 5.

Stop the application before you replace its database. `prego` does not replace a database that has a `-wal` or
`-journal` file next to it. `--force` replaces it, and removes the `-wal`, `-shm` and `-journal` files of the old
database so that SQLite does not apply them to the new file.

## Use the hash to stop changes

Give the hash that you expect. If the snapshot has a different hash, `prego` stops with exit code 3. Nothing is
written.

```sh
prego sqlite restore acme/fleet/lookup@2026-11-20 ./data/lookup.db --expect sha256:<hash>
```

Pin the hash on machines that must all use the same data.

## See snapshots

```sh
prego sqlite ls acme/fleet          # the databases that you can read
prego sqlite log acme/fleet/lookup  # the snapshots, newest first (* is the latest)
```

## Keep or remove snapshots

Snapshots count in your storage. By default, Prego keeps the newest 20 snapshots of each database for 30 days.
Prego always keeps the newest snapshot, and it keeps a snapshot with a tag until you remove it.

```sh
prego sqlite tag acme/fleet/lookup@42 2026-11-20                  # a tag is written one time only
prego sqlite set acme/fleet/lookup --keep-count 10 --keep-days 14
prego sqlite prune acme/fleet/lookup --keep 5                     # keep the newest 5
prego sqlite prune acme/fleet/lookup --older-than 7d              # <n>h, <n>d or <n>w
prego sqlite rm acme/fleet/lookup@42                              # one snapshot
prego sqlite rm acme/fleet/lookup                                 # the database and all its snapshots
```

- `prune` never removes a tagged snapshot or the newest snapshot. With `--keep` and `--older-than`, it removes
  only snapshots that match both. It lists the snapshots and asks before it removes them. In a script, add
  `--yes`.
- `rm` of a whole database asks first, unless `--yes`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Done. |
| 1 | An error: the message tells why. |
| 2 | The snapshot uses an encryption mode that this version of `prego` cannot read. Update `prego`. Nothing is written. |
| 3 | The hash is not the hash that you gave with `--expect`. Nothing is written. |
| 4 | Prego refused the save, or the save could not be sent. The command shows the error. |
| 5 | `PRAGMA quick_check` or `PRAGMA integrity_check` failed. Nothing is sent, or the target does not change. |

## Errors

| Error | What to do |
| --- | --- |
| `not found, or you have no grant for it` | Check the reference, and that a grant for "SQLite snapshots" matches the database. |
| `... is not a database, or it is encrypted` | The file is not a SQLite database, or it is encrypted. Prego does not accept encrypted databases. |
| `the file is empty (0 bytes)` | There is no database to save. |
| `400 sqlite_invalid (reason: ...)` | Prego checked the file and refused it. |
| `403 plan_limit` | Your plan does not have SQLite snapshots, or a limit is full (storage, databases or snapshots). |
| `413 database_too_large` | The database is larger than your plan allows. |
| `429 rate_limited` | At most one save per minute for each database. Wait for the time in `retry after`. |
| `... is in use or was not closed cleanly` | Stop the application that uses the database, or use `--force`. |

## Personal data

- You are responsible for the data in your databases.
- Do not share a snapshot that holds personal data with a tenant that must not see it.
- You cannot change a snapshot. To remove data from Prego, remove the snapshots that hold it.

[PROTOCOL.md](../PROTOCOL.md) section 16 has the routes, the frames, the hash and the full client contract.

Full docs, with examples: <https://docs.prego.k8skill.com/sqlite-snapshots> (sign in with your Prego account; open from the console's Docs link).
