# SQLite snapshots

SQLite snapshots share a SQLite database with your machines, your agents and other developers. Save a snapshot
from one machine and restore it on many. `prego sqlite save` makes the snapshot with SQLite and checks it with
`PRAGMA quick_check` before it sends anything.

**We are not your backup. We are for sharing.** Keep your own backups of data that you must not lose.

**Plans:** Trial, Org and Publisher can save. Indie does not include SQLite snapshots. Consumer restores through
grants.

## Start

- [SQLite snapshots guide](quickstart.md): references, save, restore, rotation, the exit codes, and the errors.
- [Share a SQLite database](../../README.md#share-a-sqlite-database) in the root README.
- Full docs: <https://docs.prego.k8skill.com/sqlite-snapshots> (sign in with your Prego account).

## Examples

The root README has [a GitLab CI save job and a fleet restore](../../README.md#share-a-sqlite-database).
