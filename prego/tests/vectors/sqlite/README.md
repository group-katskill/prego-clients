# SQLite snapshots test vectors (ADR-0059)

Data only. Prego-clients copies these files as they are; the registry tests read them in `test/sqlite-format.test.ts`
and `test/sqlite.test.ts`. `scripts/sqlite/make-vectors.py` writes them (Python standard library, SQLite 3.45.1).
The committed files are the reference: do not make them again unless you add a case, and then commit every file.

`cases.json`:

- `files[]`: one entry per file.
  - `expect: "accept"`: the server stores the file. The entry gives `file_sha256` (64 hex), `frame_hashes`
    (`sha256:<hex>` of each uncompressed 64 MiB frame; one frame here), `snapshot_hash`, `page_size`, `page_count`,
    `text_encoding`, `user_version`, `application_id`, `tables`, `indexes` and `names_complete` (false when page 1
    does not hold every name).
  - `expect: "refuse"`: the server gives `400 sqlite_invalid` with `error.reason` equal to `reason`.
- `hash_rule_cases[]`: the snapshot hash rule alone, for 1, 2 and 3 frame hashes.

The snapshot hash (wire decisions item 1): one UTF-8 line per frame, `sha256:<64 lowercase hex>\n`, in frame order;
the snapshot hash is `sha256:` and the hex `sha256` of all the lines together.

`empty.db` is a new empty database: its header has text encoding 0 and schema format 0 (SQLite writes them with the
first table). It is accepted (wire decisions item 13) and records `text_encoding` 0.
