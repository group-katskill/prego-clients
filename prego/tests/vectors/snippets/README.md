# Snippets hash vectors (ADR-0057 item 6)

Shared test data for the snippet version hash. Data only: the registry tests and the `prego snippet hash` tests in
prego-clients read the same folders and the same `cases.json`. Copy the data, never code.

## Rule

1. Make one entry per file: `{"path", "mode", "size", "sha256"}`.
   - `path`: relative, `/` separated, at most 255 bytes, no empty, `.` or `..` segment, no leading `/`.
   - `mode`: the string `"0644"` or `"0755"`. Use the owner execute bit of the file mode: `0700` gives `"0755"`,
     `0600` gives `"0644"`.
   - `size`: the file size in bytes, a JSON integer.
   - `sha256`: the SHA-256 of the file bytes, 64 lowercase hex characters, with no `sha256:` prefix.
2. Sort the entries by the UTF-8 bytes of `path`.
3. Write `{"files":[...]}` in RFC 8785 canonical JSON (keys in order `mode`, `path`, `sha256`, `size`), as UTF-8.
4. The version hash is `sha256:` and the 64 lowercase hex characters of the SHA-256 of those bytes.

## Files

- `files/<case>/`: the files of each case.
- `cases.json`:
  - `cases[]`: `name`, `dir`, `files` (path and mode of each file), `canonical` (the canonical JSON text) and `hash`.
    Take the modes from `cases.json`, not from the file system: git keeps only some mode bits.
  - `invalid_paths[]`: paths that a push refuses (`400 snippet_invalid`).
  - `tar_modes[]`: the mode that a tar mode gives.

A change of this data is a change of the hash contract. It needs an ADR change first.
