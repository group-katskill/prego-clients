# Secret-shape vectors (ADR-0035 section 9, ADR-0058 item 12)

Shared test data for the secret check. Data only: the registry tests and the `prego context save` redaction tests in
prego-clients read the same `cases.json`. Copy the data, never code. There is no pattern source here: write the
patterns from the ADR text.

## Files

- `cases.json`:
  - `kinds[]`: the kind names, in ADR-0035 section 9 order. The client writes `[REDACTED:<kind>]` for a match.
  - `cases[]`: `name`, `input` (one line of text) and `kind` (the kind that the line matches, or `null` for no match).
    Each positive case matches one kind only. The negative cases are near misses: too short, inside a word, a
    lowercase form, a public key, a test key.

## Notes

- The first character of each secret prefix in `input` is written as a `\uXXXX` escape (for example `ghp_`), so
  that secret scanners do not flag this file. A JSON parser gives the real text.
- The values are not real credentials. They are made of `EXAMPLE0` and similar text.
- A line matches when any part of it has the shape. The server reports the path and the line number, never the value.
- A change of this data is a change of the secret check contract. It needs an ADR change first.
