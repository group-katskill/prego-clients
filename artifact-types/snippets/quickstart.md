# Snippets with `prego snippet`

**From prego 1.0.0.** Snippets need `prego` 1.0.0 or later and Prego registry 1.24.0 or later.

A snippet is a named set of text files: scripts, prompts, agent skills, templates and runbooks. Your machines and
agents read snippets with the identity that they already have. Like a gist, but private and versioned.

> **An agent follows the text in a snippet.** Pin the hash with `--expect`, and give `read` grants only on
> snippets that you trust. Do not put passwords, tokens or keys in a snippet: the registry refuses files that
> look like they contain a secret (`422 looks_like_secret`).

This guide uses tenant `acme`, namespace `ops` and snippet `deploy-scripts`. Replace them with your own.

## What you get

- Each push that changes the files makes a new version. A version does not change after you push it.
- Each version has a number and a hash. The same files always give the same hash, on every machine.
- A tag points to one version. You cannot move or rewrite a tag.
- You can compare two versions, and roll back to an older version.

## Before you start

- Your plan must have Snippets: Trial, Indie, Org and Publisher can push. Consumer reads through grants.
- You need a grant with the type "Snippets" (or "any"). Use `read` to get snippets, `publish` to push, tag and
  roll back. No grant gives `404`: the registry does not tell whether the snippet exists.
- `prego` uses the same identity sources as the other tools: GitLab or GitHub OIDC, SPIFFE, an API key, or
  `prego login` (use `prego login --publish` to push from a laptop). SPIFFE (`SPIFFE_ENDPOINT_SOCKET` or
  `PREGO_SVID_FILE`) needs the Org or Publisher plan (or a Trial).

## References

- `acme/deploy-scripts` is in namespace `default`.
- `acme/ops/deploy-scripts` is in namespace `ops`.
- A snippet name is 1 to 128 characters from `a-z`, `0-9`, `.`, `_` and `-`, starting with a letter or a digit.
- Add `@<version>` to read one version: a number (`@7`), a tag (`@2026-11-19`), a hash (`@sha256:<hex>`) or
  `@current` (the default).

## Push

```sh
prego snippet push ./deploy-scripts acme/ops/deploy-scripts --message "Add rollback step"
prego snippet push ./deploy-scripts acme/ops/deploy-scripts --tag 2026-11-19
prego snippet push ./prompt.md acme/ops/review-prompt              # one file: a snippet of one file
prego snippet push ./bundle.tar.gz acme/ops/deploy-scripts --tar   # a ready-made .tar.gz or .tar
```

- A folder gives all its regular files, also dotfiles. A folder named `.git` is skipped.
- `prego` checks the files before it sends anything, with the rules below, and sends one `.tar.gz`.
- If the files are the same as the current version, no new version is made: `no change, version N is current`.
- `--if-current sha256:<hash>` stops the push (`409 conflict`) when another person pushed first.
- `--message` is at most 200 characters.

## Get

```sh
prego snippet get acme/ops/deploy-scripts                        # into ./deploy-scripts
prego snippet get acme/ops/deploy-scripts@7 ./scripts            # version 7 into ./scripts
prego snippet get acme/ops/deploy-scripts --file rollback.sh     # one file on stdout
prego snippet get acme/ops/deploy-scripts@7 v7.tar.gz --tar      # the .tar.gz of version 7
```

- The folder must be new or empty. `prego` reads the file list, computes the version hash from it, downloads
  each file of that exact version (by its hash) and checks its size and SHA-256. It writes the files only when
  all of them pass.
- A file path that leaves the folder (`..`, `/` at the start) is refused, and nothing is written.
- Files get mode `0644`, or `0755` for a file that was executable. Owner and time are not kept.
- `--tar` writes the registry's tarball as it is. `prego` unpacks it in memory first and checks its hash.

## Pin the hash

```sh
prego snippet get acme/ops/deploy-scripts@2026-11-19 ./scripts --expect sha256:<hash>
```

If the version hash is different, `prego` exits with code **3** and writes nothing. Use this in CI and for
agents. The hash of a folder on your machine, offline:

```sh
prego snippet hash ./deploy-scripts
```

## History, tags, diff and rollback

```sh
prego snippet ls acme/ops                                      # the snippets you can read
prego snippet log acme/ops/deploy-scripts                      # versions, newest first, * = current
prego snippet tag acme/ops/deploy-scripts@7 stable             # written one time only, never *.tar.gz
prego snippet diff acme/ops/deploy-scripts 6 stable            # files added, removed, changed, and the lines
prego snippet rollback acme/ops/deploy-scripts --to 6 --reason "Step 4 fails on staging"
```

Rollback does not make a new version. It makes version 6 the current version again. Rolling forward is the
same command with a newer version.

## Rules for files

- At most 100 files per version, each at most 1 MiB, all together at most 8 MiB.
- Text only: UTF-8 with no NUL byte. Binary files are refused.
- Paths are relative and `/` separated, at most 255 bytes, with no empty, `.` or `..` segment and no `\`.
- Paths have no control characters (U+0001 to U+001F, U+007F to U+009F) and no bidi controls (U+202A to U+202E, U+2066 to
  U+2069). Names must be valid UTF-8.
- Two paths may not be the same after Unicode NFC and lowercase (`README.md` and `readme.md`), and a path may not
  also be a folder of another path (`a` and `a/b`, also `A` and `a/b`). Such a version would not unpack the same on every system.
- Symlinks, hard links and devices are refused.
- The mode is `0755` when the owner can run the file, else `0644`.

For the limits of your plan (snippets per tenant, storage, usage), see the console and the plan limits page.

## The version hash

The hash is the same in `prego`, in the console and in the registry:

1. One entry per file: `{"path", "mode", "size", "sha256"}`. `mode` is the text `"0644"` or `"0755"`, `size`
   is the number of bytes, `sha256` is the 64 lowercase hex characters of the file's SHA-256.
2. Sort the entries by the UTF-8 bytes of `path`.
3. Write `{"files":[...]}` in RFC 8785 canonical JSON.
4. The version hash is `sha256:` and the hex SHA-256 of those bytes.

The hash covers the file list, not the tarball bytes, so a tarball from another tool gives the same hash for
the same files. [PROTOCOL.md](../../PROTOCOL.md) section 14 has the routes and the full client contract.

## CI

```yaml
# GitLab CI: read a pinned snippet with the job's OIDC identity.
deploy:
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  script:
    - prego snippet get acme/ops/deploy-scripts@stable ./scripts --expect "$DEPLOY_SCRIPTS_HASH"
    - ./scripts/deploy.sh
```

## Errors

| Message | Meaning |
| --- | --- |
| `not found, or you have no grant for it` | No snippet, no version, or no `read` grant (`404`). |
| `403 ...` | You can read the snippet but you have no `publish` grant, or the plan does not allow it. |
| `403 plan_limit` | The plan's storage pool or snippet count is full. Reads, tags and rollback still work. |
| `409 conflict` | `--if-current` did not match, or the tag is there already. |
| `412` / exit code 3 | `--expect` did not match. Nothing was written. |
| `413 ...` | A file, the version or the upload is too large. |
| exit code 2: `this snippet uses encryption mode M, which this prego version cannot read` | The snippet uses an encryption mode (a later add-on) that this `prego` cannot read. Nothing was written. |
| `422 looks_like_secret (file: F, line N)` | A line looks like a credential. The value is never shown. |
| `400 snippet_invalid (file: F, reason)` | A path or a file breaks the rules above. |

Full docs, with examples: <https://docs.prego.k8skill.com/snippets> (sign in with your Prego account; open from the console's Docs link).
