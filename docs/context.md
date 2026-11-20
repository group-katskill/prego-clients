# Agent context with `prego context`

**From prego 1.1.0.** Context needs `prego` 1.1.0 or later and Prego registry 1.25.0 or later.

Context is agent context that you save in Prego. An agent saves its context before it compacts or stops:
memory files, notes, plans, task lists and conversation transcripts. Later, the same agent or another agent
restores the context and continues the work. Your agents save and restore context with the identity that they
already have. They do not keep a key.

> **An agent follows the text in the context that it restores.** Context from another agent is not reviewed by
> a person. Give `read` grants only to agents that you trust, and pin the hash with `--expect`.

This guide uses tenant `acme`, namespace `agents` and context `billing-agent`. Replace them with your own.

## What you get

- Each save makes a checkpoint. You cannot change a checkpoint after you save it.
- Each checkpoint has a number and a hash. The same files always give the same hash.
- Each checkpoint shows the agent that saved it, the session, and the reason for the save (the trigger).
- A tag keeps a checkpoint until you remove it.
- Prego removes old checkpoints without a tag after a number of days that you set.
- You give other agents access with a grant, and you can remove the grant at any time.

## Context or Snippets

- Use **Snippets** ([guide](snippets.md)) for text that a person writes and that machines use again and
  again: scripts, prompts, agent skills.
- Use **Context** for text that an agent saves so that the work is not lost.

Context is not a live memory store. You cannot add to a checkpoint, edit it or search in it. Each save is a new
checkpoint.

## Before you start

- Your plan must have Context: Trial, Indie, Org and Publisher save. Consumer restores through grants.
- You need a grant with the type "Context" (or "any"). Use `read` to restore, `publish` to save, tag and change
  settings, and `delete` to remove checkpoints. No grant gives `404`: the registry does not tell whether the
  context exists.
- `prego` uses the same identity sources as the other tools: GitLab or GitHub OIDC, SPIFFE, an API key, or
  `prego login` (use `prego login --publish` to save from a laptop).

## References

- `acme/billing-agent` is in namespace `default`; `acme/agents/billing-agent` is in namespace `agents`.
- A context name is 1 to 128 characters from `a-z`, `0-9`, `.`, `_` and `-`, starting with a letter or a digit.
- Add `@<checkpoint>` to select one checkpoint: `latest` (the default), a number (`@42`), a tag
  (`@handoff-to-review`) or a hash (`@sha256:<hex>`).

## Save context

```sh
prego context save ./.agent-memory acme/agents/billing-agent --session 2026-11-20-a --trigger compact
prego context save ./.agent-memory acme/agents/billing-agent --session 2026-11-20-a \
  --label ticket=OPS-412 --message "Before compaction"
```

- The command reads all regular files of the folder (also dotfiles; a folder named `.git` is skipped), checks
  them, makes one `.tar.gz` and sends it.
- If the files are the same as the latest checkpoint of the session, Prego makes no new checkpoint.
- `--session` (at most 128 characters) groups the checkpoints of one agent run. `--trigger` is `compact`,
  `stop`, `manual` (the default) or `schedule`. `--parent sha256:<hash>` names the checkpoint that this one
  continues. `--label key=value` can be given up to 16 times. `--message` is at most 200 characters. `--tag`
  tags the new checkpoint.

### Save context before compaction

Run the command from the hook that your agent tool runs before compaction, with `--trigger compact`:

```sh
prego context save "$HOME/.agent-memory" acme/agents/billing-agent \
  --session "${AGENT_SESSION_ID:-$(date -u +%Y-%m-%d)}" --trigger compact --message "before compaction"
```

## Secrets and personal data

- Before `prego` sends a checkpoint, it replaces text that looks like a key or a token with
  `[REDACTED:<kind>]`: Prego API keys, PEM private keys, AWS access key IDs, GitHub, GitLab and Slack tokens,
  Stripe live keys and JWTs. It prints how many strings it replaced, never the strings.
- `--no-redact` sends the files as they are. The registry still refuses a file that looks like it holds a
  secret.
- Prego refuses a checkpoint that still has such text (`422 looks_like_secret`). The error gives the file and
  the line, never the text.
- Prego does not find all secrets, and does not find personal data. Do not save context that holds customer
  secrets or personal data that you must not keep. Set a short number of days for context with personal data.
- `prego context hash` gives the hash after redaction, the same hash that a save of the folder gives.

## If Prego refuses a save

`prego` keeps the checkpoint in `./.prego-context/<context>-<time>.tar.gz` (readable only by you), prints the
path and the error, and exits with code **4**. Your context is not lost. This also happens when the token
exchange fails or the upload is too large. Fix the cause, then save the folder again.

## Restore context

```sh
prego context restore acme/agents/billing-agent ./.agent-memory                          # the latest checkpoint
prego context restore acme/agents/billing-agent ./.agent-memory --session 2026-11-20-a   # the latest of a session
prego context restore acme/agents/billing-agent@42 ./.agent-memory
prego context restore acme/agents/billing-agent@handoff-to-review ./.agent-memory
```

- The folder must be new or empty. `prego` reads the file list, computes the hash from it, downloads the
  checkpoint by that hash and checks that its files give the same hash. It writes the files only when all of
  them pass.
- A file path that leaves the folder (`..`, `/` at the start) is refused, and nothing is written.
- Files get mode `0644`, or `0755` for a file that was executable.

## Pin the hash

```sh
prego context restore acme/agents/billing-agent@handoff-to-review ./.agent-memory --expect sha256:<hash>
```

If the checkpoint has a different hash, `prego` exits with code **3** and writes nothing.

## See, keep and remove checkpoints

```sh
prego context ls acme/agents                                    # the contexts you can read
prego context log acme/agents/billing-agent --session 2026-11-20-a   # newest first, * = latest
prego context tag acme/agents/billing-agent@42 handoff-to-review     # written one time only
prego context set acme/agents/billing-agent --keep-days 30
prego context set acme/agents/billing-agent --on-full drop_oldest
prego context rm acme/agents/billing-agent@42
prego context rm acme/agents/billing-agent --session 2026-11-20-a
```

- Prego keeps checkpoints without a tag for `keep_days` days (default 90, Trial 30; the plan sets the maximum),
  and always keeps the newest checkpoint of a context.
- When your plan has no space for more checkpoints, Prego refuses the save (`on_full` = `refuse`, the default).
  With `drop_oldest`, Prego removes the oldest checkpoint without a tag of that context and saves the new one.

## Rules for files

- Text only: UTF-8 with no NUL byte. Markdown, JSON, JSONL and YAML work. Binary files are refused.
- At most 1,000 files per checkpoint, each at most 32 MiB, all together at most 128 MiB; the upload is at most
  32 MiB compressed.
- Paths follow the Snippets rules ([guide](snippets.md#rules-for-files)): relative, `/` separated, at most 255
  bytes, no `.` or `..` segment, no control or bidi characters, no two paths that are equal after Unicode NFC and
  lowercase. Symlinks are refused.

For the limits of your plan (contexts and checkpoints per tenant, storage, usage), see the console and the plan
limits page.

## Errors

| Message | Meaning |
| --- | --- |
| `not found, or you have no grant for it` | No context, no checkpoint, or no grant (`404`). |
| `403 ...` | You can read the context but you have no grant for this, or the plan does not allow it. |
| `403 plan_limit` | The plan's checkpoint count or storage pool is full. Restores, tags, settings and deletes still work. |
| `409 conflict` | The tag already names another checkpoint. |
| `412` / exit code 3 | `--expect` did not match. Nothing was written. |
| `413 ...` | A file, the checkpoint or the upload is too large. |
| exit code 2: `this checkpoint uses encryption mode M, which this prego version cannot read` | The checkpoint uses an encryption mode (a later add-on) that this `prego` cannot read. Nothing was written. |
| exit code 4 | The save was refused. The checkpoint is kept in `./.prego-context/`; the error says why. |
| `422 looks_like_secret (file: F, line N)` | A line looks like a credential. The value is never shown. |
| `400 checkpoint_invalid (file: F, reason)` | A path or a file breaks the rules above. |

[PROTOCOL.md](../PROTOCOL.md) section 15 has the routes and the full client contract.

Full docs, with examples: <https://docs.prego.k8skill.com/context> (sign in with your Prego account; open from the console's Docs link).
