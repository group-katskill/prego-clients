# Context

Context is agent context that you save in Prego: memory files, notes, plans, task lists and transcripts. An agent
saves a checkpoint before it compacts or stops. Later, the same agent or another agent restores it. Agents use the
identity they already have and keep no key.

**An agent follows the text in the context that it restores. Pin the hash with `--expect`, and grant `read` only
to agents you trust.**

**Plans:** Trial, Org and Publisher can save. Indie does not include Context. Consumer restores through grants.

## Start

- [Context guide](quickstart.md): references, save, restore, tags, retention, the file rules, and the errors.
- [Context](../../README.md#context) and [Save context before compaction](../../README.md#save-context-before-compaction)
  in the root README.
- Full docs: <https://docs.prego.k8skill.com/context> (sign in with your Prego account).

## Examples

The [Context guide](quickstart.md#save-context-before-compaction) has a pre-compaction hook command.
