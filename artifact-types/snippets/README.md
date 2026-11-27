# Snippets

A snippet is a named set of text files: scripts, prompts, agent skills, templates and runbooks. Its versions do not change.
Machines and agents read snippets with the identity that they already have. Like a gist, but private and
versioned.

**An agent follows the text in a snippet. Pin the hash with `--expect`, and grant `read` only on snippets you
trust.**

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants.

## Start

- [Snippets guide](quickstart.md): references, the file rules, the hash, CI, and the errors.
- [Snippets](../../README.md#snippets) in the root README.
- Full docs: <https://docs.prego.k8skill.com/snippets> (sign in with your Prego account).

## Examples

The [Snippets guide](quickstart.md#ci) has a CI job.

[Share runbooks](examples/README.md): an Ansible playbook and a Python runbook that you push as snippets, with the
recommended `runbook.yaml` file. A runbook is code that you run: pin a tag and the hash.
