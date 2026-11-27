# Snippets examples: share runbooks

Prego has no special type for runbooks. A runbook is a snippet: the playbook or the script, the files that it needs,
and a README with the run command. Each folder here is a runbook that you can push as a snippet.

| Folder | What it shows |
| --- | --- |
| [`ansible-deploy-web/`](ansible-deploy-web/) | An Ansible playbook with a role, an inventory example and a check run first. |
| [`python-rotate-logs/`](python-rotate-logs/) | A Python runbook with pinned requirements, run in a virtual environment, with a dry run first. |

**A runbook is code that you run.**

- Get a tagged version and give the hash with `--expect`. Do not run the current version in automation.
- Give the hash to the people who run the runbook in a different channel, for example in the change ticket.
- Give `read` grants only on runbooks from publishers that you trust.
- Prego does not sign snippets yet. Signed sets work today for A2A Agent Cards. Signed snippets come in a later
  release. Until then, the reader pins the hash.
- Do not put passwords, vault passwords, keys or real host lists in a runbook. Prego refuses a file that looks like a
  secret.

## Push and run

```sh
prego login --publish --namespace ops
prego snippet push artifact-types/snippets/examples/ansible-deploy-web acme/ops/deploy-web --tag 2026-11-26
prego snippet hash artifact-types/snippets/examples/ansible-deploy-web   # put this hash in the change ticket
```

On the machine that runs it:

```sh
prego snippet get acme/ops/deploy-web@2026-11-26 ./deploy-web --expect sha256:<hash>
```

Then follow the README in the folder.

## The runbook.yaml convention

Each folder has a `runbook.yaml` file. We recommend it. Prego does not read or check it.

| Key | What it means |
| --- | --- |
| `kind` | The tool that runs the runbook: `ansible`, `python` or `shell`. |
| `entrypoint` | The file to start, relative to the folder. |
| `inputs` | The values that the person or the job must give: `name`, `description`, and `default` or `required: true`. |

Full docs: <https://docs.prego.k8skill.com/snippets#share-runbooks>.
