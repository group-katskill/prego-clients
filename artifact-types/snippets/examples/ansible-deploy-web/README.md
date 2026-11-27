# deploy-web runbook

Installs nginx and serves one static site on the hosts in the `web` group. Debian and Ubuntu hosts.

## Run

```sh
prego snippet get acme/ops/deploy-web@2026-11-26 ./deploy-web --expect sha256:<hash>
cd deploy-web
cp inventory.example.ini inventory.ini   # add your hosts
ansible-playbook -i inventory.ini playbook.yml --check --diff
ansible-playbook -i inventory.ini playbook.yml
```

Change a value with `-e`, for example `-e web_port=8081`. The inputs are in [`runbook.yaml`](runbook.yaml).

Do the check run (`--check --diff`) first. Read the changes. Then do the real run.

If you add Ansible Vault files, give the vault password at run time (`--ask-vault-pass`, or `--vault-password-file`
from your secret store). Do not push the vault password file. Keep `inventory.ini` out of the snippet.
