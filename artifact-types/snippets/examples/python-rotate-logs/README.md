# rotate-logs runbook

Removes `.log` files older than a number of days from one folder. Python 3.9 or later.

## Run

Make the virtual environment outside the runbook folder, so that the folder stays the same as the pushed version.

```sh
prego snippet get acme/ops/rotate-logs@2026-11-26 ./rotate-logs --expect sha256:<hash>
python3 -m venv .venv-rotate-logs
. .venv-rotate-logs/bin/activate
pip install -r rotate-logs/requirements.txt
python rotate-logs/runbook.py --dir /var/log/myapp --days 14 --dry-run
python rotate-logs/runbook.py --dir /var/log/myapp --days 14
```

Do the dry run first. Read the list of files. Then do the real run. The inputs are in [`runbook.yaml`](runbook.yaml).
