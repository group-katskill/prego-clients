# Python packages with `prego`

**From prego 0.9.0.** Python packages need `prego` 0.9.0 or later and Prego registry 1.9.0 or later, on the Org
or Publisher plan.

Prego gives each namespace a private Python index. uv, pip and Poetry read it. `uv publish`, twine and
`prego python publish` write to it. Your public dependencies still come from pypi.org: Prego does not copy
them.

This guide uses tenant `acme`, namespace `default` and project `acme-core`. Replace them with your own.

- Index URL: `https://pypi.prego.k8skill.com/t/acme/default/simple/`
- Upload URL: `https://pypi.prego.k8skill.com/t/acme/default/legacy/`
- Files: wheels (`.whl`) and sdists (`.tar.gz`), at most 90 MiB each.
- A Python token lasts 30 minutes on every plan, so long installs do not stop part way.

## Install with uv (recommended)

```sh
prego setup python              # writes the prego index and [tool.uv.sources] to pyproject.toml
prego exec -- uv sync
```

`prego setup python` adds these lines to `pyproject.toml`. It keeps all other lines, and it never writes a
token:

```toml
[[tool.uv.index]]
name = "prego"
url = "https://pypi.prego.k8skill.com/t/acme/default/simple/"
explicit = true
authenticate = "always"

[tool.uv.sources]
acme-core = { index = "prego" }
```

- Without `--project`, the sources are the projects that your identity can read in the namespace. With
  `--project acme-core` (one or more times), only those. If it finds none, the table has a comment line: add
  one line for each private package.
- `explicit = true` tells uv to ask Prego only for the packages in `[tool.uv.sources]`. All other names come
  from pypi.org. This stops dependency confusion.
- `--namespace <ns>` picks another namespace. `--print` prints the lines and writes nothing.

## Install with Poetry

```sh
prego setup python --tool poetry                     # [[tool.poetry.source]] name "prego", priority explicit
prego exec --python -- poetry add --source prego acme-core
prego exec --python -- poetry install
```

## Install with pip

pip asks every index for every name and installs the highest version. A package on pypi.org with the same name
as your private package can win. Use pip only when you cannot use uv or Poetry.

```sh
prego exec --pip -- pip install acme-core
```

If you use pip, register the same names on pypi.org as empty placeholders, or install with hashes
(`pip install --require-hashes -r requirements.txt`). `prego setup python --tool pip` prints this warning and
the line.

## `prego exec` for Python

`prego exec -- <command>` uses the Python mode when the command is `uv`, `uvx`, `pip`, `python`, `twine`,
`poetry`, `pdm` or `hatch`, or with `--python` or `--pip`. It gets one Python token for the namespace and sets,
for the command only:

| Variable | Value |
| --- | --- |
| `UV_INDEX_PREGO_USERNAME`, `UV_INDEX_PREGO_PASSWORD` | `__token__` and the token, for the uv index named `prego` |
| `UV_PUBLISH_USERNAME`, `UV_PUBLISH_PASSWORD`, `UV_PUBLISH_URL` | for `uv publish` |
| `TWINE_USERNAME`, `TWINE_PASSWORD`, `TWINE_REPOSITORY_URL` | for `twine upload` |
| `POETRY_HTTP_BASIC_PREGO_USERNAME`, `POETRY_HTTP_BASIC_PREGO_PASSWORD` | for the Poetry source named `prego` |
| `PIP_EXTRA_INDEX_URL` | with `--pip` only: the index URL with the token in it |
| `PREGO_TOKEN` | the token |

Nothing is written to a file. `--namespace <ns>` picks the namespace of the upload URL and the token. In the
Python mode, `prego exec` prints nothing on stderr.

## Publish

```sh
uv build
prego exec -- uv publish                         # UV_PUBLISH_URL is set
prego python publish dist/*                      # or with prego only
prego exec -- python3 -m twine upload dist/*     # or twine
```

- `prego python publish` checks every file before the first upload: only `.whl` and `.tar.gz`, at most 90 MiB.
  It streams each file with the upload API that twine uses, and stops at the first error with the registry's
  message. At the end it prints the uv lines for the projects.
- You cannot upload the same filename two times, also after a delete. Publish a new version.
- A grant with `publish` lets a machine publish. Publishing never uses an API key.

## The keyring helper (`keyrings.prego`)

`keyrings.prego` is a keyring backend in this repository (`keyrings-prego/`). For a Prego Python host it runs
`prego token --python --url <index url>`; for every other host it gives nothing. `prego token --python` caches
the token (mode 0600, in `$XDG_RUNTIME_DIR`) until one minute before it ends, so nested pip runs make no new
exchange. It is not on pypi.org yet. Until then, use `prego exec`.

## CI

GitLab, with OIDC and no stored secret:

```yaml
test:
  id_tokens:
    PREGO_ID_TOKEN: { aud: prego.k8skill.com }
  variables:
    PREGO_TENANT: acme
    PREGO_EDGE_CODE: k7mq
  script:
    - prego exec -- uv sync --locked
```

GitHub Actions works the same with `permissions: id-token: write`. See the [CI guide](ci.md).

## Errors

| Message | Cause | Fix |
| --- | --- | --- |
| `File already exists.` | The filename was used before. | Publish a new version. |
| `is larger than 90 MiB` | The file is too large. `prego python publish` stops before the upload. | Make the wheel smaller, or split the package. |
| `Python packages need the Org or Publisher plan.` | The tenant is on Indie. | Change to Org or Publisher. |
| `401` | No token, or the token expired. | Run the command with `prego exec`, or run `prego whoami`. |
| `is not a Prego Python URL` | `prego token --python --url` got another host. | Give the Prego index URL. A token never goes to another host. |
