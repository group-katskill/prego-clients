# Python

Prego gives each namespace a private Python index on `pypi.prego.k8skill.com`. uv, pip and Poetry read it.
`prego python publish`, `uv publish` and twine write to it. Public packages still come from pypi.org.

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants.

## Start

- [Python quickstart](quickstart.md): uv, Poetry, pip, publishing, the keyring helper, CI, and the errors.
- [Python packages](../../README.md#python-packages) in the root README.
- Full docs: <https://docs.prego.k8skill.com/python> (sign in with your Prego account).

## Examples

The [Python quickstart](quickstart.md#ci) has the CI jobs.
