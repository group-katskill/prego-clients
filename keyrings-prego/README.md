# keyrings.prego

A [keyring](https://pypi.org/project/keyring/) backend for Prego Python packages. pip, uv and Poetry ask the
keyring for the password of an index. For a Prego Python host (`*.prego.k8skill.com`, or the host in
`PREGO_PYPI_HOST`), this backend runs `prego token --python --url <index url>` and gives the token with the
username `__token__`. For any other host it gives nothing, so your other keyring backends still answer.

It never stores a token. `prego` caches the token (mode 0600, in `$XDG_RUNTIME_DIR`) until one minute before
it ends, so nested pip runs (sdist builds in isolated environments) make no new token exchange.

## Needs

- Python 3.9 or later, `keyring` 23 or later.
- The `prego` CLI 0.9.0 or later on `PATH`, with an identity: a CI OIDC token, a workload identity, an API key
  or `prego login`. If `prego` is not on `PATH`, the backend gives nothing.

## Use

```sh
pip install keyrings.prego                      # in the same environment as keyring
pip install --keyring-provider import --index-url https://pypi.prego.k8skill.com/t/acme/default/simple/ acme-core
uv pip install --keyring-provider subprocess acme-core   # uv runs the keyring CLI
pipx inject poetry keyrings.prego               # Poetry
```

For uv and pip, `prego exec -- <command>` is often simpler: it sets the variables for one command and needs
no keyring.

## License

Apache-2.0.
