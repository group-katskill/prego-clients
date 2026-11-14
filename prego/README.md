# prego

Command-line tool for **Prego by Katskill**.

```sh
cargo install prego
```

| Command | What it does |
| --- | --- |
| `prego token [--resource <url>]` | Prints a registry token on stdout. For tools that need a token in a variable. Its lifetime comes from the grants (15 minutes by default). With `--resource` (a registry base URL such as `https://cargo.prego.k8skill.com/t/acme/default/`), the lifetime is the one for that namespace. |
| `prego token --scope repository:acme/default/api:pull` | Gets the token from the OCI token realm instead of the STS. |
| `prego whoami [--resource <url>]` | Shows the tenant, the identity source, the principal, the token lifetime (for `--resource`, or for all grants) and the registry URLs. It does not show the token. |
| `prego setup cargo` | Prints the `.cargo/config.toml` snippet for your tenant. |
| `prego oci push <input> <image>` | Pushes an image from an OCI image layout directory or a `docker save` tar file. Each layer is sent in parts of at most 95 MiB, so layers above the `docker push` limit work. `--from <repo>` mounts blobs from another repository of the tenant. `--chunk-size <MiB>` sets the part size (default 64). |
| `prego go publish [<dir>] [<tag>]` | From 0.4.0. Builds a Go module zip from the git tree of the tag (never from the working directory) and publishes it. `--dry-run` prints the files and the h1. `--json` prints `{module, version, h1, mod_h1}`. `--namespace` chooses the namespace. |
| `prego go-auth` | From 0.4.0. The GOAUTH helper for Go 1.24 and later: `GOAUTH='prego go-auth'`. |
| `prego setup go` | From 0.4.0. Prints the `go env -w` lines for `GOPROXY`, `GONOSUMDB` and `GOAUTH`. `--write` runs them. `--prefix` gives a module path prefix. |
| `prego setup npm [--scope @acme]` | From 0.6.0. Writes the scope line and `${PREGO_NPM_TOKEN}` (never a token) to `.npmrc`. `--client pnpm\|yarn\|bun` for the other tools (`.yarnrc.yml`, `bunfig.toml`), `--user` for `~/.npmrc`, `--print` to write nothing, `--namespace` for another namespace. |
| `prego npm-env` | From 0.6.0. Prints `export PREGO_NPM_TOKEN='<token>'`, for `eval "$(prego npm-env)"`. |
| `prego exec -- <command>` | From 0.4.0. Runs the command with `NETRC` set to a temporary file (mode 0600) that holds a registry token, for Go before 1.24. From 0.6.0 also with the token in `PREGO_NPM_TOKEN` and `PREGO_TOKEN`, for npm, pnpm, Yarn and Bun. |
| `prego env pull <ref>` | From 0.8.0. Gets the Release Variables of a release (`acme/payments@1.4.0`), merged from the tenant, namespace and version sets. `--format env\|json\|flat`, `--out FILE`. `--expect <hash>` exits with 3 if the resolved hash is different. In env format every value is shell-quoted. |
| `prego env push <ref>` | From 0.8.0. Pushes a new version of a set from `--file vars.json`, `--env-file .env` (strings only), `--set KEY=VALUE` and `--set-json KEY=<JSON>`. The push replaces the whole set. `--if-current <hash>`, `--message`, `--level tenant\|namespace`. |
| `prego env history\|rollback\|diff <ref>` | From 0.8.0. The versions of a set, a rollback (`--to <n> --reason`), and the keys changed between two versions. |
| `prego env hash <file>` | From 0.8.0. The RFC 8785 `sha256:` hash of a JSON object, the same as the registry, offline. |
| `prego setup python` | From 0.9.0. Writes the prego index (`explicit = true`) and `[tool.uv.sources]` to `pyproject.toml`, never a token. Without `--project`, the sources are the projects you can read. `--tool poetry` writes a Poetry source, `--tool pip` prints the line and the dependency confusion warning. `--print` writes nothing. |
| `prego python publish <file>...` | From 0.9.0. Uploads wheels and sdists to the namespace (`--namespace`). Files over 90 MiB are refused before the upload. |
| `prego token --python [--url <url>]` | From 0.9.0. Prints a Python token (30 minutes) for the namespace of the URL, cached until 1 minute before it ends. For the keyring helper `keyrings.prego`. |
| `prego exec [--python] [--pip] -- <command>` | From 0.9.0. The Python mode (also automatic for `uv`, `pip`, `python`, `twine`, `poetry`, `pdm`, `hatch`): one Python token in the uv, twine and Poetry variables, and in `PIP_EXTRA_INDEX_URL` with `--pip`. |
| `prego adapter push <folder> <repo>:<version>` | From 0.10.0 (Publisher plan). Pushes an AI model adapter (LoRA and the other peft methods): `adapter_config.json`, one `.safetensors` file and at most 8 text files. It checks them first, with the rules of the registry. `--license` (or `license:` in the README.md front matter) is required; `--base-revision` records the commit of the base model. A version is written one time only. |
| `prego adapter get <repo>:<version> <folder>` | From 0.10.0. Writes the files of an adapter to a new or empty folder and checks the SHA-256 of each file. Load it with peft (`PeftModel.from_pretrained`) or vLLM (`--lora-modules`). |
| `prego setup docker` | Prints the `~/.docker/config.json` snippet. With `--write`, adds `credHelpers` for the Prego OCI hosts to that file. It makes a backup copy first and keeps all other keys. |

Stock `docker push`, Podman and BuildKit send each layer in one request, and Prego accepts at most 95 MiB in one
request. Use `prego oci push` for an image with a bigger layer:

```sh
docker save acme-api:1.4.0 -o api.tar
prego oci push api.tar acme/default/api:1.4.0
```

`prego` uses the same identity sources, options and settings file (`~/.config/prego/config.toml`) as
`cargo-credential-prego` and `docker-credential-prego`. See the repository `README.md` and
`docs/go-quickstart.md`, `docs/npm-quickstart.md` and `docs/release-variables.md`.

Release Variables are plain text, readable by everyone who can pull the release. Do not store passwords, tokens
or keys here.

`prego token` prints a secret. Use it in a variable (`export PREGO_NPM_TOKEN="$(prego token)"`), not in a
log.

License: `Apache-2.0`.
