//! `prego`: the command-line tool for Prego by KatSkill.

#![forbid(unsafe_code)]

mod adapter;
mod admin;
mod args;
mod context;
mod docker_config;
mod env;
mod go;
mod login;
mod npm;
mod oci;
mod python;
mod setup;
mod snippet;
mod sqlite;
mod token;

use args::{Command, Parsed};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_COMMIT: &str = env!("PREGO_GIT_COMMIT");
const USER_AGENT: &str = concat!("prego/", env!("CARGO_PKG_VERSION"));

const HELP: &str = "\
prego: command-line tool for Prego by KatSkill.

Usage: prego [options] <command>

Commands:
  login [--publish] [--no-browser]
                                  log in with your console sign-in: open the page, confirm the code. The
                                  session is kept in the OS keychain (on Linux without a desktop, in the
                                  kernel keyring, lost at reboot), never in a file. It gives read access;
                                  --publish asks for read and publish. The tools use it when no workload
                                  identity and no PREGO_API_KEY is set. Not for CI
  logout                          end the login session and delete it from this computer
  status                          show the login session: tenant, access, end time (never a token)
  token [--scope <scope>]... [--resource <url>]
                                  print a registry token on stdout. Its lifetime comes from the grants (15 min
                                  by default). With --resource (a registry base URL, for example
                                  https://cargo.prego.k8skill.com/t/acme/default/), the lifetime is the one of
                                  the grants for that namespace. With --scope, get it from the OCI token
                                  realm, for example --scope repository:acme/default/api:pull
  whoami [--namespace <ns>] [--resource <url>]
                                  show the tenant, the identity source, the principal, the token lifetime and
                                  the registry URLs
  setup cargo [--namespace <ns>] [--registry <name>]
                                  print the .cargo/config.toml snippet
  setup docker [--write]          print the ~/.docker/config.json snippet. With --write, add credHelpers for
                                  the Prego OCI hosts to that file (a backup copy is made first)
  oci push <input> <image> [--from <repo>] [--chunk-size <MiB>]
                                  push an image from an OCI image layout directory or a docker save tar
                                  file. Layers are sent in parts (default 64 MiB, at most 95 MiB), so layers
                                  above the 95 MiB limit of docker push work. <image> is
                                  [host/]<tenant>/<namespace>/<repo>[:tag]. --from mounts blobs that are
                                  already in another repository of the tenant
  adapter push <folder> <repo>:<version> [--license <id>] [--base-revision <rev>]
                                  (preview) push an AI model adapter (LoRA and the other peft methods;
                                  Publisher and Trial plans). The folder has adapter_config.json, one .safetensors file
                                  and at most 8 text files (README.md, tokenizer files). prego checks them
                                  first, with the rules of the registry. The license comes from --license,
                                  or from license: in the README.md front matter. A version is written one
                                  time only. <repo> is [host/]<tenant>/<namespace>/<repo>
  adapter get <repo>:<version> <folder>
                                  (preview) write the files of an adapter to a new or empty folder, and
                                  check their SHA-256. Load it with peft (PeftModel.from_pretrained) or vLLM
                                  (--lora-modules name=<folder>)
  go publish [<module dir>] [<tag>] [--namespace <ns>] [--dry-run] [--json]
                                  build the module zip from the git tree of the tag (not from the working
                                  directory) and publish it. The tag defaults to the tag on HEAD
                                  (vX.Y.Z, or <subdir>/vX.Y.Z). --dry-run prints the files and the h1 and
                                  sends nothing. --json prints {module, version, h1, mod_h1}
  go-auth                         the GOAUTH helper for Go 1.24 and later: GOAUTH='prego go-auth'
  setup go [--namespace <ns>] [--prefix <path>]... [--write]
                                  print the go env -w lines for GOPROXY, GONOSUMDB and GOAUTH. With
                                  --write, run them. --prefix gives a module path prefix for GONOSUMDB
  setup npm [--scope @<scope>] [--namespace <ns>] [--client npm|pnpm|yarn|bun] [--user] [--print]
                                  write the scope line and a ${PREGO_NPM_TOKEN} reference (never a token)
                                  to .npmrc (npm, pnpm), .yarnrc.yml (yarn) or bunfig.toml (bun) in the
                                  current directory. --user writes ~/.npmrc. --print writes nothing. The
                                  scope defaults to the tenant's only npm scope
  npm-env                         print export PREGO_NPM_TOKEN='<token>', for eval \"$(prego npm-env)\"
  setup python [--namespace <ns>] [--project <name>]... [--tool uv|poetry|pip] [--print]
                                  write the prego index to pyproject.toml (never a token). uv (default):
                                  [[tool.uv.index]] with explicit = true, and [tool.uv.sources] for the
                                  projects (default: the projects you can read). poetry: [[tool.poetry.source]]
                                  with priority explicit. pip: print the line and the dependency confusion
                                  warning. --print writes nothing
  python publish [--namespace <ns>] <file>...
                                  upload wheels (.whl) and sdists (.tar.gz). Files over 90 MiB are refused
                                  before the upload
  token --python [--url <index url>] [--namespace <ns>]
                                  print a Python token (30 min) on stdout, for keyrings.prego. It is cached
                                  (mode 0600, in $XDG_RUNTIME_DIR) until 1 min before it ends
  env pull <ref> [--format env|json|flat] [--expect <hash>] [--out FILE]
                                  get the Release Variables of a release, merged from the tenant,
                                  namespace and version sets (the most specific wins). <ref> is
                                  <tenant>/<package>@<version> (namespace default) or
                                  <tenant>/<namespace>/<package...>@<version>. The format is env when stdout
                                  is not a terminal: KEY='value' lines, every value shell-quoted, JSON values
                                  as canonical JSON. --expect exits with 3 if the resolved hash is different
                                  (nothing is written)
  env push <ref> --file vars.json | --env-file .env | --set KEY=VALUE | --set-json KEY=<JSON>
           [--message <text>] [--if-current <hash>] [--level tenant|namespace]
                                  push a new version of a set. The push replaces the whole set: the file
                                  (a .env file gives strings only), then --set and --set-json on top.
                                  --if-current refuses the push if the current hash is different. With
                                  --level, <ref> is <tenant> or <tenant>/<namespace>. Needs publish
  env history <ref> [--level ...] list the versions of a set (* is the current one)
  env rollback <ref> --to <n> --reason <text> [--level ...]
                                  make version n the current one (no new version is made)
  env diff <ref> --from <n> --to <m> [--level ...]
                                  show the keys added, removed and changed between two versions
  env hash <file|->               print the sha256 hash of a JSON object of variables (RFC 8785
                                  canonical form), the same as the registry, offline
                                  Release Variables are plain text, readable by everyone who can pull the
                                  release. Do not store passwords, tokens or keys here.
  snippet push <folder|file> <ref> [--tag <tag>] [--message <text>] [--if-current <hash>] [--tar]
                                  push a new version of a snippet: a named set of text files (scripts,
                                  prompts, agent skills, templates). <ref> is <tenant>/<snippet> (namespace
                                  default) or <tenant>/<namespace>/<snippet>. A folder gives all its regular
                                  files (not .git); a file gives a snippet of one file. With --tar, the file
                                  is a .tar.gz or .tar that is sent as it is. At most 100 files, 1 MiB each,
                                  8 MiB together, UTF-8 text only; the mode is 0644, or 0755 when the owner
                                  can run the file. The same files give no new version. --if-current refuses
                                  the push if the current hash is different. Needs publish
  snippet get <ref>[@<version>] [<folder>] [--file <path>] [--tar] [--expect <hash>]
                                  write the files of a version (default current) to a new or empty folder
                                  (default ./<snippet>). <version> is a number, a tag, sha256:<hex> or current.
                                  Each file and the version hash are checked; no file leaves the folder.
                                  --file prints one file on stdout. --tar writes the .tar.gz to the file
                                  <folder> or to stdout. --expect exits with 3 if the version hash is
                                  different, and an encryption mode other than none exits with 2
                                  (nothing is written in both cases)
  snippet ls <tenant>[/<namespace>]
                                  list the snippets that you can read
  snippet log <ref>               list the versions, newest first, with tags (* is the current one)
  snippet diff <ref> <version> <version>
                                  show the files added, removed and changed, and a unified diff
  snippet tag <ref>@<version> <tag>
                                  give a version a tag. A tag is written one time only
  snippet rollback <ref> --to <version> --reason <text>
                                  make an older (or newer) version the current one (no new version is made)
  snippet hash <folder|file> [--tar]
                                  print the version hash (sha256 of the canonical file list), the same as
                                  the registry, offline
                                  A snippet that an agent reads is an instruction to that agent: pin it by
                                  hash (--expect) and grant read only on snippets you trust.
  context save <folder> <ref> [--session <s>] [--trigger compact|stop|manual|schedule] [--parent <hash>]
               [--label k=v]... [--message <text>] [--tag <tag>] [--no-redact]
                                  save a checkpoint of agent context (memory, notes, plans, transcripts):
                                  all regular files of the folder (not .git), UTF-8 text only, at most
                                  1,000 files, 32 MiB each, 128 MiB together. <ref> is <tenant>/<context>
                                  or <tenant>/<namespace>/<context>. Secret-shaped strings are replaced
                                  with [REDACTED:<kind>] first (the count is printed, never the strings);
                                  --no-redact sends the files as they are. The same files as the latest
                                  checkpoint of the session give no new checkpoint. If the save is
                                  refused, the checkpoint is kept in ./.prego-context/ and the exit code
                                  is 4. Needs publish
  context restore <ref>[@<checkpoint>] <folder> [--session <s>] [--expect <hash>]
                                  write a checkpoint (default latest; with --session, the latest of that
                                  session) to a new or empty folder. <checkpoint> is latest, a number, a
                                  tag or sha256:<hex>. The hash and every file are checked; no file leaves
                                  the folder; modes are 0644 or 0755. --expect exits with 3 if the hash is
                                  different, and an encryption mode other than none exits with 2 (nothing
                                  is written in both cases)
  context ls <tenant>[/<namespace>]
                                  list the contexts that you can read
  context log <ref> [--session <s>]
                                  list the checkpoints, newest first (* is the latest)
  context tag <ref>@<checkpoint> <tag>
                                  give a checkpoint a tag (written one time only). A tagged checkpoint is
                                  not removed by retention
  context rm <ref>@<checkpoint> | context rm <ref> --session <s>
                                  remove one checkpoint, or every checkpoint of a session. Needs delete
  context set <ref> [--keep-days <n>] [--on-full refuse|drop_oldest]
                                  keep checkpoints without a tag for n days; at the plan's checkpoint
                                  limit, refuse the save or remove the oldest checkpoint without a tag
  context hash <folder> [--no-redact]
                                  print the checkpoint hash of a folder, after redaction (as save sends
                                  it), offline
                                  An agent follows the text in the context that it restores: pin it by
                                  hash (--expect) and grant read only to agents you trust.
  sqlite save <file.db> <ref> [--compact] [--check quick|full|none] [--label k=v]... [--message <text>]
              [--tag <tag>]
                                  save a snapshot of a SQLite database. SQLite makes the copy (--compact uses
                                  VACUUM INTO, without free pages); the file is never copied as it is, so a
                                  program can keep using the database. Then PRAGMA quick_check runs on the
                                  copy (--check full: integrity_check; --check none: no check); if it fails,
                                  nothing is sent and the exit code is 5. <ref> is <tenant>/<database> or
                                  <tenant>/<namespace>/<database>.
                                  The same snapshot hash as the latest snapshot gives no new snapshot.
                                  Needs free disk space for one copy (in TMPDIR). If Prego refuses the
                                  save, the exit code is 4. Needs publish
  sqlite restore <ref>[@<snapshot>] <file.db> [--expect <hash>] [--force]
                                  write a snapshot (default latest; a number, a tag or sha256:<hex>) to
                                  <file.db>.prego-tmp, check the snapshot hash, the file sha256 and
                                  PRAGMA quick_check, then rename it to <file.db>. If a check fails, the
                                  exit code is 5 and <file.db> does not change. A database with a -wal or
                                  -journal file is not replaced unless --force (which also removes the
                                  -wal, -shm and -journal files): stop the program that uses it first.
                                  --expect exits with 3 if the hash is different, and an encryption mode
                                  other than none exits with 2 (nothing is written in both cases)
  sqlite ls <tenant>[/<namespace>]
                                  list the SQLite databases that you can read
  sqlite log <ref>                list the snapshots, newest first (* is the latest)
  sqlite tag <ref>@<snapshot> <tag>
                                  give a snapshot a tag (written one time only). Rotation does not remove
                                  a tagged snapshot
  sqlite rm <ref>@<snapshot> | sqlite rm <ref> [--yes]
                                  remove one snapshot, or the database with all its snapshots (asks
                                  first, unless --yes). Needs delete
  sqlite prune <ref> [--keep <n>] [--older-than <n>h|<n>d|<n>w] [--yes]
                                  remove the snapshots after the newest n, or older than the age (with
                                  both: only snapshots that match both). Never a tagged snapshot, never
                                  the newest one. Lists them and asks first, unless --yes. Needs delete
  sqlite set <ref> [--keep-count <n>] [--keep-days <n>]
                                  how many snapshots without a tag Prego keeps, and for how many days
  sqlite hash <file.db> [--compact]
                                  print the snapshot hash that a save would give, offline
                                  We are not your backup. We are for sharing. Keep your own copies of
                                  data that you must not lose.
  exec -- <command> [args]        run a command with a fresh registry token in PREGO_NPM_TOKEN and
                                  PREGO_TOKEN (npm, pnpm, Yarn, Bun), and NETRC set to a temporary file
                                  (mode 0600, deleted at the end) that holds it (Go before 1.24)
  exec [--python] [--pip] [--namespace <ns>] -- <command> [args]
                                  Python mode (with --python or --pip, or for uv, uvx, pip, python, twine,
                                  poetry, pdm and hatch): one Python token (30 min) in
                                  UV_INDEX_PREGO_USERNAME/PASSWORD, UV_PUBLISH_*, TWINE_* and
                                  POETRY_HTTP_BASIC_PREGO_*, with the upload URL of the namespace. --pip
                                  also sets PIP_EXTRA_INDEX_URL. Nothing is written to a file

Options (environment fallback, then ~/.config/prego/config.toml):
  --tenant <slug>    (PREGO_TENANT)    tenant slug
  --sts-url <url>    (PREGO_STS_URL)   default https://api.prego.k8skill.com/v1/sts/token
  --edge-code <code> (PREGO_EDGE_CODE) your tenant's edge code (the console shows it)
  --audience <aud>   (PREGO_AUDIENCE)  default prego.k8skill.com
  --source <name>    (PREGO_SOURCE)    auto, spiffe, svid-file, gitlab, github, token-file, api-key,
                                       device (the prego login session; auto uses it last)

Environment only:
  PREGO_OCI_HOSTS    more OCI hosts, comma-separated (also oci_hosts in config.toml)
  PREGO_GO_HOSTS     Go hosts, comma-separated; the first is used (also go_hosts in config.toml;
                     default go.prego.k8skill.com)
  PREGO_NPM_HOST     the npm host (also npm_host in config.toml; default npm.prego.k8skill.com)
  PREGO_PYPI_HOST    the Python packages host (also pypi_host in config.toml; default
                     pypi.prego.k8skill.com)
  PREGO_CA_FILE      PEM CA bundle added to the built-in roots (on-prem TLS proxies)
  DOCKER_CONFIG      directory of the Docker config.json (default ~/.docker)

Program options:
  -V, --version      print the version and git commit
  -h, --help         print this help
";

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match args::parse(&raw) {
        Ok(p) => p,
        Err(m) => fail(&format!("prego: {m}. Run `prego --help`.")),
    };
    let env = prego_auth::ProcessEnv;
    let result = match parsed {
        Parsed::Help => {
            print!("{HELP}");
            Ok(())
        }
        Parsed::Version => {
            println!("prego {VERSION} ({GIT_COMMIT})");
            Ok(())
        }
        Parsed::Run { globals, command } => {
            let globals: Vec<&str> = globals.iter().map(String::as_str).collect();
            match command {
                Command::Login {
                    publish,
                    no_browser,
                } => login::login(&globals, publish, no_browser, &env),
                Command::Logout => login::logout(&globals, &env),
                Command::Status => login::status(&globals, &env),
                Command::Token { scopes, resource } => {
                    token::token(&globals, &scopes, resource.as_deref(), &env)
                }
                Command::TokenPython { url, namespace } => {
                    python::token(&globals, url.as_deref(), &namespace, &env)
                }
                Command::SetupPython(opts) => python::setup::setup(&globals, &opts, &env),
                Command::PythonPublish { files, namespace } => {
                    python::publish::publish(&globals, &files, &namespace, &env)
                }
                Command::Whoami {
                    namespace,
                    resource,
                } => token::whoami(&globals, &namespace, resource.as_deref(), &env),
                Command::SetupCargo {
                    namespace,
                    registry,
                } => setup::cargo(&globals, &namespace, registry.as_deref(), &env),
                Command::SetupDocker { write } => setup::docker(write, &env),
                Command::AdapterPush {
                    folder,
                    reference,
                    license,
                    base_revision,
                } => adapter::push(
                    &globals,
                    &folder,
                    &reference,
                    license.as_deref(),
                    base_revision.as_deref(),
                    &env,
                ),
                Command::AdapterGet { reference, folder } => {
                    adapter::get(&globals, &reference, &folder, &env)
                }
                Command::OciPush {
                    input,
                    reference,
                    from,
                    chunk_size_mib,
                } => oci::push(
                    &globals,
                    &input,
                    &reference,
                    from.as_deref(),
                    chunk_size_mib,
                    &env,
                ),
                Command::GoPublish {
                    dir,
                    tag,
                    namespace,
                    dry_run,
                    json,
                } => go::publish::publish(
                    &globals,
                    &go::publish::Options {
                        dir: &dir,
                        tag: tag.as_deref(),
                        namespace: &namespace,
                        dry_run,
                        json,
                    },
                    &env,
                ),
                Command::GoAuth { args } => go::auth::go_auth(&globals, &args, &env),
                Command::SetupGo {
                    namespace,
                    prefixes,
                    write,
                } => go::setup(&globals, &namespace, &prefixes, write, &env),
                Command::SetupNpm(opts) => npm::setup(&globals, &opts, &env),
                Command::NpmEnv => npm::npm_env(&globals, &env),
                Command::Env(c) => env::run(&globals, &c, &env),
                Command::Snippet(c) => snippet::run(&globals, &c, &env),
                Command::Context(c) => context::run(&globals, &c, &env),
                Command::Sqlite(c) => sqlite::run(&globals, &c, &env),
                Command::Exec {
                    command,
                    python: py,
                    pip,
                } => {
                    let run = match &py {
                        Some(ns) => python::exec(&globals, &command, ns, pip, &env),
                        None => go::exec(&globals, &command, &env),
                    };
                    match run {
                        Ok(code) => std::process::exit(code),
                        Err(e) => Err(e),
                    }
                }
            }
        }
    };
    if let Err(m) = result {
        fail(&m);
    }
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    #[test]
    fn help_says_release_variables_are_not_secrets() {
        let help: String = super::HELP.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains(crate::env::NOT_SECRETS), "{help}");
        assert!(help.contains("The push replaces the whole set"));
    }

    #[test]
    fn help_says_to_pin_context() {
        let help: String = super::HELP.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains(crate::context::TRUST), "{help}");
    }

    #[test]
    fn help_has_the_sqlite_purpose_line() {
        let help: String = super::HELP.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains(crate::sqlite::PURPOSE), "{help}");
    }

    #[test]
    fn help_says_to_pin_snippets() {
        let help: String = super::HELP.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains(crate::snippet::TRUST), "{help}");
    }
}
