//! `prego`: the command-line tool for Prego by Katskill.

#![forbid(unsafe_code)]

mod admin;
mod args;
mod docker_config;
mod go;
mod login;
mod npm;
mod oci;
mod setup;
mod token;

use args::{Command, Parsed};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_COMMIT: &str = env!("PREGO_GIT_COMMIT");
const USER_AGENT: &str = concat!("prego/", env!("CARGO_PKG_VERSION"));

const HELP: &str = "\
prego: command-line tool for Prego by Katskill.

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
  exec -- <command> [args]        run a command with a fresh registry token in PREGO_NPM_TOKEN and
                                  PREGO_TOKEN (npm, pnpm, Yarn, Bun), and NETRC set to a temporary file
                                  (mode 0600, deleted at the end) that holds it (Go before 1.24)

Options (environment fallback, then ~/.config/prego/config.toml):
  --tenant <slug>    (PREGO_TENANT)    tenant slug
  --sts-url <url>    (PREGO_STS_URL)   default https://sts.prego.k8skill.com/v1/sts/token
  --edge-code <code> (PREGO_EDGE_CODE) your tenant's edge code (the console shows it)
  --audience <aud>   (PREGO_AUDIENCE)  default prego.k8skill.com
  --source <name>    (PREGO_SOURCE)    auto, spiffe, svid-file, gitlab, github, token-file, api-key,
                                       device (the prego login session; auto uses it last)

Environment only:
  PREGO_OCI_HOSTS    more OCI hosts, comma-separated (also oci_hosts in config.toml)
  PREGO_GO_HOSTS     Go hosts, comma-separated; the first is used (also go_hosts in config.toml;
                     default go.prego.k8skill.com)
  PREGO_NPM_HOST     the npm host (also npm_host in config.toml; default npm.prego.k8skill.com)
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
                Command::Whoami {
                    namespace,
                    resource,
                } => token::whoami(&globals, &namespace, resource.as_deref(), &env),
                Command::SetupCargo {
                    namespace,
                    registry,
                } => setup::cargo(&globals, &namespace, registry.as_deref(), &env),
                Command::SetupDocker { write } => setup::docker(write, &env),
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
                Command::Exec { command } => match go::exec(&globals, &command, &env) {
                    Ok(code) => std::process::exit(code),
                    Err(e) => Err(e),
                },
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
