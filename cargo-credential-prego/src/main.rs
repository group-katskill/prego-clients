//! `cargo-credential-prego`: a Cargo credential provider for Prego registries.
//!
//! Cargo starts this binary with `--cargo-plugin` and speaks the credential protocol on stdin and stdout.
//! The arguments from `credential-provider` come in each request, not on the command line.

#![forbid(unsafe_code)]

mod provider;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_COMMIT: &str = env!("PREGO_GIT_COMMIT");

const HELP: &str = "\
cargo-credential-prego: Cargo credential provider for Prego by Katskill.

Cargo runs this program. Configure it in .cargo/config.toml:

  [registries.acme]
  index = \"sparse+https://cargo.prego.k8skill.com/t/acme/default/index/\"
  credential-provider = [\"cargo-credential-prego\", \"--tenant\", \"acme\"]

Provider arguments (environment fallback, then ~/.config/prego/config.toml):
  --tenant <slug>    (PREGO_TENANT)    tenant slug, required
  --sts-url <url>    (PREGO_STS_URL)   default https://sts.prego.k8skill.com/v1/sts/token
  --edge-code <code> (PREGO_EDGE_CODE) your tenant's edge code (the console shows it)
  --audience <aud>   (PREGO_AUDIENCE)  default prego.k8skill.com
  --source <name>    (PREGO_SOURCE)    auto, spiffe, svid-file, gitlab, github, token-file, api-key

Environment only:
  PREGO_CA_FILE      PEM CA bundle added to the built-in roots (on-prem TLS proxies)

Program options:
  -V, --version      print the version and git commit
  -h, --help         print this help
";

fn main() {
    let first = std::env::args().nth(1);
    match first.as_deref() {
        Some("-V" | "--version") => println!("cargo-credential-prego {VERSION} ({GIT_COMMIT})"),
        Some("-h" | "--help") => print!("{HELP}"),
        _ => cargo_credential::main(provider::PregoCredential::new(Box::new(
            prego_auth::ProcessEnv,
        ))),
    }
}
