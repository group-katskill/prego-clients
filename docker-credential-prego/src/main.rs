//! `docker-credential-prego`: a Docker credential helper for Prego OCI registries.
//!
//! Docker runs `docker-credential-prego <action>` and writes the request on stdin. See [`helper`].

#![forbid(unsafe_code)]

mod helper;

use std::io::{Read, Write};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_COMMIT: &str = env!("PREGO_GIT_COMMIT");

const HELP: &str = "\
docker-credential-prego: Docker credential helper for Prego by Katskill.

Docker runs this program. Configure it in ~/.docker/config.json:

  { \"credHelpers\": { \"oci.prego.k8skill.com\": \"prego\" } }

and set the tenant in ~/.config/prego/config.toml (tenant = \"acme\") or PREGO_TENANT.

Usage: docker-credential-prego [options] <get|store|erase|list>

  get     reads a server URL on stdin. For a Prego OCI host it prints the tenant as Username and the
          subject token as Secret. For any other host it fails with
          \"credentials not found in native keychain\", so Docker uses its other credentials.
  store   does nothing. Prego keeps no password in Docker.
  erase   does nothing.
  list    prints the Prego OCI hosts with the tenant.

Options (environment fallback, then config.toml):
  --tenant <slug>    (PREGO_TENANT)    tenant slug
  --audience <aud>   (PREGO_AUDIENCE)  default prego.k8skill.com
  --source <name>    (PREGO_SOURCE)    auto, spiffe, svid-file, gitlab, github, token-file, api-key

Environment only:
  PREGO_OCI_HOSTS    more OCI hosts, comma-separated (also oci_hosts in config.toml)
  PREGO_CA_FILE      PEM CA bundle added to the built-in roots (on-prem TLS proxies)

Program options:
  -V, --version      print the version and git commit
  -h, --help         print this help
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("-V" | "--version" | "version") => {
            println!("docker-credential-prego {VERSION} ({GIT_COMMIT})");
            return;
        }
        Some("-h" | "--help") => {
            print!("{HELP}");
            return;
        }
        None => {
            eprint!("{HELP}");
            std::process::exit(1);
        }
        _ => {}
    }

    // The action is the last argument. Options come before it.
    let (action, flags) = args.split_last().expect("args is not empty");
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();

    let mut input = String::new();
    if matches!(action.as_str(), "get" | "store" | "erase") {
        let read = std::io::stdin()
            .take(helper::MAX_INPUT_BYTES as u64 + 1)
            .read_to_string(&mut input);
        if read.is_err() || input.len() > helper::MAX_INPUT_BYTES {
            println!("prego: cannot read the request on stdin");
            std::process::exit(1);
        }
    }

    let outcome = helper::run(action, &flags, &input, &prego_auth::ProcessEnv);
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(outcome.stdout.as_bytes());
    let _ = out.flush();
    std::process::exit(outcome.code);
}
