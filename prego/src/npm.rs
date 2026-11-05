//! npm, pnpm, Yarn and Bun: `prego setup npm` and `prego npm-env`.
//!
//! The client files get the scope line and a reference to `PREGO_NPM_TOKEN` only. A token value is never
//! written to a file.

use std::path::{Path, PathBuf};

use prego_auth::npm::{npm_host, registry_url, TOKEN_VAR};
use prego_auth::{Config, Env, FileConfig};

/// The package manager that `prego setup npm` writes the settings for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    Npm,
    Pnpm,
    Yarn,
    Bun,
}

impl Client {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "npm" => Ok(Client::Npm),
            "pnpm" => Ok(Client::Pnpm),
            "yarn" => Ok(Client::Yarn),
            "bun" => Ok(Client::Bun),
            other => Err(format!(
                "--client `{other}` is not known. Use npm, pnpm, yarn or bun"
            )),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Client::Npm => "npm",
            Client::Pnpm => "pnpm",
            Client::Yarn => "yarn",
            Client::Bun => "bun",
        }
    }

    /// The file name in the project directory.
    fn file_name(self) -> &'static str {
        match self {
            Client::Npm | Client::Pnpm => ".npmrc",
            Client::Yarn => ".yarnrc.yml",
            Client::Bun => "bunfig.toml",
        }
    }
}

/// The options of `prego setup npm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupOptions {
    pub namespace: String,
    /// `@acme` or `acme`. `None`: the tenant's only registered scope, from the admin API.
    pub scope: Option<String>,
    pub client: Client,
    /// Write `~/.npmrc` in place of `.npmrc` in the current directory (npm and pnpm only).
    pub user: bool,
    /// Print the lines, write no file.
    pub print: bool,
}

/// Checks an npm scope and returns it without the `@`. npm's rules: lowercase letters, digits and
/// `-._~`, not starting with `.` or `_`, 1 to 50 characters.
pub fn check_scope(scope: &str) -> Result<String, String> {
    let s = scope.strip_prefix('@').unwrap_or(scope);
    let ok = !s.is_empty()
        && s.len() <= 50
        && !s.starts_with(['.', '_'])
        && s.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '_' | '~')
        });
    if ok {
        Ok(s.to_string())
    } else {
        Err(format!(
            "prego: bad npm scope `{scope}`: use lowercase letters, digits and -._~ (1 to 50 characters), \
             for example @acme"
        ))
    }
}

/// The tenant's registered scopes from the admin API, without the `@`. `None` if the identity cannot read
/// them.
fn admin_scopes(config: &Config, env: &dyn Env) -> Option<Vec<String>> {
    let v = crate::admin::get(config, env, "/npm/scopes")?;
    let mut list: Vec<String> = v["items"]
        .as_array()?
        .iter()
        .filter_map(|i| i["scope"].as_str())
        .filter_map(|s| check_scope(s).ok())
        .collect();
    list.dedup();
    Some(list)
}

/// The registry URL without the scheme, as npm writes the auth key: `//host/t/acme/default/`.
fn nerf_dart(url: &str) -> &str {
    url.split_once("://").map_or(url, |(_, rest)| rest)
}

/// The two `.npmrc` lines.
pub fn npmrc_lines(scope: &str, url: &str) -> [String; 2] {
    [
        format!("@{scope}:registry={url}"),
        format!("//{}:_authToken=${{{TOKEN_VAR}}}", nerf_dart(url)),
    ]
}

/// Puts the two lines into an `.npmrc` text. Each line takes the place of an old line with the same key;
/// other lines stay as they are. Returns the new text and the notes for the user.
pub fn merge_npmrc(old: &str, scope: &str, url: &str, host: &str) -> (String, Vec<String>) {
    let lines = npmrc_lines(scope, url);
    let keys: Vec<String> = lines
        .iter()
        .map(|l| l.split_once('=').unwrap().0.to_string())
        .collect();
    let mut notes = Vec::new();
    let mut out: Vec<String> = Vec::new();
    let mut done = [false, false];
    for line in old.lines() {
        let key = line.split_once('=').map(|(k, _)| k.trim());
        if let Some(i) = keys.iter().position(|k| Some(k.as_str()) == key) {
            let value = line.split_once('=').unwrap().1.trim();
            if i == 1 && !value.is_empty() && !value.starts_with("${") {
                notes.push(format!(
                    "Replaced a token value in the {} line with ${{{TOKEN_VAR}}}. Never commit a token.",
                    keys[1]
                ));
            }
            if !done[i] {
                out.push(lines[i].clone());
                done[i] = true;
            }
            continue;
        }
        if key == Some("registry") {
            let value = line.split_once('=').unwrap().1.trim();
            if prego_auth::oci::normalize_host(value).as_deref() == Some(host) {
                notes.push(format!(
                    "Warning: the line `{}` sends all packages to Prego, and Prego serves scoped packages \
                     only. Remove it; the @{scope}:registry line is enough.",
                    line.trim()
                ));
            }
        }
        out.push(line.to_string());
    }
    for (i, line) in lines.iter().enumerate() {
        if !done[i] {
            out.push(line.clone());
        }
    }
    let mut text = out.join("\n");
    text.push('\n');
    (text, notes)
}

/// The Yarn 4 block for `.yarnrc.yml`.
pub fn yarn_block(scope: &str, url: &str) -> String {
    format!(
        "npmScopes:\n  {scope}:\n    npmRegistryServer: \"{url}\"\n    npmAuthToken: \"${{{TOKEN_VAR}}}\"\n"
    )
}

/// The Bun block for `bunfig.toml`.
pub fn bun_block(scope: &str, url: &str) -> String {
    format!("[install.scopes]\n\"@{scope}\" = {{ url = \"{url}\", token = \"${TOKEN_VAR}\" }}\n")
}

/// What to do with a Yarn or Bun file. The tool never rewrites YAML or TOML: it adds its block when the
/// file has no scopes section yet, else it leaves the file as it is.
#[derive(Debug, PartialEq, Eq)]
pub enum Append {
    /// The new text of the file.
    Write(String),
    /// The file already holds the block.
    AlreadySet,
    /// The file has a scopes section: the user adds the block by hand.
    ByHand,
}

pub fn append_block(old: Option<&str>, block: &str, client: Client) -> Append {
    let Some(old) = old.filter(|o| !o.trim().is_empty()) else {
        return Append::Write(block.to_string());
    };
    // The lines that set the URL and the token must both be there already.
    let wanted: Vec<&str> = block.lines().skip(1).map(str::trim).collect();
    let has: Vec<&str> = old.lines().map(str::trim).collect();
    if wanted.iter().all(|w| has.contains(w)) {
        return Append::AlreadySet;
    }
    let has_section = match client {
        Client::Yarn => old.lines().any(|l| l.trim_end().starts_with("npmScopes:")),
        _ => {
            old.contains("install.scopes")
                || old
                    .lines()
                    .any(|l| l.trim_start().starts_with("scopes") && l.contains('='))
        }
    };
    if has_section {
        return Append::ByHand;
    }
    let mut text = old.to_string();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push('\n');
    text.push_str(block);
    Append::Write(text)
}

/// Writes the file through a temporary file in the same directory, and keeps the mode of an old file.
fn write_file(path: &Path, text: &str) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.prego-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    let fail = |e: std::io::Error| format!("prego: cannot write {}: {e}", path.display());
    std::fs::write(&tmp, text).map_err(fail)?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        fail(e)
    })
}

fn read_file(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("prego: cannot read {}: {e}", path.display())),
    }
}

fn target_path(client: Client, user: bool, env: &dyn Env) -> Result<PathBuf, String> {
    if user {
        let home = env
            .var("HOME")
            .filter(|h| !h.is_empty())
            .ok_or("prego: --user needs HOME")?;
        return Ok(PathBuf::from(home).join(".npmrc"));
    }
    Ok(PathBuf::from(client.file_name()))
}

/// `prego setup npm`.
pub fn setup(globals: &[&str], opts: &SetupOptions, env: &dyn Env) -> Result<(), String> {
    crate::setup::check_slug("namespace", &opts.namespace)?;
    if opts.user && matches!(opts.client, Client::Yarn | Client::Bun) {
        return Err(format!(
            "prego: --user is for npm and pnpm (~/.npmrc). For {}, run the command in the project",
            opts.client.name()
        ));
    }
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    let config = Config::from_parts(globals, env, &file).map_err(|e| e.to_string())?;
    let scope = match &opts.scope {
        Some(s) => check_scope(s)?,
        None => match admin_scopes(&config, env).as_deref() {
            Some([one]) => one.clone(),
            Some([]) => {
                return Err(
                    "prego: the tenant has no npm scope yet. Register one in the console \
                            (Settings), then give it with --scope @<scope>"
                        .into(),
                )
            }
            Some(_) => {
                return Err(
                    "prego: the tenant has more than one npm scope. Give one with --scope @<scope>"
                        .into(),
                )
            }
            None => return Err(
                "prego: give the npm scope with --scope @<scope> (your identity cannot read the \
                            tenant's scopes)"
                    .into(),
            ),
        },
    };
    let host = npm_host(&file, env);
    let url = registry_url(&host, &config.tenant, &opts.namespace);
    let client = opts.client;

    if opts.print {
        match client {
            Client::Npm | Client::Pnpm => {
                println!("# .npmrc (commit it: it holds no token)");
                for l in npmrc_lines(&scope, &url) {
                    println!("{l}");
                }
            }
            Client::Yarn => print!("# .yarnrc.yml\n{}", yarn_block(&scope, &url)),
            Client::Bun => print!("# bunfig.toml\n{}", bun_block(&scope, &url)),
        }
        next_steps(client, &scope, &url);
        return Ok(());
    }

    let path = target_path(client, opts.user, env)?;
    let old = read_file(&path)?;
    let shown = path.display();
    match client {
        Client::Npm | Client::Pnpm => {
            let (text, notes) = merge_npmrc(old.as_deref().unwrap_or(""), &scope, &url, &host);
            if old.as_deref() == Some(text.as_str()) {
                println!("{shown} already sends @{scope} to {url}.");
            } else {
                write_file(&path, &text)?;
                println!("Wrote {shown}: @{scope} packages come from {url}, with the token from ${TOKEN_VAR}.");
            }
            for n in notes {
                println!("{n}");
            }
        }
        Client::Yarn | Client::Bun => {
            let block = if client == Client::Yarn {
                yarn_block(&scope, &url)
            } else {
                bun_block(&scope, &url)
            };
            match append_block(old.as_deref(), &block, client) {
                Append::Write(text) => {
                    write_file(&path, &text)?;
                    println!("Wrote {shown}: @{scope} packages come from {url}, with the token from ${TOKEN_VAR}.");
                }
                Append::AlreadySet => println!("{shown} already sends @{scope} to {url}."),
                Append::ByHand => {
                    println!(
                        "{shown} already has a scopes section, and prego does not change it. Add these \
                         lines to that section by hand:"
                    );
                    print!("{block}");
                }
            }
        }
    }
    next_steps(client, &scope, &url);
    Ok(())
}

fn next_steps(client: Client, scope: &str, url: &str) {
    let tool = client.name();
    println!("Then run: prego exec -- {tool} install   (or: eval \"$(prego npm-env)\")");
    if matches!(client, Client::Npm | Client::Pnpm) {
        // whoami and ping do not use the scope line: they need the registry URL.
        println!("Check the connection: prego exec -- {tool} whoami --registry {url}");
    }
    println!(
        "Also create the free organization @{scope} on npmjs.com, so that nobody else can publish \
         @{scope} packages there (dependency confusion)."
    );
}

/// The line for `eval "$(prego npm-env)"`. The token holds only base64url characters and dots, but the
/// value is quoted anyway.
pub fn env_line(token: &str) -> String {
    format!("export {TOKEN_VAR}='{}'", token.replace('\'', ""))
}

/// `prego npm-env`: prints `export PREGO_NPM_TOKEN='<token>'` on stdout.
pub fn npm_env(globals: &[&str], env: &dyn Env) -> Result<(), String> {
    let config = Config::from_args(globals, env).map_err(|e| e.to_string())?;
    let token = crate::token::registry_token(&config, &[], None, env)?.1;
    println!("{}", env_line(token.token.expose()));
    eprintln!(
        "prego npm-env: token valid for {}. Run it again after that.",
        crate::token::minutes(token.lifetime)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://npm.prego.k8skill.com/t/acme/default/";
    const HOST: &str = "npm.prego.k8skill.com";

    #[test]
    fn scopes() {
        assert_eq!(check_scope("@acme").unwrap(), "acme");
        assert_eq!(check_scope("acme-co.x~1").unwrap(), "acme-co.x~1");
        for bad in [
            "@",
            "",
            "@Acme",
            "@.a",
            "@_a",
            "@a/b",
            "@a b",
            &"a".repeat(51),
        ] {
            assert!(check_scope(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn npmrc_new_file() {
        let (text, notes) = merge_npmrc("", "acme", URL, HOST);
        assert_eq!(
            text,
            "@acme:registry=https://npm.prego.k8skill.com/t/acme/default/\n\
             //npm.prego.k8skill.com/t/acme/default/:_authToken=${PREGO_NPM_TOKEN}\n"
        );
        assert!(notes.is_empty());
        // A second run changes nothing.
        assert_eq!(merge_npmrc(&text, "acme", URL, HOST).0, text);
    }

    #[test]
    fn npmrc_keeps_other_lines_and_replaces_ours() {
        let old = "# team settings\n\
                   save-exact=true\n\
                   @acme:registry=https://old.example.test/\n\
                   //npm.prego.k8skill.com/t/acme/default/:_authToken=eyJhbGciOi.literal.token\n\
                   @other:registry=https://other.example.test/\n\
                   @acme:registry=https://dup.example.test/";
        let (text, notes) = merge_npmrc(old, "acme", URL, HOST);
        assert_eq!(
            text,
            "# team settings\n\
             save-exact=true\n\
             @acme:registry=https://npm.prego.k8skill.com/t/acme/default/\n\
             //npm.prego.k8skill.com/t/acme/default/:_authToken=${PREGO_NPM_TOKEN}\n\
             @other:registry=https://other.example.test/\n"
        );
        assert_eq!(notes.len(), 1);
        assert!(notes[0].starts_with("Replaced a token value"), "{notes:?}");
        assert!(!text.contains("literal"));
    }

    #[test]
    fn npmrc_warns_on_a_prego_default_registry() {
        let old = "registry=https://npm.prego.k8skill.com/t/acme/default/\n";
        let (text, notes) = merge_npmrc(old, "acme", URL, HOST);
        assert!(text.starts_with(old), "the line stays; the user removes it");
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("scoped packages only"), "{notes:?}");
        let (_, notes) = merge_npmrc("registry=https://registry.npmjs.org/\n", "acme", URL, HOST);
        assert!(notes.is_empty());
    }

    #[test]
    fn yarn_and_bun_blocks() {
        assert_eq!(
            yarn_block("acme", URL),
            "npmScopes:\n  acme:\n    npmRegistryServer: \"https://npm.prego.k8skill.com/t/acme/default/\"\n    \
             npmAuthToken: \"${PREGO_NPM_TOKEN}\"\n"
        );
        assert_eq!(
            bun_block("acme", URL),
            "[install.scopes]\n\"@acme\" = { url = \"https://npm.prego.k8skill.com/t/acme/default/\", token = \
             \"$PREGO_NPM_TOKEN\" }\n"
        );
    }

    #[test]
    fn append_rules() {
        let y = yarn_block("acme", URL);
        assert_eq!(
            append_block(None, &y, Client::Yarn),
            Append::Write(y.clone())
        );
        assert_eq!(
            append_block(Some("nodeLinker: node-modules"), &y, Client::Yarn),
            Append::Write(format!("nodeLinker: node-modules\n\n{y}"))
        );
        assert_eq!(
            append_block(Some(&format!("nodeLinker: pnp\n\n{y}")), &y, Client::Yarn),
            Append::AlreadySet
        );
        assert_eq!(
            append_block(
                Some("npmScopes:\n  other:\n    npmRegistryServer: x\n"),
                &y,
                Client::Yarn
            ),
            Append::ByHand
        );

        let b = bun_block("acme", URL);
        assert_eq!(
            append_block(Some("[install]\nexact = true\n"), &b, Client::Bun),
            Append::Write(format!("[install]\nexact = true\n\n{b}"))
        );
        assert_eq!(append_block(Some(&b), &b, Client::Bun), Append::AlreadySet);
        assert_eq!(
            append_block(
                Some("[install.scopes]\n\"@x\" = \"https://x.test/\"\n"),
                &b,
                Client::Bun
            ),
            Append::ByHand
        );
        assert_eq!(
            append_block(
                Some("[install]\nscopes = { \"@x\" = \"https://x.test/\" }\n"),
                &b,
                Client::Bun
            ),
            Append::ByHand
        );
    }

    #[test]
    fn env_lines() {
        assert_eq!(env_line("a.b-c_d"), "export PREGO_NPM_TOKEN='a.b-c_d'");
        assert_eq!(env_line("a'b"), "export PREGO_NPM_TOKEN='ab'");
    }
}
