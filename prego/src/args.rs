//! Command-line parsing. Global options can come before or after the command.

/// What the user asked for.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Help,
    Version,
    Run {
        /// Global options as `--name=value`, for `prego_auth::Config::from_parts`.
        globals: Vec<String>,
        command: Command,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Token {
        scopes: Vec<String>,
        resource: Option<String>,
    },
    /// `prego token --python [--url URL] [--namespace ns]`.
    TokenPython {
        url: Option<String>,
        namespace: String,
    },
    /// `prego setup python`.
    SetupPython(crate::python::setup::SetupOptions),
    /// `prego python publish <file>...`.
    PythonPublish {
        files: Vec<String>,
        namespace: String,
    },
    Whoami {
        namespace: String,
        resource: Option<String>,
    },
    SetupCargo {
        namespace: String,
        registry: Option<String>,
    },
    SetupDocker {
        write: bool,
    },
    /// `prego adapter push <folder> <repo>:<version>`.
    AdapterPush {
        folder: String,
        reference: String,
        license: Option<String>,
        base_revision: Option<String>,
    },
    /// `prego adapter get <repo>:<version> <folder>`.
    AdapterGet {
        reference: String,
        folder: String,
    },
    OciPush {
        /// An OCI image layout directory or a `docker save` tar file.
        input: String,
        /// `[host/]<tenant>/<namespace>/<repo>[:tag]`.
        reference: String,
        /// A repository in the same tenant to mount blobs from.
        from: Option<String>,
        /// Upload part size in MiB.
        chunk_size_mib: Option<u64>,
    },
    GoPublish {
        dir: String,
        tag: Option<String>,
        namespace: String,
        dry_run: bool,
        json: bool,
    },
    /// The GOAUTH helper. `args` is empty, or the URL that Go retries.
    GoAuth {
        args: Vec<String>,
    },
    SetupGo {
        namespace: String,
        prefixes: Vec<String>,
        write: bool,
    },
    /// `prego setup npm`.
    SetupNpm(crate::npm::SetupOptions),
    /// `prego npm-env`.
    NpmEnv,
    /// `prego exec -- <command>`.
    Exec {
        command: Vec<String>,
        /// The Python mode: `Some(namespace)` with `--python` or `--pip`, or for a Python program.
        python: Option<String>,
        /// `--pip`: also set `PIP_EXTRA_INDEX_URL`.
        pip: bool,
    },
    /// `prego login`.
    Login {
        publish: bool,
        no_browser: bool,
        /// `--namespace <ns>`, zero or more. None: namespace `default`.
        namespaces: Vec<String>,
    },
    /// `prego logout`.
    Logout,
    /// `prego status`.
    Status,
    /// `prego env ...`.
    Env(crate::env::EnvCommand),
    /// `prego snippet ...`.
    Snippet(crate::snippet::SnippetCommand),
    /// `prego keys ...`.
    Keys(Box<crate::keys::KeysCommand>),
    /// `prego a2a ...`.
    A2a(Box<crate::a2a::A2aCommand>),
    /// `prego context ...`.
    Context(Box<crate::context::ContextCommand>),
    /// `prego sqlite ...`.
    Sqlite(Box<crate::sqlite::SqliteCommand>),
    /// `prego apispec ...`.
    Apispec(Box<crate::apispec::ApispecCommand>),
}

const GLOBAL: [&str; 5] = [
    "--tenant",
    "--sts-url",
    "--edge-code",
    "--audience",
    "--source",
];
const WITH_VALUE: [&str; 45] = [
    "--scope",
    "--resource",
    "--namespace",
    "--registry",
    "--from",
    "--chunk-size",
    "--dir",
    "--tag",
    "--prefix",
    "--client",
    "--format",
    "--expect",
    "--out",
    "--file",
    "--env-file",
    "--set",
    "--set-json",
    "--message",
    "--if-current",
    "--level",
    "--to",
    "--reason",
    "--project",
    "--tool",
    "--url",
    "--license",
    "--base-revision",
    "--session",
    "--parent",
    "--trigger",
    "--label",
    "--keep-days",
    "--on-full",
    "--check",
    "--keep",
    "--older-than",
    "--keep-count",
    "--type",
    "--entry",
    "--not-after",
    "--alg",
    "--sign",
    "--key",
    "--key-file",
    "--card",
];
/// Options without a value.
const FLAGS: [&str; 16] = [
    "--write",
    "--print",
    "--dry-run",
    "--json",
    "--user",
    "--publish",
    "--no-browser",
    "--python",
    "--pip",
    "--tar",
    "--no-redact",
    "--compact",
    "--force",
    "--yes",
    "--verify",
    "--no-source",
];

/// Parses the arguments after the program name.
pub fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut globals = Vec::new();
    let mut words: Vec<&str> = Vec::new();
    let mut opts: Vec<(&str, String)> = Vec::new();
    let mut flags: Vec<&str> = Vec::new();
    let mut rest: Option<Vec<String>> = None;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        // `-o <file>` is the short form of `--out <file>` (`prego a2a upgrade`).
        let arg = if arg == "-o" { "--out" } else { arg.as_str() };
        match arg {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "--" => {
                rest = Some(it.by_ref().cloned().collect());
                break;
            }
            f if FLAGS.contains(&f) => {
                if !flags.contains(&f) {
                    flags.push(f);
                }
                continue;
            }
            _ => {}
        }
        if !arg.starts_with("--") {
            words.push(arg);
            continue;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (arg, None),
        };
        if !GLOBAL.contains(&name) && !WITH_VALUE.contains(&name) {
            return Err(format!("unknown option `{name}`"));
        }
        let value = match inline {
            Some(v) => v,
            None => it
                .next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))?,
        };
        if GLOBAL.contains(&name) {
            globals.push(format!("{name}={value}"));
        } else {
            opts.push((name, value));
        }
    }

    let take = |name: &str| -> Vec<String> {
        opts.iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .collect()
    };
    let one = |name: &str| -> Result<Option<String>, String> {
        let mut v = take(name);
        if v.len() > 1 {
            return Err(format!("{name} can be given one time only"));
        }
        Ok(v.pop())
    };
    let flag = |name: &str| flags.contains(&name);
    // Each command accepts only its own options and flags.
    let allow_flags = |allowed: &[&str]| -> Result<(), String> {
        if let Some(f) = flags.iter().find(|f| !allowed.contains(f)) {
            return Err(format!("option `{f}` does not apply to this command"));
        }
        Ok(())
    };
    let allow = |allowed: &[&str], allowed_flags: &[&str]| -> Result<(), String> {
        if let Some((n, _)) = opts.iter().find(|(n, _)| !allowed.contains(n)) {
            return Err(format!("option `{n}` does not apply to this command"));
        }
        allow_flags(allowed_flags)
    };
    let is_exec = words.as_slice() == ["exec"];
    if rest.is_some() && !is_exec {
        return Err("`--` is only for `prego exec -- <command>`".into());
    }

    let command = match words.as_slice() {
        ["login"] => {
            allow(&["--namespace"], &["--publish", "--no-browser"])?;
            Command::Login {
                publish: flag("--publish"),
                no_browser: flag("--no-browser"),
                namespaces: take("--namespace"),
            }
        }
        ["logout"] => {
            allow(&[], &[])?;
            Command::Logout
        }
        ["status"] => {
            allow(&[], &[])?;
            Command::Status
        }
        ["token"] if flag("--python") => {
            allow(&["--url", "--namespace"], &["--python"])?;
            Command::TokenPython {
                url: one("--url")?,
                namespace: one("--namespace")?.unwrap_or_else(|| "default".into()),
            }
        }
        ["token"] => {
            allow(&["--scope", "--resource"], &[])?;
            let scopes = take("--scope");
            let resource = one("--resource")?;
            if !scopes.is_empty() && resource.is_some() {
                return Err("prego: use --scope or --resource, not both".into());
            }
            Command::Token { scopes, resource }
        }
        ["whoami"] => {
            allow(&["--namespace", "--resource"], &[])?;
            Command::Whoami {
                namespace: one("--namespace")?.unwrap_or_else(|| "default".into()),
                resource: one("--resource")?,
            }
        }
        ["setup", "cargo"] => {
            allow(&["--namespace", "--registry"], &[])?;
            Command::SetupCargo {
                namespace: one("--namespace")?.unwrap_or_else(|| "default".into()),
                registry: one("--registry")?,
            }
        }
        ["setup", "docker"] => {
            allow(&[], &["--write"])?;
            Command::SetupDocker {
                write: flag("--write"),
            }
        }
        ["oci", "push", input, reference] => {
            allow(&["--from", "--chunk-size"], &[])?;
            let chunk_size_mib = match one("--chunk-size")? {
                None => None,
                Some(v) => Some(
                    v.parse::<u64>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(|| format!("--chunk-size `{v}` is not a number of MiB"))?,
                ),
            };
            Command::OciPush {
                input: input.to_string(),
                reference: reference.to_string(),
                from: one("--from")?,
                chunk_size_mib,
            }
        }
        ["adapter", "push", folder, reference] => {
            allow(&["--license", "--base-revision"], &[])?;
            Command::AdapterPush {
                folder: folder.to_string(),
                reference: reference.to_string(),
                license: one("--license")?,
                base_revision: one("--base-revision")?,
            }
        }
        ["adapter", "get", reference, folder] => {
            allow(&[], &[])?;
            Command::AdapterGet {
                reference: reference.to_string(),
                folder: folder.to_string(),
            }
        }
        ["adapter", "push", ..] => {
            return Err(
                "usage: prego adapter push <folder> <repo>:<version> [--license <id>] [--base-revision <rev>]"
                    .into(),
            )
        }
        ["adapter", "get", ..] => {
            return Err("usage: prego adapter get <repo>:<version> <folder>".into())
        }
        ["oci", "push", ..] => {
            return Err(
                "usage: prego oci push <oci-layout dir | docker save tar> <image ref>".into(),
            )
        }
        ["go", "publish", pos @ ..] if pos.len() <= 2 => {
            allow(&["--namespace", "--dir", "--tag"], &["--dry-run", "--json"])?;
            let pick = |name: &str, at: usize| -> Result<Option<String>, String> {
                match (one(name)?, pos.get(at)) {
                    (Some(_), Some(_)) => Err(format!("give {name} or the word, not both")),
                    (Some(v), None) => Ok(Some(v)),
                    (None, p) => Ok(p.map(|s| s.to_string())),
                }
            };
            Command::GoPublish {
                dir: pick("--dir", 0)?.unwrap_or_else(|| ".".into()),
                tag: pick("--tag", 1)?,
                namespace: one("--namespace")?.unwrap_or_else(|| "default".into()),
                dry_run: flag("--dry-run"),
                json: flag("--json"),
            }
        }
        ["go", "publish", ..] => {
            return Err(
                "usage: prego go publish [--namespace <ns>] [--dry-run] [--json] [<module dir>] [<tag>]"
                    .into(),
            )
        }
        ["go-auth", pos @ ..] if pos.len() <= 1 => {
            allow(&[], &[])?;
            Command::GoAuth {
                args: pos.iter().map(|s| s.to_string()).collect(),
            }
        }
        ["setup", "go"] => {
            allow(&["--namespace", "--prefix"], &["--write", "--print"])?;
            if flag("--write") && flag("--print") {
                return Err("give --write or --print, not both".into());
            }
            Command::SetupGo {
                namespace: one("--namespace")?.unwrap_or_else(|| "default".into()),
                prefixes: take("--prefix"),
                write: flag("--write"),
            }
        }
        ["setup", "npm"] => {
            allow(&["--namespace", "--scope", "--client"], &["--user", "--print"])?;
            if flag("--user") && flag("--print") {
                return Err("give --user or --print, not both".into());
            }
            let client = match one("--client")? {
                Some(c) => crate::npm::Client::parse(&c)?,
                None => crate::npm::Client::Npm,
            };
            Command::SetupNpm(crate::npm::SetupOptions {
                namespace: one("--namespace")?.unwrap_or_else(|| "default".into()),
                scope: one("--scope")?,
                client,
                user: flag("--user"),
                print: flag("--print"),
            })
        }
        ["setup", "python"] => {
            allow(&["--namespace", "--project", "--tool"], &["--print"])?;
            let tool = match one("--tool")? {
                Some(t) => crate::python::setup::Tool::parse(&t)?,
                None => crate::python::setup::Tool::Uv,
            };
            Command::SetupPython(crate::python::setup::SetupOptions {
                namespace: one("--namespace")?.unwrap_or_else(|| "default".into()),
                projects: take("--project"),
                tool,
                print: flag("--print"),
            })
        }
        ["python", "publish", files @ ..] if !files.is_empty() => {
            allow(&["--namespace"], &[])?;
            Command::PythonPublish {
                files: files.iter().map(|s| s.to_string()).collect(),
                namespace: one("--namespace")?.unwrap_or_else(|| "default".into()),
            }
        }
        ["python", "publish"] => {
            return Err("usage: prego python publish [--namespace <ns>] <file>...".into())
        }
        ["npm-env"] => {
            allow(&[], &[])?;
            Command::NpmEnv
        }
        ["exec"] => {
            allow(&["--namespace"], &["--python", "--pip"])?;
            let command = match rest {
                Some(c) if !c.is_empty() => c,
                _ => return Err("usage: prego exec [--python] [--pip] [--namespace <ns>] -- <command> [args]".into()),
            };
            let pip = flag("--pip");
            let namespace = one("--namespace")?;
            let python_mode =
                pip || flag("--python") || crate::python::is_python_program(&command[0]);
            if namespace.is_some() && !python_mode {
                return Err("--namespace applies to prego exec in the Python mode only (--python)".into());
            }
            Command::Exec {
                python: python_mode.then(|| namespace.unwrap_or_else(|| "default".into())),
                pip,
                command,
            }
        }
        ["env", rest @ ..] => Command::Env(parse_env(rest, &opts, &allow)?),
        ["snippet", rest @ ..] => Command::Snippet(parse_snippet(rest, &opts, &flag, &allow)?),
        ["keys", rest @ ..] => Command::Keys(Box::new(parse_keys(rest, &opts, &allow)?)),
        ["a2a", rest @ ..] => {
            Command::A2a(Box::new(parse_a2a(rest, &opts, &flag, &allow)?))
        }
        ["context", rest @ ..] => Command::Context(Box::new(parse_context(rest, &opts, &flag, &allow)?)),
        ["sqlite", rest @ ..] => Command::Sqlite(Box::new(parse_sqlite(rest, &opts, &flag, &allow)?)),
        ["apispec", "push", file, r] => {
            allow(&["--message", "--tag"], &[])?;
            let o = Opt { opts: &opts };
            Command::Apispec(Box::new(crate::apispec::ApispecCommand::Push {
                file: file.to_string(),
                reference: r.to_string(),
                message: o.text("--message", 200)?,
                tag: o.tag()?,
            }))
        }
        ["apispec", "get", r] => {
            allow(&["--format", "--expect", "--out"], &[])?;
            let o = Opt { opts: &opts };
            let format = one("--format")?;
            if format
                .as_deref()
                .is_some_and(|f| f != "json" && f != "yaml" && f != "graphql")
            {
                return Err("--format is json, yaml (OpenAPI) or graphql".into());
            }
            Command::Apispec(Box::new(crate::apispec::ApispecCommand::Get {
                reference: r.to_string(),
                format,
                expect: o.hash("--expect")?,
                out: one("--out")?,
            }))
        }
        ["apispec", "diff", a, b] => {
            allow(&[], &["--json"])?;
            Command::Apispec(Box::new(crate::apispec::ApispecCommand::Diff {
                from: a.to_string(),
                to: b.to_string(),
                json: flag("--json"),
            }))
        }
        ["apispec", ..] => {
            return Err("usage: prego apispec push <file> <ref>@<version> | get <ref>[@<version>] | diff <ref>@<a> <ref>@<b>".into())
        }
        [] => return Ok(Parsed::Help),
        other => return Err(format!("unknown command `{}`", other.join(" "))),
    };
    Ok(Parsed::Run { globals, command })
}

/// Checks that a command gets only its own options and flags.
type Allow<'a> = dyn Fn(&[&str], &[&str]) -> Result<(), String> + 'a;

/// `prego env <subcommand>`.
fn parse_env(
    words: &[&str],
    opts: &[(&str, String)],
    allow: &Allow<'_>,
) -> Result<crate::env::EnvCommand, String> {
    use crate::env::reference::Level;
    use crate::env::{jcs, EnvCommand, Format};
    let take = |name: &str| -> Vec<String> {
        opts.iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .collect()
    };
    let one = |name: &str| -> Result<Option<String>, String> {
        let mut v = take(name);
        if v.len() > 1 {
            return Err(format!("{name} can be given one time only"));
        }
        Ok(v.pop())
    };
    let number = |name: &str| -> Result<u64, String> {
        let v = one(name)?.ok_or_else(|| format!("{name} <version number> is required"))?;
        v.parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| format!("{name} `{v}` is not a version number"))
    };
    let hash = |name: &str| -> Result<Option<String>, String> {
        match one(name)? {
            Some(h) if !jcs::is_hash(&h) => Err(format!(
                "{name} `{h}` is not a hash: use sha256:<64 lowercase hex>"
            )),
            h => Ok(h),
        }
    };
    let level = || -> Result<Level, String> {
        match one("--level")? {
            Some(l) => Level::parse(&l),
            None => Ok(Level::Version),
        }
    };
    let usage = "usage: prego env pull|push|history|rollback|diff <ref> [options], or prego env hash <file>";
    Ok(match words {
        ["pull", r] => {
            allow(&["--format", "--expect", "--out"], &[])?;
            EnvCommand::Pull {
                reference: r.to_string(),
                format: one("--format")?.map(|f| Format::parse(&f)).transpose()?,
                expect: hash("--expect")?,
                out: one("--out")?,
            }
        }
        ["push", r] => {
            allow(
                &[
                    "--file",
                    "--env-file",
                    "--set",
                    "--set-json",
                    "--message",
                    "--if-current",
                    "--level",
                ],
                &[],
            )?;
            let (file, env_file) = (one("--file")?, one("--env-file")?);
            if file.is_some() && env_file.is_some() {
                return Err("give --file or --env-file, not both".into());
            }
            let (sets, set_jsons) = (take("--set"), take("--set-json"));
            if file.is_none() && env_file.is_none() && sets.is_empty() && set_jsons.is_empty() {
                return Err(
                    "give the variables: --file vars.json, --env-file .env, --set KEY=VALUE or \
                     --set-json KEY=<JSON>"
                        .into(),
                );
            }
            let message = one("--message")?;
            if message.as_ref().is_some_and(|m| m.chars().count() > 200) {
                return Err("--message is at most 200 characters".into());
            }
            EnvCommand::Push {
                reference: r.to_string(),
                level: level()?,
                file,
                env_file,
                sets,
                set_jsons,
                message,
                if_current: hash("--if-current")?,
            }
        }
        ["history", r] => {
            allow(&["--level"], &[])?;
            EnvCommand::History {
                reference: r.to_string(),
                level: level()?,
            }
        }
        ["rollback", r] => {
            allow(&["--level", "--to", "--reason"], &[])?;
            let reason = one("--reason")?
                .filter(|s| !s.trim().is_empty())
                .ok_or("--reason <text> is required")?;
            if reason.chars().count() > 200 {
                return Err("--reason is at most 200 characters".into());
            }
            EnvCommand::Rollback {
                reference: r.to_string(),
                level: level()?,
                to: number("--to")?,
                reason,
            }
        }
        ["diff", r] => {
            allow(&["--level", "--from", "--to"], &[])?;
            EnvCommand::Diff {
                reference: r.to_string(),
                level: level()?,
                from: number("--from")?,
                to: number("--to")?,
            }
        }
        ["hash", f] => {
            allow(&[], &[])?;
            EnvCommand::Hash {
                file: f.to_string(),
            }
        }
        _ => return Err(usage.into()),
    })
}

/// `prego snippet <subcommand>`.
fn parse_snippet(
    words: &[&str],
    opts: &[(&str, String)],
    flag: &dyn Fn(&str) -> bool,
    allow: &Allow<'_>,
) -> Result<crate::snippet::SnippetCommand, String> {
    use crate::env::jcs;
    use crate::snippet::SnippetCommand;
    let take = |name: &str| -> Vec<String> {
        opts.iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .collect()
    };
    let one = |name: &str| -> Result<Option<String>, String> {
        let mut v = take(name);
        if v.len() > 1 {
            return Err(format!("{name} can be given one time only"));
        }
        Ok(v.pop())
    };
    let hash = |name: &str| -> Result<Option<String>, String> {
        match one(name)? {
            Some(h) if !jcs::is_hash(&h) => Err(format!(
                "{name} `{h}` is not a hash: use sha256:<64 lowercase hex>"
            )),
            h => Ok(h),
        }
    };
    let text = |name: &str, max: usize| -> Result<Option<String>, String> {
        match one(name)? {
            Some(m) if m.chars().count() > max => {
                Err(format!("{name} is at most {max} characters"))
            }
            m => Ok(m),
        }
    };
    let usage =
        "usage: prego snippet push|get|ls|log|diff|tag|rollback|hash ... (see prego --help)";
    Ok(match words {
        ["push", source, r] => {
            allow(&["--tag", "--message", "--if-current"], &["--tar"])?;
            let tag = one("--tag")?;
            if let Some(t) = &tag {
                crate::snippet::reference::check_tag(t)?;
            }
            SnippetCommand::Push {
                source: source.to_string(),
                reference: r.to_string(),
                tag,
                message: text("--message", 200)?,
                if_current: hash("--if-current")?,
                tar: flag("--tar"),
            }
        }
        ["get", r] | ["get", r, _] => {
            allow(&["--file", "--expect"], &["--tar"])?;
            let file = one("--file")?;
            let tar = flag("--tar");
            let folder = words.get(2).map(|s| s.to_string());
            if file.is_some() && (tar || folder.is_some()) {
                return Err("--file prints one file on stdout: give no folder and no --tar".into());
            }
            SnippetCommand::Get {
                reference: r.to_string(),
                folder,
                file,
                tar,
                expect: hash("--expect")?,
            }
        }
        ["ls", scope] => {
            allow(&[], &[])?;
            SnippetCommand::Ls {
                scope: scope.to_string(),
            }
        }
        ["log", r] => {
            allow(&[], &[])?;
            SnippetCommand::Log {
                reference: r.to_string(),
            }
        }
        ["diff", r, from, to] => {
            allow(&[], &[])?;
            SnippetCommand::Diff {
                reference: r.to_string(),
                from: from.to_string(),
                to: to.to_string(),
            }
        }
        ["tag", r, tag] => {
            allow(&[], &[])?;
            SnippetCommand::Tag {
                reference: r.to_string(),
                tag: tag.to_string(),
            }
        }
        ["rollback", r] => {
            allow(&["--to", "--reason"], &[])?;
            let to = one("--to")?.ok_or("--to <version> is required")?;
            let reason = text("--reason", 200)?
                .filter(|s| !s.trim().is_empty())
                .ok_or("--reason <text> is required")?;
            SnippetCommand::Rollback {
                reference: r.to_string(),
                to,
                reason,
            }
        }
        ["hash", source] => {
            allow(&[], &["--tar"])?;
            SnippetCommand::Hash {
                source: source.to_string(),
                tar: flag("--tar"),
            }
        }
        _ => return Err(usage.into()),
    })
}

/// Options for `prego keys` and `prego a2a`: one value, a hash, a short text.
struct Opt<'a> {
    opts: &'a [(&'a str, String)],
}

impl Opt<'_> {
    fn take(&self, name: &str) -> Vec<String> {
        self.opts
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .collect()
    }
    fn one(&self, name: &str) -> Result<Option<String>, String> {
        let mut v = self.take(name);
        if v.len() > 1 {
            return Err(format!("{name} can be given one time only"));
        }
        Ok(v.pop())
    }
    fn hash(&self, name: &str) -> Result<Option<String>, String> {
        match self.one(name)? {
            Some(h) if !crate::env::jcs::is_hash(&h) => Err(format!(
                "{name} `{h}` is not a hash: use sha256:<64 lowercase hex>"
            )),
            h => Ok(h),
        }
    }
    fn text(&self, name: &str, max: usize) -> Result<Option<String>, String> {
        match self.one(name)? {
            Some(m) if m.chars().count() > max => {
                Err(format!("{name} is at most {max} characters"))
            }
            m => Ok(m),
        }
    }
    fn tag(&self) -> Result<Option<String>, String> {
        let tag = self.one("--tag")?;
        if let Some(t) = &tag {
            crate::snippet::reference::check_tag(t)?;
        }
        Ok(tag)
    }
    fn reason(&self) -> Result<String, String> {
        self.text("--reason", 200)?
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| "--reason <text> is required".to_string())
    }
}

/// `prego keys <subcommand>` (ADR-0061 section 6).
fn parse_keys(
    words: &[&str],
    opts: &[(&str, String)],
    allow: &Allow<'_>,
) -> Result<crate::keys::KeysCommand, String> {
    use crate::keys::KeysCommand;
    let o = Opt { opts };
    let usage = "usage: prego keys push|get|ls|log|tag|rollback|revoke|fingerprint|new ... (see prego --help)";
    Ok(match words {
        ["push", files @ .., r] if !files.is_empty() => {
            allow(
                &[
                    "--type",
                    "--tag",
                    "--message",
                    "--if-current",
                    "--not-after",
                ],
                &[],
            )?;
            KeysCommand::Push {
                files: files.iter().map(|s| s.to_string()).collect(),
                reference: r.to_string(),
                kind: o.one("--type")?,
                tag: o.tag()?,
                message: o.text("--message", 200)?,
                if_current: o.hash("--if-current")?,
                not_after: o.one("--not-after")?,
            }
        }
        ["get", r] => {
            allow(&["--entry", "--expect"], &[])?;
            KeysCommand::Get {
                reference: r.to_string(),
                entry: o.one("--entry")?,
                expect: o.hash("--expect")?,
            }
        }
        ["ls", scope] => {
            allow(&[], &[])?;
            KeysCommand::Ls {
                scope: scope.to_string(),
            }
        }
        ["log", r] => {
            allow(&[], &[])?;
            KeysCommand::Log {
                reference: r.to_string(),
            }
        }
        ["tag", r, tag] => {
            allow(&[], &[])?;
            KeysCommand::Tag {
                reference: r.to_string(),
                tag: tag.to_string(),
            }
        }
        ["rollback", r] => {
            allow(&["--to", "--reason"], &[])?;
            KeysCommand::Rollback {
                reference: r.to_string(),
                to: o.one("--to")?.ok_or("--to <version> is required")?,
                reason: o.reason()?,
            }
        }
        ["revoke", r] => {
            allow(&["--reason"], &[])?;
            KeysCommand::Revoke {
                reference: r.to_string(),
                reason: o.reason()?,
            }
        }
        ["fingerprint", file] => {
            allow(&["--type"], &[])?;
            KeysCommand::Fingerprint {
                file: file.to_string(),
                kind: o.one("--type")?,
            }
        }
        ["new", r] => {
            allow(&["--alg", "--out", "--message"], &[])?;
            KeysCommand::New {
                alg: o.one("--alg")?.ok_or("--alg ed25519|es256 is required")?,
                reference: r.to_string(),
                out: o.one("--out")?,
                message: o.text("--message", 200)?,
            }
        }
        _ => return Err(usage.into()),
    })
}

/// `prego a2a <subcommand>` (ADR-0062 section 5).
fn parse_a2a(
    words: &[&str],
    opts: &[(&str, String)],
    flag: &dyn Fn(&str) -> bool,
    allow: &Allow<'_>,
) -> Result<crate::a2a::A2aCommand, String> {
    use crate::a2a::A2aCommand;
    let o = Opt { opts };
    let usage =
        "usage: prego a2a check|push|get|ls|log|diff|tag|rollback|upgrade ... (see prego --help)";
    Ok(match words {
        ["check", source] => {
            allow(&["--key-file", "--key"], &[])?;
            A2aCommand::Check {
                source: source.to_string(),
                key_file: o.one("--key-file")?,
                key: o.one("--key")?,
            }
        }
        ["push", source, r] => {
            allow(
                &["--sign", "--key", "--tag", "--message", "--if-current"],
                &["--no-source"],
            )?;
            A2aCommand::Push {
                source: source.to_string(),
                reference: r.to_string(),
                sign: o.one("--sign")?,
                key: o.one("--key")?,
                no_source: flag("--no-source"),
                tag: o.tag()?,
                message: o.text("--message", 200)?,
                if_current: o.hash("--if-current")?,
            }
        }
        ["get", r] | ["get", r, _] => {
            allow(&["--card", "--expect"], &["--verify"])?;
            let card = o.one("--card")?;
            let folder = words.get(2).map(|s| s.to_string());
            if card.is_some() && folder.is_some() {
                return Err("--card prints one card on stdout: give no folder".into());
            }
            A2aCommand::Get {
                reference: r.to_string(),
                folder,
                card,
                expect: o.hash("--expect")?,
                verify: flag("--verify"),
            }
        }
        ["ls", scope] => {
            allow(&[], &[])?;
            A2aCommand::Ls {
                scope: scope.to_string(),
            }
        }
        ["log", r] => {
            allow(&[], &[])?;
            A2aCommand::Log {
                reference: r.to_string(),
            }
        }
        ["diff", r, from, to] => {
            allow(&[], &[])?;
            A2aCommand::Diff {
                reference: r.to_string(),
                from: from.to_string(),
                to: to.to_string(),
            }
        }
        ["tag", r, tag] => {
            allow(&[], &[])?;
            A2aCommand::Tag {
                reference: r.to_string(),
                tag: tag.to_string(),
            }
        }
        ["rollback", r] => {
            allow(&["--to", "--reason"], &[])?;
            A2aCommand::Rollback {
                reference: r.to_string(),
                to: o.one("--to")?.ok_or("--to <version> is required")?,
                reason: o.reason()?,
            }
        }
        ["upgrade", file] => {
            allow(&["--out"], &["--force"])?;
            A2aCommand::Upgrade {
                file: file.to_string(),
                out: o.one("--out")?,
                force: flag("--force"),
            }
        }
        _ => return Err(usage.into()),
    })
}

fn parse_context(
    words: &[&str],
    opts: &[(&str, String)],
    flag: &dyn Fn(&str) -> bool,
    allow: &Allow<'_>,
) -> Result<crate::context::ContextCommand, String> {
    use crate::context::{self, reference, ContextCommand};
    use crate::env::jcs;
    let take = |name: &str| -> Vec<String> {
        opts.iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .collect()
    };
    let one = |name: &str| -> Result<Option<String>, String> {
        let mut v = take(name);
        if v.len() > 1 {
            return Err(format!("{name} can be given one time only"));
        }
        Ok(v.pop())
    };
    let hash = |name: &str| -> Result<Option<String>, String> {
        match one(name)? {
            Some(h) if !jcs::is_hash(&h) => Err(format!(
                "{name} `{h}` is not a hash: use sha256:<64 lowercase hex>"
            )),
            h => Ok(h),
        }
    };
    let session = || -> Result<Option<String>, String> {
        let s = one("--session")?;
        if let Some(s) = &s {
            reference::check_session(s)?;
        }
        Ok(s)
    };
    let usage = "usage: prego context save|restore|ls|log|tag|rm|set|hash ... (see prego --help)";
    Ok(match words {
        ["save", folder, r] => {
            allow(
                &[
                    "--session",
                    "--parent",
                    "--trigger",
                    "--label",
                    "--message",
                    "--tag",
                ],
                &["--no-redact"],
            )?;
            let tag = one("--tag")?;
            if let Some(t) = &tag {
                reference::check_tag(t)?;
            }
            let trigger = one("--trigger")?;
            if let Some(t) = &trigger {
                context::check_trigger(t)?;
            }
            let message = one("--message")?;
            if message.as_ref().is_some_and(|m| m.chars().count() > 200) {
                return Err("--message is at most 200 characters".into());
            }
            let mut labels = Vec::new();
            for l in take("--label") {
                let (k, v) = l
                    .split_once('=')
                    .ok_or_else(|| format!("bad --label `{l}`: use key=value"))?;
                labels.push((k.to_string(), v.to_string()));
            }
            context::check_labels(&labels)?;
            ContextCommand::Save {
                folder: folder.to_string(),
                reference: r.to_string(),
                session: session()?,
                parent: hash("--parent")?,
                trigger,
                labels,
                message,
                tag,
                redact: !flag("--no-redact"),
            }
        }
        ["restore", r, folder] => {
            allow(&["--session", "--expect"], &[])?;
            ContextCommand::Restore {
                reference: r.to_string(),
                folder: folder.to_string(),
                session: session()?,
                expect: hash("--expect")?,
            }
        }
        ["ls", scope] => {
            allow(&[], &[])?;
            ContextCommand::Ls {
                scope: scope.to_string(),
            }
        }
        ["log", r] => {
            allow(&["--session"], &[])?;
            ContextCommand::Log {
                reference: r.to_string(),
                session: session()?,
            }
        }
        ["tag", r, tag] => {
            allow(&[], &[])?;
            ContextCommand::Tag {
                reference: r.to_string(),
                tag: tag.to_string(),
            }
        }
        ["rm", r] => {
            allow(&["--session"], &[])?;
            ContextCommand::Rm {
                reference: r.to_string(),
                session: session()?,
            }
        }
        ["set", r] => {
            allow(&["--keep-days", "--on-full"], &[])?;
            let keep_days = match one("--keep-days")? {
                Some(d) => Some(
                    d.parse::<u32>()
                        .ok()
                        .filter(|n| (1..=400).contains(n))
                        .ok_or_else(|| {
                            format!("bad --keep-days `{d}`: a number of days from 1 to 400")
                        })?,
                ),
                None => None,
            };
            let on_full = one("--on-full")?;
            if let Some(o) = &on_full {
                context::check_on_full(o)?;
            }
            if keep_days.is_none() && on_full.is_none() {
                return Err("give --keep-days <n>, --on-full refuse|drop_oldest, or both".into());
            }
            ContextCommand::Set {
                reference: r.to_string(),
                keep_days,
                on_full,
            }
        }
        ["hash", folder] => {
            allow(&[], &["--no-redact"])?;
            ContextCommand::Hash {
                folder: folder.to_string(),
                redact: !flag("--no-redact"),
            }
        }
        _ => return Err(usage.into()),
    })
}

fn parse_sqlite(
    words: &[&str],
    opts: &[(&str, String)],
    flag: &dyn Fn(&str) -> bool,
    allow: &Allow<'_>,
) -> Result<crate::sqlite::SqliteCommand, String> {
    use crate::env::jcs;
    use crate::sqlite::{self, db::Check, reference, SqliteCommand};
    let take = |name: &str| -> Vec<String> {
        opts.iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .collect()
    };
    let one = |name: &str| -> Result<Option<String>, String> {
        let mut v = take(name);
        if v.len() > 1 {
            return Err(format!("{name} can be given one time only"));
        }
        Ok(v.pop())
    };
    let number = |name: &str, lo: u32, hi: u32| -> Result<Option<u32>, String> {
        match one(name)? {
            Some(v) => Ok(Some(
                v.parse::<u32>()
                    .ok()
                    .filter(|n| (lo..=hi).contains(n))
                    .ok_or_else(|| format!("bad {name} `{v}`: a number from {lo} to {hi}"))?,
            )),
            None => Ok(None),
        }
    };
    let usage =
        "usage: prego sqlite save|restore|ls|log|tag|rm|prune|set|hash ... (see prego --help)";
    Ok(match words {
        ["save", file, r] => {
            allow(
                &["--check", "--label", "--message", "--tag"],
                &["--compact"],
            )?;
            let tag = one("--tag")?;
            if let Some(t) = &tag {
                reference::check_tag(t)?;
            }
            let message = one("--message")?;
            if message.as_ref().is_some_and(|m| m.chars().count() > 200) {
                return Err("--message is at most 200 characters".into());
            }
            let mut labels = Vec::new();
            for l in take("--label") {
                let (k, v) = l
                    .split_once('=')
                    .ok_or_else(|| format!("bad --label `{l}`: use key=value"))?;
                labels.push((k.to_string(), v.to_string()));
            }
            sqlite::check_user_labels(&labels)?;
            SqliteCommand::Save {
                file: file.to_string(),
                reference: r.to_string(),
                compact: flag("--compact"),
                check: match one("--check")? {
                    Some(c) => Check::parse(&c)?,
                    None => Check::Quick,
                },
                labels,
                message,
                tag,
            }
        }
        ["restore", r, file] => {
            allow(&["--expect"], &["--force"])?;
            let expect = one("--expect")?;
            if let Some(h) = &expect {
                if !jcs::is_hash(h) {
                    return Err(format!(
                        "--expect `{h}` is not a hash: use sha256:<64 lowercase hex>"
                    ));
                }
            }
            SqliteCommand::Restore {
                reference: r.to_string(),
                file: file.to_string(),
                expect,
                force: flag("--force"),
            }
        }
        ["ls", scope] => {
            allow(&[], &[])?;
            SqliteCommand::Ls {
                scope: scope.to_string(),
            }
        }
        ["log", r] => {
            allow(&[], &[])?;
            SqliteCommand::Log {
                reference: r.to_string(),
            }
        }
        ["tag", r, tag] => {
            allow(&[], &[])?;
            SqliteCommand::Tag {
                reference: r.to_string(),
                tag: tag.to_string(),
            }
        }
        ["rm", r] => {
            allow(&[], &["--yes"])?;
            SqliteCommand::Rm {
                reference: r.to_string(),
                yes: flag("--yes"),
            }
        }
        ["prune", r] => {
            allow(&["--keep", "--older-than"], &["--yes"])?;
            let keep = number("--keep", 0, 100_000)?;
            let older_than = match one("--older-than")? {
                Some(a) => Some(sqlite::parse_age(&a)?),
                None => None,
            };
            if keep.is_none() && older_than.is_none() {
                return Err("give --keep <n>, --older-than <age>, or both".into());
            }
            SqliteCommand::Prune {
                reference: r.to_string(),
                keep,
                older_than,
                yes: flag("--yes"),
            }
        }
        ["set", r] => {
            allow(&["--keep-count", "--keep-days"], &[])?;
            let keep_count = number("--keep-count", 1, 1000)?;
            let keep_days = number("--keep-days", 1, 400)?;
            if keep_count.is_none() && keep_days.is_none() {
                return Err("give --keep-count <n>, --keep-days <n>, or both".into());
            }
            SqliteCommand::Set {
                reference: r.to_string(),
                keep_count,
                keep_days,
            }
        }
        ["hash", file] => {
            allow(&[], &["--compact"])?;
            SqliteCommand::Hash {
                file: file.to_string(),
                compact: flag("--compact"),
            }
        }
        _ => return Err(usage.into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Parsed, String> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn globals_anywhere() {
        assert_eq!(
            p(&["--tenant", "acme", "token", "--source=api-key"]).unwrap(),
            Parsed::Run {
                globals: vec!["--tenant=acme".into(), "--source=api-key".into()],
                command: Command::Token {
                    scopes: vec![],
                    resource: None
                },
            }
        );
    }

    #[test]
    fn login_takes_namespaces() {
        let login = |args: &[&str]| match p(args).unwrap() {
            Parsed::Run { command, .. } => command,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            login(&["login"]),
            Command::Login {
                publish: false,
                no_browser: false,
                namespaces: vec![],
            }
        );
        assert_eq!(
            login(&[
                "login",
                "--publish",
                "--namespace",
                "rel",
                "--namespace=team-a"
            ]),
            Command::Login {
                publish: true,
                no_browser: false,
                namespaces: vec!["rel".into(), "team-a".into()],
            }
        );
        assert!(p(&["login", "--registry", "x"]).is_err());
    }

    #[test]
    fn commands_and_their_options() {
        assert_eq!(
            p(&["token", "--scope", "a", "--scope=b"]).unwrap(),
            Parsed::Run {
                globals: vec![],
                command: Command::Token {
                    scopes: vec!["a".into(), "b".into()],
                    resource: None
                },
            }
        );
        assert_eq!(
            p(&["setup", "cargo", "--namespace", "rel"]).unwrap(),
            Parsed::Run {
                globals: vec![],
                command: Command::SetupCargo {
                    namespace: "rel".into(),
                    registry: None
                },
            }
        );
        assert_eq!(
            p(&["setup", "docker", "--write"]).unwrap(),
            Parsed::Run {
                globals: vec![],
                command: Command::SetupDocker { write: true },
            }
        );
        assert_eq!(
            p(&[
                "oci",
                "push",
                "img.tar",
                "acme/d/app:1",
                "--chunk-size",
                "32",
                "--from=acme/d/base"
            ])
            .unwrap(),
            Parsed::Run {
                globals: vec![],
                command: Command::OciPush {
                    input: "img.tar".into(),
                    reference: "acme/d/app:1".into(),
                    from: Some("acme/d/base".into()),
                    chunk_size_mib: Some(32),
                },
            }
        );
        assert_eq!(p(&[]).unwrap(), Parsed::Help);
        assert_eq!(p(&["whoami", "-V"]).unwrap(), Parsed::Version);
    }

    #[test]
    fn errors() {
        assert!(p(&["token", "--write"]).is_err());
        assert!(p(&["setup", "cargo", "--write"]).is_err());
        assert!(p(&["whoami", "--scope", "x"]).is_err());
        assert!(p(&["setup", "pip"]).is_err());
        assert!(p(&["oci", "push", "img.tar"]).is_err());
        assert!(p(&["oci", "push", "a", "b", "--chunk-size", "0"]).is_err());
        assert!(p(&["oci", "push", "a", "b", "--chunk-size", "x"]).is_err());
        assert!(p(&["token", "--from", "x"]).is_err());
        assert!(p(&["token", "--bogus"]).is_err());
        assert!(p(&["token", "--scope"]).is_err());
        assert!(p(&[
            "token",
            "--scope",
            "a",
            "--resource",
            "https://x.test/t/a/b"
        ])
        .is_err());
        assert_eq!(
            p(&[
                "token",
                "--resource",
                "https://go.prego.k8skill.com/t/acme/default"
            ])
            .unwrap(),
            Parsed::Run {
                globals: vec![],
                command: Command::Token {
                    scopes: vec![],
                    resource: Some("https://go.prego.k8skill.com/t/acme/default".into())
                },
            }
        );
        assert_eq!(
            p(&[
                "whoami",
                "--resource=https://cargo.prego.k8skill.com/t/acme/rel/"
            ])
            .unwrap(),
            Parsed::Run {
                globals: vec![],
                command: Command::Whoami {
                    namespace: "default".into(),
                    resource: Some("https://cargo.prego.k8skill.com/t/acme/rel/".into())
                },
            }
        );
        assert!(p(&["whoami", "--namespace", "a", "--namespace", "b"]).is_err());
    }

    #[test]
    fn npm_commands() {
        use crate::npm::{Client, SetupOptions};
        let run = |args: &[&str]| match p(args).unwrap() {
            Parsed::Run { command, .. } => command,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            run(&["setup", "npm"]),
            Command::SetupNpm(SetupOptions {
                namespace: "default".into(),
                scope: None,
                client: Client::Npm,
                user: false,
                print: false,
            })
        );
        assert_eq!(
            run(&[
                "setup",
                "npm",
                "--scope",
                "@acme",
                "--client=pnpm",
                "--namespace",
                "rel",
                "--user"
            ]),
            Command::SetupNpm(SetupOptions {
                namespace: "rel".into(),
                scope: Some("@acme".into()),
                client: Client::Pnpm,
                user: true,
                print: false,
            })
        );
        assert_eq!(run(&["npm-env"]), Command::NpmEnv);
        for bad in [
            &["setup", "npm", "--client", "deno"][..],
            &["setup", "npm", "--user", "--print"],
            &["setup", "npm", "--write"],
            &["setup", "npm", "--scope", "a", "--scope", "b"],
            &["npm-env", "--scope", "x"],
            &["npm-env", "x"],
            &["token", "--user"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn python_commands() {
        use crate::python::setup::{SetupOptions, Tool};
        let run = |args: &[&str]| match p(args).unwrap() {
            Parsed::Run { command, .. } => command,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            run(&["token", "--python", "--url", "https://x/t/a/b/simple/"]),
            Command::TokenPython {
                url: Some("https://x/t/a/b/simple/".into()),
                namespace: "default".into()
            }
        );
        assert_eq!(
            run(&[
                "setup",
                "python",
                "--project",
                "a",
                "--project",
                "b",
                "--tool",
                "poetry",
                "--print"
            ]),
            Command::SetupPython(SetupOptions {
                namespace: "default".into(),
                projects: vec!["a".into(), "b".into()],
                tool: Tool::Poetry,
                print: true,
            })
        );
        assert_eq!(
            run(&[
                "python",
                "publish",
                "--namespace",
                "rel",
                "a.whl",
                "b.tar.gz"
            ]),
            Command::PythonPublish {
                files: vec!["a.whl".into(), "b.tar.gz".into()],
                namespace: "rel".into()
            }
        );
        // A Python program turns on the Python mode; --python and --pip do too.
        assert_eq!(
            run(&["exec", "--", "uv", "sync"]),
            Command::Exec {
                command: vec!["uv".into(), "sync".into()],
                python: Some("default".into()),
                pip: false
            }
        );
        assert_eq!(
            run(&["exec", "--pip", "--namespace", "rel", "--", "make"]),
            Command::Exec {
                command: vec!["make".into()],
                python: Some("rel".into()),
                pip: true
            }
        );
        assert_eq!(
            run(&["exec", "--", "npm", "ci"]),
            Command::Exec {
                command: vec!["npm".into(), "ci".into()],
                python: None,
                pip: false
            }
        );
        for bad in [
            &["exec", "--namespace", "rel", "--", "npm", "ci"][..],
            &["token", "--python", "--scope", "x"],
            &["token", "--url", "https://x/"],
            &["setup", "python", "--tool", "conda"],
            &["setup", "python", "--write"],
            &["python", "publish"],
            &["python", "publish", "a.whl", "--pip"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn go_commands() {
        let run = |args: &[&str]| match p(args).unwrap() {
            Parsed::Run { command, .. } => command,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            run(&[
                "go",
                "publish",
                "--dry-run",
                "--json",
                "tools",
                "tools/v1.0.0"
            ]),
            Command::GoPublish {
                dir: "tools".into(),
                tag: Some("tools/v1.0.0".into()),
                namespace: "default".into(),
                dry_run: true,
                json: true,
            }
        );
        assert_eq!(
            run(&[
                "go",
                "publish",
                "--dir",
                "x",
                "--tag=v1.0.0",
                "--namespace",
                "rel"
            ]),
            Command::GoPublish {
                dir: "x".into(),
                tag: Some("v1.0.0".into()),
                namespace: "rel".into(),
                dry_run: false,
                json: false,
            }
        );
        assert_eq!(
            run(&[
                "go-auth",
                "https://go.prego.k8skill.com/t/acme/default/x/@v/list"
            ]),
            Command::GoAuth {
                args: vec!["https://go.prego.k8skill.com/t/acme/default/x/@v/list".into()]
            }
        );
        assert_eq!(
            run(&[
                "setup",
                "go",
                "--prefix",
                "a.b",
                "--prefix=c.d/e",
                "--print"
            ]),
            Command::SetupGo {
                namespace: "default".into(),
                prefixes: vec!["a.b".into(), "c.d/e".into()],
                write: false,
            }
        );
        assert_eq!(
            run(&["--tenant", "acme", "exec", "--", "go", "build", "--json"]),
            Command::Exec {
                command: vec!["go".into(), "build".into(), "--json".into()],
                python: None,
                pip: false,
            }
        );
        for bad in [
            &["go", "publish", "a", "b", "c"][..],
            &["go", "publish", "--dir", "x", "y"],
            &["go", "publish", "--write"],
            &["setup", "go", "--write", "--print"],
            &["setup", "go", "--json"],
            &["exec"],
            &["exec", "--"],
            &["token", "--", "x"],
            &["go-auth", "a", "b"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn snippet_commands() {
        use crate::snippet::SnippetCommand;
        let sn = |a: &[&str]| match p(a).unwrap() {
            Parsed::Run {
                command: Command::Snippet(c),
                ..
            } => c,
            other => panic!("{other:?}"),
        };
        let h = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            sn(&[
                "snippet",
                "push",
                "./skill",
                "acme/agent-skill",
                "--tag",
                "v1",
                "--message",
                "m",
                "--if-current",
                &h
            ]),
            SnippetCommand::Push {
                source: "./skill".into(),
                reference: "acme/agent-skill".into(),
                tag: Some("v1".into()),
                message: Some("m".into()),
                if_current: Some(h.clone()),
                tar: false,
            }
        );
        assert_eq!(
            sn(&["snippet", "get", "acme/x@3", "out", "--expect", &h]),
            SnippetCommand::Get {
                reference: "acme/x@3".into(),
                folder: Some("out".into()),
                file: None,
                tar: false,
                expect: Some(h.clone()),
            }
        );
        assert_eq!(
            sn(&["snippet", "get", "acme/x", "--file", "a/b.md"]),
            SnippetCommand::Get {
                reference: "acme/x".into(),
                folder: None,
                file: Some("a/b.md".into()),
                tar: false,
                expect: None,
            }
        );
        assert_eq!(
            sn(&["snippet", "rollback", "acme/x", "--to", "prod", "--reason", "bad"]),
            SnippetCommand::Rollback {
                reference: "acme/x".into(),
                to: "prod".into(),
                reason: "bad".into(),
            }
        );
        assert_eq!(
            sn(&["snippet", "diff", "acme/x", "1", "v2"]),
            SnippetCommand::Diff {
                reference: "acme/x".into(),
                from: "1".into(),
                to: "v2".into(),
            }
        );
        assert_eq!(
            sn(&["snippet", "hash", "f.tar.gz", "--tar"]),
            SnippetCommand::Hash {
                source: "f.tar.gz".into(),
                tar: true,
            }
        );
        for bad in [
            &["snippet"][..],
            &["snippet", "push", "d"],
            &["snippet", "push", "d", "a/x", "--tag", "123"],
            &["snippet", "push", "d", "a/x", "--expect", &h],
            &["snippet", "get", "a/x", "--expect", "sha256:abc"],
            &["snippet", "get", "a/x", "out", "--file", "f"],
            &["snippet", "get", "a/x", "--tar", "--file", "f"],
            &["snippet", "rollback", "a/x", "--to", "1"],
            &["snippet", "ls", "a", "--tar"],
            &["snippet", "diff", "a/x", "1"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn env_commands() {
        use crate::env::reference::Level;
        use crate::env::{EnvCommand, Format};
        let env = |a: &[&str]| match p(a).unwrap() {
            Parsed::Run {
                command: Command::Env(c),
                ..
            } => c,
            other => panic!("{other:?}"),
        };
        let h = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            env(&["env", "pull", "acme/p@1", "--format", "env", "--expect", &h, "--out", "r.env"]),
            EnvCommand::Pull {
                reference: "acme/p@1".into(),
                format: Some(Format::Env),
                expect: Some(h.clone()),
                out: Some("r.env".into()),
            }
        );
        assert_eq!(
            env(&[
                "env",
                "push",
                "acme",
                "--level",
                "tenant",
                "--set",
                "A=1",
                "--set",
                "B=2",
                "--set-json",
                "C=[1]",
                "--message",
                "m",
                "--if-current",
                &h
            ]),
            EnvCommand::Push {
                reference: "acme".into(),
                level: Level::Tenant,
                file: None,
                env_file: None,
                sets: vec!["A=1".into(), "B=2".into()],
                set_jsons: vec!["C=[1]".into()],
                message: Some("m".into()),
                if_current: Some(h.clone()),
            }
        );
        assert_eq!(
            env(&["env", "rollback", "acme/p@1", "--to", "3", "--reason", "bad flag"]),
            EnvCommand::Rollback {
                reference: "acme/p@1".into(),
                level: Level::Version,
                to: 3,
                reason: "bad flag".into(),
            }
        );
        assert_eq!(
            env(&[
                "env",
                "diff",
                "acme/ns",
                "--level",
                "namespace",
                "--from",
                "1",
                "--to",
                "2"
            ]),
            EnvCommand::Diff {
                reference: "acme/ns".into(),
                level: Level::Namespace,
                from: 1,
                to: 2
            }
        );
        assert_eq!(
            env(&["env", "hash", "-"]),
            EnvCommand::Hash { file: "-".into() }
        );
        assert_eq!(
            env(&["env", "history", "acme/p@1"]),
            EnvCommand::History {
                reference: "acme/p@1".into(),
                level: Level::Version
            }
        );
        for bad in [
            &["env"][..],
            &["env", "pull"],
            &["env", "pull", "a/p@1", "--format", "yaml"],
            &["env", "pull", "a/p@1", "--expect", "sha256:abc"],
            &["env", "pull", "a/p@1", "--set", "A=1"],
            &["env", "push", "a/p@1"],
            &["env", "push", "a/p@1", "--file", "a", "--env-file", "b"],
            &["env", "push", "a/p@1", "--set", "A=1", "--level", "package"],
            &["env", "push", "a/p@1", "--set", "A=1", "--if-current", "x"],
            &["env", "rollback", "a/p@1", "--to", "2"],
            &["env", "rollback", "a/p@1", "--to", "0", "--reason", "r"],
            &["env", "diff", "a/p@1", "--from", "1"],
            &["env", "hash"],
            &["env", "hash", "f", "--json"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
        let long = "m".repeat(201);
        assert!(p(&["env", "push", "a/p@1", "--set", "A=1", "--message", &long]).is_err());
    }

    #[test]
    fn sqlite_commands() {
        use crate::sqlite::{db::Check, SqliteCommand};
        let sq = |args: &[&str]| match p(args) {
            Ok(Parsed::Run {
                command: Command::Sqlite(c),
                ..
            }) => *c,
            other => panic!("{other:?}"),
        };
        let h = format!("sha256:{}", "b".repeat(64));
        assert_eq!(
            sq(&[
                "sqlite",
                "save",
                "app.db",
                "acme/fleet/lookup",
                "--compact",
                "--check",
                "full",
                "--label",
                "build=42",
                "--message",
                "Daily build",
                "--tag",
                "2026-11-20"
            ]),
            SqliteCommand::Save {
                file: "app.db".into(),
                reference: "acme/fleet/lookup".into(),
                compact: true,
                check: Check::Full,
                labels: vec![("build".into(), "42".into())],
                message: Some("Daily build".into()),
                tag: Some("2026-11-20".into()),
            }
        );
        assert_eq!(
            sq(&["sqlite", "save", "app.db", "acme/lookup"]),
            SqliteCommand::Save {
                file: "app.db".into(),
                reference: "acme/lookup".into(),
                compact: false,
                check: Check::Quick,
                labels: vec![],
                message: None,
                tag: None,
            }
        );
        assert_eq!(
            sq(&[
                "sqlite",
                "restore",
                "acme/lookup@42",
                "l.db",
                "--expect",
                &h,
                "--force"
            ]),
            SqliteCommand::Restore {
                reference: "acme/lookup@42".into(),
                file: "l.db".into(),
                expect: Some(h.clone()),
                force: true,
            }
        );
        assert_eq!(
            sq(&[
                "sqlite",
                "prune",
                "acme/lookup",
                "--older-than",
                "7d",
                "--yes"
            ]),
            SqliteCommand::Prune {
                reference: "acme/lookup".into(),
                keep: None,
                older_than: Some(7 * 86_400),
                yes: true,
            }
        );
        assert_eq!(
            sq(&[
                "sqlite",
                "set",
                "acme/lookup",
                "--keep-count",
                "10",
                "--keep-days",
                "14"
            ]),
            SqliteCommand::Set {
                reference: "acme/lookup".into(),
                keep_count: Some(10),
                keep_days: Some(14),
            }
        );
        assert_eq!(
            sq(&["sqlite", "hash", "app.db", "--compact"]),
            SqliteCommand::Hash {
                file: "app.db".into(),
                compact: true,
            }
        );
        assert_eq!(
            sq(&["sqlite", "rm", "acme/lookup"]),
            SqliteCommand::Rm {
                reference: "acme/lookup".into(),
                yes: false,
            }
        );
        for bad in [
            &["sqlite", "save", "app.db"][..],
            &["sqlite", "save", "a.db", "acme/l", "--check", "fast"],
            &[
                "sqlite",
                "save",
                "a.db",
                "acme/l",
                "--label",
                "prego.check=ok",
            ],
            &["sqlite", "save", "a.db", "acme/l", "--tag", "x.db.gz"],
            &["sqlite", "save", "a.db", "acme/l", "--force"],
            &["sqlite", "restore", "acme/l", "l.db", "--expect", "abc"],
            &["sqlite", "restore", "acme/l", "l.db", "--compact"],
            &["sqlite", "prune", "acme/l"],
            &["sqlite", "prune", "acme/l", "--older-than", "7"],
            &["sqlite", "set", "acme/l"],
            &["sqlite", "set", "acme/l", "--keep-count", "0"],
            &["sqlite", "set", "acme/l", "--keep-days", "401"],
            &["sqlite", "log", "acme/l", "--yes"],
            &["sqlite", "backup", "acme/l"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn context_commands() {
        use crate::context::ContextCommand;
        let cx = |args: &[&str]| match p(args) {
            Ok(Parsed::Run {
                command: Command::Context(c),
                ..
            }) => *c,
            other => panic!("{other:?}"),
        };
        let h = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            cx(&[
                "context",
                "save",
                "mem",
                "acme/a1",
                "--session",
                "s1",
                "--label",
                "a=1",
                "--label",
                "b=x=y",
                "--trigger",
                "stop",
                "--parent",
                &h,
                "--no-redact"
            ]),
            ContextCommand::Save {
                folder: "mem".into(),
                reference: "acme/a1".into(),
                session: Some("s1".into()),
                parent: Some(h.clone()),
                trigger: Some("stop".into()),
                labels: vec![("a".into(), "1".into()), ("b".into(), "x=y".into())],
                message: None,
                tag: None,
                redact: false,
            }
        );
        assert_eq!(
            cx(&["context", "restore", "acme/a1@7", "out", "--expect", &h]),
            ContextCommand::Restore {
                reference: "acme/a1@7".into(),
                folder: "out".into(),
                session: None,
                expect: Some(h.clone()),
            }
        );
        assert_eq!(
            cx(&["context", "set", "acme/a1", "--keep-days", "400"]),
            ContextCommand::Set {
                reference: "acme/a1".into(),
                keep_days: Some(400),
                on_full: None,
            }
        );
        assert_eq!(
            cx(&["context", "hash", "mem"]),
            ContextCommand::Hash {
                folder: "mem".into(),
                redact: true,
            }
        );
        for bad in [
            &["context", "save", "mem"][..],
            &["context", "restore", "acme/a1"],
            &["context", "save", "m", "acme/a1", "--parent", "abc"],
            &["context", "save", "m", "acme/a1", "--session", "a/b"],
            &["context", "save", "m", "acme/a1", "--tar"],
            &["context", "restore", "acme/a1", "o", "--no-redact"],
            &["context", "log", "acme/a1", "--expect", &h],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }
}
