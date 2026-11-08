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
    },
    /// `prego logout`.
    Logout,
    /// `prego status`.
    Status,
    /// `prego env ...`.
    Env(crate::env::EnvCommand),
}

const GLOBAL: [&str; 5] = [
    "--tenant",
    "--sts-url",
    "--edge-code",
    "--audience",
    "--source",
];
const WITH_VALUE: [&str; 25] = [
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
];
/// Options without a value.
const FLAGS: [&str; 9] = [
    "--write",
    "--print",
    "--dry-run",
    "--json",
    "--user",
    "--publish",
    "--no-browser",
    "--python",
    "--pip",
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
        let arg = arg.as_str();
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
            allow(&[], &["--publish", "--no-browser"])?;
            Command::Login {
                publish: flag("--publish"),
                no_browser: flag("--no-browser"),
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
}
