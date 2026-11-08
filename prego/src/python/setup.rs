//! `prego setup python`: the uv index and sources, the Poetry source, or the pip line. It never writes a
//! token.

use std::path::Path;

use prego_auth::http::{Body, Http};
use toml_edit::{value, ArrayOfTables, DocumentMut, InlineTable, Item, Table};

use super::{python_token, target, Target};

/// The tool that `prego setup python` writes the settings for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Uv,
    Poetry,
    Pip,
}

impl Tool {
    pub fn parse(s: &str) -> Result<Tool, String> {
        match s {
            "uv" => Ok(Tool::Uv),
            "poetry" => Ok(Tool::Poetry),
            "pip" => Ok(Tool::Pip),
            other => Err(format!(
                "--tool `{other}` is not known. Use uv, poetry or pip"
            )),
        }
    }
}

/// The options of `prego setup python`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupOptions {
    pub namespace: String,
    /// Project names for `[tool.uv.sources]`. Empty: the projects that the identity can read, from the index.
    pub projects: Vec<String>,
    pub tool: Tool,
    /// Print the lines, write no file.
    pub print: bool,
}

/// The name of the index in uv and the source in Poetry. `prego exec` sets `UV_INDEX_PREGO_*` and
/// `POETRY_HTTP_BASIC_PREGO_*` for it.
pub const INDEX_NAME: &str = "prego";

const PIP_WARNING: &str = "\
# Warning: pip asks every index for every name and installs the highest version. A package on pypi.org
# with the same name as your private package can win (dependency confusion). Use uv or Poetry with an
# explicit index. If you must use pip, register the same names on pypi.org as empty placeholders, or
# install with hashes (pip install --require-hashes -r requirements.txt).";

const NO_PROJECTS: &str =
    " Add one line for each private package: acme-core = { index = \"prego\" }";

/// Checks a project name (PEP 508): letters, digits, `-`, `_`, `.`, starting and ending with a letter or
/// digit, at most 128 characters.
pub fn check_project(name: &str) -> Result<(), String> {
    let b = name.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "prego: bad project name `{name}`: use letters, digits, `-`, `_` and `.` (PEP 508)"
        ))
    }
}

/// Puts the uv index and the sources into a `pyproject.toml` text. Other lines stay as they are. Returns the
/// new text and the notes for the user.
pub fn merge_uv(
    old: &str,
    index_url: &str,
    projects: &[String],
) -> Result<(String, Vec<String>), String> {
    let mut doc: DocumentMut = old
        .parse()
        .map_err(|_| "prego: pyproject.toml is not valid TOML".to_string())?;
    let mut notes = Vec::new();
    let uv = sub_table(sub_table(doc.as_table_mut(), "tool")?, "uv")?;

    // [[tool.uv.index]] with name = "prego": update it, or add it.
    if !uv.contains_key("index") {
        uv.insert("index", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let list = uv["index"].as_array_of_tables_mut().ok_or(
        "prego: tool.uv.index in pyproject.toml is not a list of tables ([[tool.uv.index]])",
    )?;
    let pos = list
        .iter()
        .position(|t| t.get("name").and_then(Item::as_str) == Some(INDEX_NAME));
    let entry = match pos {
        Some(i) => list.get_mut(i).expect("index entry"),
        None => {
            list.push(Table::new());
            list.get_mut(list.len() - 1).expect("new entry")
        }
    };
    entry["name"] = value(INDEX_NAME);
    entry["url"] = value(index_url);
    entry["explicit"] = value(true);
    entry["authenticate"] = value("always");
    if entry.contains_key("username") || entry.contains_key("password") {
        entry.remove("username");
        entry.remove("password");
        notes.push(
            "Removed username and password from the prego index: prego exec sets them. Never commit a token."
                .into(),
        );
    }

    // [tool.uv.sources]: one line for each project.
    let empty = !uv.contains_key("sources");
    let sources = sub_table(uv, "sources")?;
    sources.set_implicit(false);
    for p in projects {
        let mut t = InlineTable::new();
        t.insert("index", INDEX_NAME.into());
        match sources.get(p) {
            Some(old)
                if old
                    .as_inline_table()
                    .and_then(|t| t.get("index"))
                    .and_then(|v| v.as_str())
                    == Some(INDEX_NAME) => {}
            Some(_) => {
                notes.push(format!(
                    "Replaced the source of `{p}` with the prego index."
                ));
                sources.insert(p, value(t));
            }
            None => {
                sources.insert(p, value(t));
            }
        }
    }
    if projects.is_empty() && empty {
        sources.decor_mut().set_suffix(format!("\n#{NO_PROJECTS}"));
    }
    Ok((doc.to_string(), notes))
}

/// Puts the Poetry source into a `pyproject.toml` text. Other lines stay as they are.
pub fn merge_poetry(old: &str, index_url: &str) -> Result<String, String> {
    let mut doc: DocumentMut = old
        .parse()
        .map_err(|_| "prego: pyproject.toml is not valid TOML".to_string())?;
    let poetry = sub_table(sub_table(doc.as_table_mut(), "tool")?, "poetry")?;
    if !poetry.contains_key("source") {
        poetry.insert("source", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let list = poetry["source"]
        .as_array_of_tables_mut()
        .ok_or("prego: tool.poetry.source in pyproject.toml is not a list of tables")?;
    let pos = list
        .iter()
        .position(|t| t.get("name").and_then(Item::as_str) == Some(INDEX_NAME));
    let entry = match pos {
        Some(i) => list.get_mut(i).expect("source entry"),
        None => {
            list.push(Table::new());
            list.get_mut(list.len() - 1).expect("new entry")
        }
    };
    entry["name"] = value(INDEX_NAME);
    entry["url"] = value(index_url);
    entry["priority"] = value("explicit");
    Ok(doc.to_string())
}

/// A table under `parent`, made implicit (no header line) if it is new.
fn sub_table<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table, String> {
    if !parent.contains_key(key) {
        let mut t = Table::new();
        t.set_implicit(true);
        parent.insert(key, Item::Table(t));
    }
    parent[key]
        .as_table_mut()
        .ok_or_else(|| format!("prego: `{key}` in pyproject.toml is not a table"))
}

/// The project names that the identity can read in the namespace: the PEP 691 JSON root index.
fn index_projects(
    config: &prego_auth::Config,
    t: &Target,
    env: &dyn prego_auth::Env,
) -> Option<Vec<String>> {
    let token = python_token(config, t, env).ok()?;
    let http = Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref()).ok()?;
    let auth = format!("Bearer {}", token.expose());
    let res = http
        .send(
            "GET",
            &t.index(),
            &[
                ("Accept", "application/vnd.pypi.simple.v1+json"),
                ("Authorization", &auth),
            ],
            Body::Empty,
        )
        .ok()?;
    if res.status != 200 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&res.body).ok()?;
    let mut names: Vec<String> = v["projects"]
        .as_array()?
        .iter()
        .filter_map(|p| p["name"].as_str())
        .filter(|n| check_project(n).is_ok())
        .map(str::to_string)
        .collect();
    names.sort();
    names.dedup();
    Some(names)
}

/// `prego setup python`.
pub fn setup(globals: &[&str], o: &SetupOptions, env: &dyn prego_auth::Env) -> Result<(), String> {
    for p in &o.projects {
        check_project(p)?;
    }
    let (config, t) = target(globals, None, &o.namespace, env)?;
    let index = t.index();

    if o.tool == Tool::Pip {
        println!("{PIP_WARNING}");
        println!("# Index: {index}");
        let name = o.projects.first().map_or("<project>", String::as_str);
        println!("prego exec --pip -- pip install {name}");
        return Ok(());
    }

    let path = Path::new("pyproject.toml");
    let old = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && o.print => String::new(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(
                "prego: no pyproject.toml in this directory. Run the command in the project directory, or \
                 use --print"
                    .into(),
            )
        }
        Err(e) => return Err(format!("prego: cannot read pyproject.toml: {e}")),
    };

    let projects = match (&o.tool, o.projects.is_empty()) {
        (Tool::Uv, true) => index_projects(&config, &t, env).unwrap_or_default(),
        _ => o.projects.clone(),
    };

    let (text, notes) = match o.tool {
        Tool::Uv => merge_uv(if o.print { "" } else { &old }, &index, &projects)?,
        Tool::Poetry => (
            merge_poetry(if o.print { "" } else { &old }, &index)?,
            Vec::new(),
        ),
        Tool::Pip => unreachable!(),
    };

    if o.print {
        println!("# Add this to pyproject.toml (or run the command without --print):");
        print!("{text}");
    } else if text == old {
        println!("pyproject.toml already uses the prego index.");
    } else {
        crate::env::write_atomic("pyproject.toml", &text)?;
        println!("Updated pyproject.toml: index {index}");
    }
    for n in notes {
        println!("{n}");
    }
    match o.tool {
        Tool::Uv => {
            if projects.is_empty() {
                println!("#{NO_PROJECTS}");
            }
            println!("Then run: prego exec -- uv sync");
        }
        Tool::Poetry => {
            let name = projects.first().map_or("<project>", String::as_str);
            println!("Then run: poetry add --source {INDEX_NAME} {name}");
            println!("and: prego exec -- poetry install (or install keyrings.prego for Poetry)");
        }
        Tool::Pip => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://pypi.prego.k8skill.com/t/acme/default/simple/";

    #[test]
    fn uv_new_file() {
        let (text, notes) = merge_uv("", URL, &["acme-core".into()]).unwrap();
        assert_eq!(
            text,
            "[[tool.uv.index]]\nname = \"prego\"\nurl = \"https://pypi.prego.k8skill.com/t/acme/default/simple/\"\n\
             explicit = true\nauthenticate = \"always\"\n\n[tool.uv.sources]\nacme-core = { index = \"prego\" }\n"
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn uv_keeps_other_lines_and_is_stable() {
        let old = "[project]\nname = \"app\" # the app\ndependencies = [\"acme-core\"]\n\n\
                   [[tool.uv.index]]\nname = \"other\"\nurl = \"https://example.test/simple/\"\n\n\
                   [[tool.uv.index]]\nname = \"prego\"\nurl = \"https://old.test/\"\npassword = \"x\"\n\n\
                   [tool.uv.sources]\nacme-core = { git = \"https://example.test/x\" }\nother = { path = \"../o\" }\n";
        let (text, notes) = merge_uv(old, URL, &["acme-core".into(), "acme-db".into()]).unwrap();
        assert!(
            text.starts_with("[project]\nname = \"app\" # the app\n"),
            "{text}"
        );
        assert!(text.contains("name = \"other\"\nurl = \"https://example.test/simple/\""));
        assert!(text.contains(&format!("url = \"{URL}\"")));
        assert!(!text.contains("old.test") && !text.contains("password"));
        assert!(text.contains("acme-core = { index = \"prego\" }"));
        assert!(text.contains("acme-db = { index = \"prego\" }"));
        assert!(text.contains("other = { path = \"../o\" }"));
        assert_eq!(notes.len(), 2, "{notes:?}");
        // A second run changes nothing.
        let (again, notes) = merge_uv(&text, URL, &["acme-core".into()]).unwrap();
        assert_eq!(again, text);
        assert!(notes.is_empty());
    }

    #[test]
    fn uv_no_projects_writes_a_comment() {
        let (text, _) = merge_uv("[project]\nname = \"app\"\n", URL, &[]).unwrap();
        assert!(text.contains("[tool.uv.sources]\n#"), "{text}");
        assert!(
            text.contains("acme-core = { index = \\\"prego\\\" }")
                || text.contains("{ index = \"prego\" }")
        );
        assert!(merge_uv("tool = 1\n", URL, &[]).is_err());
        assert!(merge_uv("not toml [", URL, &[]).is_err());
    }

    #[test]
    fn poetry_source() {
        let text = merge_poetry("[project]\nname = \"app\"\n", URL).unwrap();
        assert_eq!(
            text,
            "[project]\nname = \"app\"\n\n[[tool.poetry.source]]\nname = \"prego\"\n\
             url = \"https://pypi.prego.k8skill.com/t/acme/default/simple/\"\npriority = \"explicit\"\n"
        );
        assert_eq!(merge_poetry(&text, URL).unwrap(), text);
    }

    #[test]
    fn project_names() {
        for ok in ["acme-core", "a", "A.b_c-1"] {
            check_project(ok).unwrap();
        }
        for bad in ["", "-a", "a-", "a b", "a/b", &"a".repeat(129)] {
            assert!(check_project(bad).is_err(), "{bad}");
        }
    }
}
