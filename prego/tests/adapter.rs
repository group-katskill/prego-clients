//! Runs `prego adapter push` and `prego adapter get` against the mock registry in
//! `support/mock_registry.rs`.

mod support {
    pub mod mock_registry;
}

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use support::mock_registry::{sha256, MockRegistry};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
const API_KEY: &str = "prk_test_secret_value";
const REPO: &str = "acme/ml/support-bot";
const CONFIG: &str =
    r#"{"peft_type":"LORA","base_model_name_or_path":"meta-llama/Llama-3.1-8B-Instruct","r":16}"#;

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(reg: &MockRegistry, home: &Path, args: &[&str]) -> Run {
    let sts = reg.sts_url();
    let out = Command::new(BIN)
        .args(args)
        .args(["--sts-url", &sts])
        .env_clear()
        .env("PREGO_TENANT", "acme")
        .env("PREGO_API_KEY", API_KEY)
        .env("PREGO_OCI_HOSTS", reg.host())
        .env("HOME", home)
        .output()
        .expect("run prego");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn registry() -> MockRegistry {
    MockRegistry::start(&format!("acme:{API_KEY}"), 1024 * 1024)
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("prego-adapter-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A safetensors file with one F32 tensor of `n` elements.
fn safetensors(n: u64, seed: u8) -> Vec<u8> {
    let header = format!(
        r#"{{"base_model.model.lora_A.weight":{{"dtype":"F32","shape":[{n}],"data_offsets":[0,{}]}}}}"#,
        n * 4
    );
    let mut out = (header.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(header.as_bytes());
    out.extend((0..n * 4).map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed)));
    out
}

/// An adapter folder in `<root>/adapter`.
fn adapter(root: &Path, seed: u8) -> PathBuf {
    let dir = root.join("adapter");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("adapter_config.json"), CONFIG).unwrap();
    std::fs::write(
        dir.join("adapter_model.safetensors"),
        safetensors(4096, seed),
    )
    .unwrap();
    std::fs::write(
        dir.join("README.md"),
        "---\nlicense: other\nlicense_name: llama3.1\n---\n# Support bot\n",
    )
    .unwrap();
    dir
}

fn reference(reg: &MockRegistry, tag: &str) -> String {
    format!("{}/{REPO}:{tag}", reg.host())
}

#[test]
fn push_then_get() {
    let reg = registry();
    // Blobs of 1 KiB or more come from the storage link.
    reg.with(|s| s.redirect_from = Some(1024));
    let root = temp_dir("roundtrip");
    let dir = adapter(&root, 1);
    let r = reference(&reg, "2026-11-14");
    let push = run(
        &reg,
        &root,
        &[
            "adapter",
            "push",
            dir.to_str().unwrap(),
            &r,
            "--base-revision",
            "0e9e39f",
        ],
    );
    assert_eq!(push.code, 0, "{}", push.stderr);
    assert!(
        push.stderr
            .contains("license LicenseRef-llama3.1 (from README.md)"),
        "{}",
        push.stderr
    );
    let (digest, media_type, body) = reg.tag(REPO, "2026-11-14").expect("tag");
    assert_eq!(push.stdout.trim(), format!("{r}@{digest}"));
    assert_eq!(media_type, "application/vnd.oci.image.manifest.v1+json");
    let m: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(m["artifactType"], "application/vnd.prego.adapter.v1+json");
    assert_eq!(
        m["config"]["mediaType"],
        "application/vnd.prego.adapter.config.v1+json"
    );
    assert_eq!(m["config"]["digest"], sha256(CONFIG.as_bytes()));
    assert_eq!(
        m["annotations"]["org.opencontainers.image.licenses"],
        "LicenseRef-llama3.1"
    );
    assert_eq!(
        m["annotations"]["dev.prego.adapter.base"],
        "meta-llama/Llama-3.1-8B-Instruct"
    );
    assert_eq!(
        m["annotations"]["dev.prego.adapter.base.revision"],
        "0e9e39f"
    );
    let titles: Vec<&str> = m["layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            l["annotations"]["org.opencontainers.image.title"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert_eq!(titles, ["adapter_model.safetensors", "README.md"]);

    // The same push again changes nothing (same digest).
    let again = run(
        &reg,
        &root,
        &[
            "adapter",
            "push",
            dir.to_str().unwrap(),
            &r,
            "--base-revision",
            "0e9e39f",
        ],
    );
    assert_eq!(again.code, 0, "{}", again.stderr);
    assert!(again.stderr.contains("exists"), "{}", again.stderr);

    let out = root.join("got/support-bot");
    let get = run(&reg, &root, &["adapter", "get", &r, out.to_str().unwrap()]);
    assert_eq!(get.code, 0, "{}", get.stderr);
    assert!(
        get.stderr.contains("license LicenseRef-llama3.1"),
        "{}",
        get.stderr
    );
    for name in [
        "adapter_config.json",
        "adapter_model.safetensors",
        "README.md",
    ] {
        assert_eq!(
            std::fs::read(out.join(name)).unwrap(),
            std::fs::read(dir.join(name)).unwrap(),
            "{name}"
        );
    }
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 3);
    // The storage link was used, and it never got the registry token.
    let storage: Vec<_> = reg
        .requests()
        .into_iter()
        .filter(|q| q.target.starts_with("/storage/"))
        .collect();
    assert!(!storage.is_empty());
    assert!(storage.iter().all(|q| q.authorization.is_none()));
}

#[test]
fn a_version_is_written_once() {
    let reg = registry();
    let root = temp_dir("once");
    let dir = adapter(&root, 1);
    let r = reference(&reg, "v1");
    assert_eq!(
        run(&reg, &root, &["adapter", "push", dir.to_str().unwrap(), &r]).code,
        0
    );
    std::fs::write(dir.join("adapter_model.safetensors"), safetensors(4096, 2)).unwrap();
    let second = run(&reg, &root, &["adapter", "push", dir.to_str().unwrap(), &r]);
    assert_eq!(second.code, 1);
    assert!(
        second.stderr.contains("HTTP 409")
            && second
                .stderr
                .contains("An adapter version is written one time only"),
        "{}",
        second.stderr
    );
}

#[test]
fn a_plan_without_adapters() {
    let reg = registry();
    reg.with(|s| s.deny_adapters = true);
    let root = temp_dir("plan");
    let dir = adapter(&root, 1);
    let res = run(
        &reg,
        &root,
        &[
            "adapter",
            "push",
            dir.to_str().unwrap(),
            &reference(&reg, "v1"),
        ],
    );
    assert_eq!(res.code, 1);
    assert!(
        res.stderr
            .contains("Only the Publisher plan (and Trial) can push adapters"),
        "{}",
        res.stderr
    );
}

#[test]
fn local_checks_send_nothing() {
    let reg = registry();
    let root = temp_dir("local");
    let dir = adapter(&root, 1);
    std::fs::write(dir.join("training_args.bin"), [0x80, 0x04]).unwrap();
    let res = run(
        &reg,
        &root,
        &[
            "adapter",
            "push",
            dir.to_str().unwrap(),
            &reference(&reg, "v1"),
        ],
    );
    assert_eq!(res.code, 1);
    assert!(res.stderr.contains("is a pickle file"), "{}", res.stderr);
    std::fs::remove_file(dir.join("training_args.bin")).unwrap();
    std::fs::write(dir.join("README.md"), "# No license\n").unwrap();
    let res = run(
        &reg,
        &root,
        &[
            "adapter",
            "push",
            dir.to_str().unwrap(),
            &reference(&reg, "v1"),
        ],
    );
    assert_eq!(res.code, 1);
    assert!(res.stderr.contains("needs a license"), "{}", res.stderr);
    let res = run(
        &reg,
        &root,
        &[
            "adapter",
            "push",
            dir.to_str().unwrap(),
            &format!("{}/{REPO}", reg.host()),
        ],
    );
    assert_eq!(res.code, 1);
    assert!(
        res.stderr
            .contains("give the version of the adapter as a tag"),
        "{}",
        res.stderr
    );
    assert!(reg.requests().is_empty());
}

#[test]
fn get_refuses_a_changed_blob_and_cleans_up() {
    let reg = registry();
    let root = temp_dir("corrupt");
    let dir = adapter(&root, 1);
    let r = reference(&reg, "v1");
    assert_eq!(
        run(&reg, &root, &["adapter", "push", dir.to_str().unwrap(), &r]).code,
        0
    );
    reg.with(|s| s.corrupt_get = true);
    let out = root.join("got");
    let res = run(&reg, &root, &["adapter", "get", &r, out.to_str().unwrap()]);
    assert_eq!(res.code, 1);
    assert!(
        res.stderr.contains("does not match its digest"),
        "{}",
        res.stderr
    );
    assert!(!out.exists());
}

#[test]
fn get_needs_an_adapter_and_an_empty_folder() {
    let reg = registry();
    let root = temp_dir("refuse");
    let dir = adapter(&root, 1);
    let r = reference(&reg, "v1");
    assert_eq!(
        run(&reg, &root, &["adapter", "push", dir.to_str().unwrap(), &r]).code,
        0
    );
    let res = run(&reg, &root, &["adapter", "get", &r, dir.to_str().unwrap()]);
    assert_eq!(res.code, 1);
    assert!(res.stderr.contains("is not empty"), "{}", res.stderr);

    // An image manifest is not an adapter.
    let config = b"{}".to_vec();
    let image = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": sha256(&config), "size": 2},
        "layers": [],
    })
    .to_string()
    .into_bytes();
    reg.with(|s| {
        let d = sha256(&image);
        s.manifests.insert(
            (REPO.into(), d.clone()),
            (
                "application/vnd.oci.image.manifest.v1+json".into(),
                image.clone(),
            ),
        );
        s.tags.insert((REPO.into(), "image".into()), d);
    });
    let out = root.join("got");
    let res = run(
        &reg,
        &root,
        &[
            "adapter",
            "get",
            &reference(&reg, "image"),
            out.to_str().unwrap(),
        ],
    );
    assert_eq!(res.code, 1);
    assert!(
        res.stderr.contains("is not a Prego adapter"),
        "{}",
        res.stderr
    );
    assert!(!out.exists());
}
