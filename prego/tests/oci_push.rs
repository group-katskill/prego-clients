//! Runs `prego oci push` against the mock registry in `support/mock_registry.rs`.

mod support {
    pub mod mock_registry;
}

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use support::mock_registry::{sha256, MockRegistry};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
const API_KEY: &str = "prk_test_secret_value";
const MIB: u64 = 1024 * 1024;
const REPO: &str = "acme/default/app";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn push(reg: &MockRegistry, input: &Path, tag: &str, extra: &[&str]) -> Run {
    let reference = format!("{}/{REPO}:{tag}", reg.host());
    let sts = reg.sts_url();
    let mut args = vec![
        "oci",
        "push",
        input.to_str().unwrap(),
        &reference,
        "--sts-url",
        &sts,
    ];
    args.extend_from_slice(extra);
    let out = Command::new(BIN)
        .args(&args)
        .env_clear()
        .env("PREGO_TENANT", "acme")
        .env("PREGO_API_KEY", API_KEY)
        .env("PREGO_OCI_HOSTS", reg.host())
        .env("HOME", input.parent().unwrap())
        .output()
        .expect("run prego");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn registry() -> MockRegistry {
    MockRegistry::start(&format!("acme:{API_KEY}"), MIB)
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("prego-oci-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Bytes that are not all the same, so a wrong offset changes the digest.
fn data(len: u64, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 13) as u8)
        .collect()
}

fn desc(media_type: &str, bytes: &[u8]) -> Value {
    json!({ "mediaType": media_type, "digest": sha256(bytes), "size": bytes.len() })
}

/// An OCI image: config, layers, and the manifest bytes.
struct TestImage {
    config: Vec<u8>,
    layers: Vec<Vec<u8>>,
    manifest: Vec<u8>,
}

fn image(layer_sizes: &[u64], seed: u8) -> TestImage {
    let layers: Vec<Vec<u8>> = layer_sizes
        .iter()
        .enumerate()
        .map(|(i, &n)| data(n, seed + i as u8))
        .collect();
    let config = serde_json::to_vec(&json!({
        "architecture": "amd64", "os": "linux",
        "rootfs": { "type": "layers", "diff_ids": layers.iter().map(|l| sha256(l)).collect::<Vec<_>>() }
    }))
    .unwrap();
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": desc("application/vnd.oci.image.config.v1+json", &config),
        "layers": layers.iter().map(|l| desc("application/vnd.oci.image.layer.v1.tar", l)).collect::<Vec<_>>(),
    }))
    .unwrap();
    TestImage {
        config,
        layers,
        manifest,
    }
}

fn write_blob(dir: &Path, bytes: &[u8]) {
    let d = sha256(bytes);
    let p = dir.join("blobs/sha256").join(&d["sha256:".len()..]);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

/// Writes an OCI image layout with `img` as the only image.
fn oci_layout(dir: &Path, img: &TestImage) {
    std::fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
    for b in std::iter::once(&img.config)
        .chain(&img.layers)
        .chain(std::iter::once(&img.manifest))
    {
        write_blob(dir, b);
    }
    let index = json!({ "schemaVersion": 2, "manifests": [
        desc("application/vnd.oci.image.manifest.v1+json", &img.manifest)
    ]});
    std::fs::write(dir.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();
}

fn tar_of(files: &[(&str, &[u8])], links: &[(&str, &str)], out: &Path) {
    let mut b = tar::Builder::new(std::fs::File::create(out).unwrap());
    for (name, bytes) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, name, *bytes).unwrap();
    }
    for (name, target) in links {
        let mut h = tar::Header::new_gnu();
        h.set_size(0);
        h.set_entry_type(tar::EntryType::Symlink);
        b.append_link(&mut h, name, target).unwrap();
    }
    b.finish().unwrap();
}

fn assert_pushed(reg: &MockRegistry, img: &TestImage, tag: &str) {
    let (digest, mt, body) = reg.tag(REPO, tag).expect("tag pushed");
    assert_eq!(digest, sha256(&img.manifest));
    assert_eq!(mt, "application/vnd.oci.image.manifest.v1+json");
    assert_eq!(body, img.manifest);
    for b in std::iter::once(&img.config).chain(&img.layers) {
        assert_eq!(reg.blob(REPO, &sha256(b)).as_deref(), Some(b.as_slice()));
    }
}

#[test]
fn pushes_an_oci_layout_in_equal_parts() {
    let reg = registry();
    let dir = temp_dir("layout");
    let input = dir.join("img");
    std::fs::create_dir_all(&input).unwrap();
    // 3.5 MiB in parts of 1 MiB: 1, 1, 1 and 0.5 MiB.
    let img = image(&[3 * MIB + MIB / 2, 1000], 1);
    oci_layout(&input, &img);

    let r = push(&reg, &input, "v1", &["--chunk-size", "1"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.stdout,
        format!("{}/{REPO}:v1@{}\n", reg.host(), sha256(&img.manifest))
    );
    assert_pushed(&reg, &img, "v1");

    let reqs = reg.requests();
    assert!(
        reqs.iter().all(|q| !q.chunked),
        "no chunked transfer encoding"
    );
    let big = 3 * MIB + MIB / 2;
    let ranges: Vec<String> = reqs
        .iter()
        .filter(|q| q.method == "PATCH" && q.content_length.unwrap_or(0) >= MIB / 2)
        .map(|q| q.content_range.clone().unwrap())
        .collect();
    assert_eq!(
        ranges,
        vec![
            format!("0-{}", MIB - 1),
            format!("{}-{}", MIB, 2 * MIB - 1),
            format!("{}-{}", 2 * MIB, 3 * MIB - 1),
            format!("{}-{}", 3 * MIB, big - 1),
        ]
    );
    assert!(reqs.iter().all(|q| q.content_length.unwrap_or(0) <= MIB));
    // The final PUT keeps the query of the upload location.
    assert!(reqs.iter().any(|q| q.method == "PUT"
        && q.target.contains("?_state=")
        && q.target.contains("&digest=sha256:")));
    // One realm request for the whole push, and the identity goes only to the realm.
    assert_eq!(reg.with(|s| s.token_requests), 1);
    assert!(reqs
        .iter()
        .filter(|q| q.target.starts_with("/v2/"))
        .all(|q| !q
            .authorization
            .as_deref()
            .unwrap_or("")
            .starts_with("Basic")));
    assert!(!r.stderr.contains(API_KEY));

    // A second push finds every blob and sends no upload.
    let before = reg.requests().len();
    let r = push(&reg, &input, "v1", &["--chunk-size", "1"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let again = &reg.requests()[before..];
    assert!(again
        .iter()
        .all(|q| q.method != "POST" && q.method != "PATCH"));
    assert!(r.stderr.contains("exists"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn pushes_an_old_docker_save_tar() {
    let reg = registry();
    let dir = temp_dir("legacy");
    let config =
        br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#;
    let l1 = data(2 * MIB + 7, 3);
    let l2 = data(300, 4);
    let manifest = json!([{
        "Config": "abc.json",
        "RepoTags": ["app:v2"],
        "Layers": ["l1/layer.tar", "l2/layer.tar", "l3/layer.tar"]
    }]);
    let manifest = serde_json::to_vec(&manifest).unwrap();
    let tar = dir.join("app.tar");
    tar_of(
        &[
            ("manifest.json", &manifest),
            ("abc.json", config),
            ("l1/layer.tar", &l1),
            ("l2/layer.tar", &l2),
        ],
        // docker save writes a symlink for a layer that is the same as another one.
        &[("l3/layer.tar", "../l1/layer.tar")],
        &tar,
    );

    let r = push(&reg, &tar, "v2", &[]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let (_, mt, body) = reg.tag(REPO, "v2").unwrap();
    assert_eq!(mt, "application/vnd.oci.image.manifest.v1+json");
    let m: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(m["config"]["digest"], sha256(config));
    let layers: Vec<&str> = m["layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["digest"].as_str().unwrap())
        .collect();
    assert_eq!(layers, vec![sha256(&l1), sha256(&l2), sha256(&l1)]);
    assert_eq!(
        m["layers"][0]["mediaType"],
        "application/vnd.oci.image.layer.v1.tar"
    );
    assert_eq!(reg.blob(REPO, &sha256(&l1)).unwrap(), l1);
    assert!(r.stdout.ends_with(&format!("@{}\n", sha256(&body))));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn pushes_a_multi_platform_index_from_a_docker_save_tar() {
    let reg = registry();
    let dir = temp_dir("index");
    let amd = image(&[1500], 10);
    let arm = image(&[1600], 20);
    let index = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": sha256(&amd.manifest),
              "size": amd.manifest.len(), "platform": { "os": "linux", "architecture": "amd64" } },
            { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": sha256(&arm.manifest),
              "size": arm.manifest.len(), "platform": { "os": "linux", "architecture": "arm64" } },
        ]
    }))
    .unwrap();
    let top = serde_json::to_vec(&json!({ "schemaVersion": 2, "manifests": [
        { "mediaType": "application/vnd.oci.image.index.v1+json", "digest": sha256(&index), "size": index.len(),
          "annotations": { "org.opencontainers.image.ref.name": "v3" } }
    ]}))
    .unwrap();
    let mut owned: Vec<(String, Vec<u8>)> = vec![
        (
            "oci-layout".into(),
            br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec(),
        ),
        ("index.json".into(), top),
        ("manifest.json".into(), b"[]".to_vec()),
    ];
    for b in [
        &amd.config,
        &amd.layers[0],
        &amd.manifest,
        &arm.config,
        &arm.layers[0],
        &arm.manifest,
        &index,
    ] {
        owned.push((format!("blobs/sha256/{}", &sha256(b)[7..]), b.clone()));
    }
    let files: Vec<(&str, &[u8])> = owned
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let tar = dir.join("multi.tar");
    tar_of(&files, &[], &tar);

    let r = push(&reg, &tar, "v3", &[]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let (d, mt, _) = reg.tag(REPO, "v3").unwrap();
    assert_eq!(d, sha256(&index));
    assert_eq!(mt, "application/vnd.oci.image.index.v1+json");
    for m in [&amd.manifest, &arm.manifest] {
        assert!(reg.with(|s| s.manifests.contains_key(&(REPO.into(), sha256(m)))));
    }
    // Children by digest first, then the index by tag.
    let puts: Vec<String> = reg
        .requests()
        .iter()
        .filter(|q| q.method == "PUT" && q.target.contains("/manifests/"))
        .map(|q| q.target.rsplit('/').next().unwrap().to_string())
        .collect();
    assert_eq!(
        puts,
        vec![sha256(&amd.manifest), sha256(&arm.manifest), "v3".into()]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn resumes_after_a_lost_response_and_a_416() {
    let reg = registry();
    reg.with(|s| {
        // PATCH 2 stores its bytes but the answer is lost (500). PATCH 4 gets a 416.
        s.patch_500_after_store.insert(2);
        s.patch_416.insert(4);
    });
    let dir = temp_dir("resume");
    let input = dir.join("img");
    std::fs::create_dir_all(&input).unwrap();
    let img = image(&[4 * MIB + 5], 7);
    oci_layout(&input, &img);

    let r = push(&reg, &input, "v1", &["--chunk-size", "1"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_pushed(&reg, &img, "v1");
    let status_gets = reg
        .requests()
        .iter()
        .filter(|q| q.method == "GET" && q.target.contains("/blobs/uploads/"))
        .count();
    assert_eq!(status_gets, 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn gets_a_new_token_after_401_and_waits_after_429() {
    let reg = registry();
    reg.with(|s| {
        s.revoke_at.insert(3);
        s.throttle_at.insert(5);
    });
    let dir = temp_dir("token");
    let input = dir.join("img");
    std::fs::create_dir_all(&input).unwrap();
    let img = image(&[2 * MIB], 9);
    oci_layout(&input, &img);

    let r = push(&reg, &input, "v1", &["--chunk-size", "1"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_pushed(&reg, &img, "v1");
    assert_eq!(reg.with(|s| s.token_requests), 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn mounts_from_another_repository() {
    let reg = registry();
    let dir = temp_dir("mount");
    let input = dir.join("img");
    std::fs::create_dir_all(&input).unwrap();
    let img = image(&[3 * MIB], 11);
    oci_layout(&input, &img);
    let base = "acme/default/base";
    reg.with(|s| {
        s.blobs
            .insert((base.into(), sha256(&img.layers[0])), img.layers[0].clone());
    });

    let r = push(&reg, &input, "v1", &["--from", base]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_pushed(&reg, &img, "v1");
    assert!(r.stderr.contains("mounted"), "{}", r.stderr);
    let patched: u64 = reg
        .requests()
        .iter()
        .filter(|q| q.method == "PATCH")
        .map(|q| q.content_length.unwrap_or(0))
        .sum();
    assert_eq!(
        patched,
        img.config.len() as u64,
        "only the config is uploaded"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn refuses_a_corrupt_blob_before_upload() {
    let reg = registry();
    let dir = temp_dir("corrupt");
    let input = dir.join("img");
    std::fs::create_dir_all(&input).unwrap();
    let img = image(&[5000], 12);
    oci_layout(&input, &img);
    let p = input
        .join("blobs/sha256")
        .join(&sha256(&img.layers[0])[7..]);
    let mut bad = img.layers[0].clone();
    bad[100] ^= 1;
    std::fs::write(p, bad).unwrap();

    let r = push(&reg, &input, "v1", &[]);
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("does not match its digest"),
        "{}",
        r.stderr
    );
    assert!(reg.requests().iter().all(|q| q.method != "PATCH"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn never_sends_the_identity_to_another_realm() {
    let reg = registry();
    reg.with(|s| s.realm_override = Some("https://evil.test/token".into()));
    let dir = temp_dir("realm");
    let input = dir.join("img");
    std::fs::create_dir_all(&input).unwrap();
    oci_layout(&input, &image(&[10], 13));

    let r = push(&reg, &input, "v1", &[]);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("not at the Prego realm"), "{}", r.stderr);
    assert_eq!(reg.with(|s| s.token_requests), 0);
    assert!(reg.requests().iter().all(|q| q.authorization.is_none()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn input_and_reference_errors() {
    let reg = registry();
    let dir = temp_dir("errors");
    let input = dir.join("img");
    std::fs::create_dir_all(&input).unwrap();
    oci_layout(&input, &image(&[10], 14));
    let run = |args: &[&str], hosts: &str| {
        let out = Command::new(BIN)
            .args(args)
            .env_clear()
            .env("PREGO_TENANT", "acme")
            .env("PREGO_API_KEY", API_KEY)
            .env("PREGO_OCI_HOSTS", hosts)
            .env("HOME", &dir)
            .output()
            .unwrap();
        (
            out.status.code().unwrap(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let i = input.to_str().unwrap();
    let host = reg.host();

    let (code, err) = run(
        &["oci", "push", i, "registry.example.test/acme/d/a:1"],
        &host,
    );
    assert_eq!(code, 1);
    assert!(err.contains("is not a Prego OCI host"), "{err}");

    let (code, err) = run(&["oci", "push", i, &format!("{host}/other/d/a:1")], &host);
    assert_eq!(code, 1);
    assert!(err.contains("must start with the tenant `acme`"), "{err}");

    let (code, err) = run(
        &[
            "oci",
            "push",
            "/nonexistent/x",
            &format!("{host}/acme/d/a:1"),
        ],
        &host,
    );
    assert_eq!(code, 1);
    assert!(err.contains("does not exist"), "{err}");

    let gz = dir.join("img.tar.gz");
    std::fs::write(&gz, [0x1f, 0x8b, 8, 0]).unwrap();
    let (code, err) = run(
        &[
            "oci",
            "push",
            gz.to_str().unwrap(),
            &format!("{host}/acme/d/a:1"),
        ],
        &host,
    );
    assert_eq!(code, 1);
    assert!(err.contains("gunzip"), "{err}");

    // No request reached the registry.
    assert!(reg.requests().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn pushes_a_layer_above_95_mib_with_the_default_part_size() {
    let reg = MockRegistry::start(&format!("acme:{API_KEY}"), 5 * MIB);
    let dir = temp_dir("big");
    let input = dir.join("img");
    std::fs::create_dir_all(&input).unwrap();
    let size = 97 * MIB + 3;
    let img = image(&[size], 15);
    oci_layout(&input, &img);

    let r = push(&reg, &input, "big", &[]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_pushed(&reg, &img, "big");
    let patches: Vec<u64> = reg
        .requests()
        .iter()
        .filter(|q| q.method == "PATCH")
        .map(|q| q.content_length.unwrap())
        .collect();
    // The config (one small part), then the layer in parts of 64 MiB.
    assert_eq!(patches[1..], [64 * MIB, size - 64 * MIB]);
    assert!(patches.iter().all(|&n| n <= 95 * MIB));
    std::fs::remove_dir_all(&dir).unwrap();
}
