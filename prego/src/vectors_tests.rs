//! The shared test vectors of ADR-0061 and ADR-0062 (`tests/vectors/{signing,keys,a2a}/`, copied as data from
//! the Prego monorepo, with their READMEs). Every case runs against the client code: JCS, RFC 7638
//! thumbprints, signed-set payloads, JWS verify rules, the key entry parsers and the private-material check,
//! the key version hash, the A2A card rule, the 0.3 detection, card and set signatures, and the upgrade.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::Value;

use crate::a2a::{self, card, upgrade};
use crate::env::jcs;
use crate::keys::entry::{self, EntryType};
use crate::sign::jwk::PublicJwk;
use crate::sign::jws::{self, code, Header};
use crate::snippet::reference::SnipRef;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn load(rel: &str) -> Value {
    let p = dir().join(rel);
    serde_json::from_slice(&std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
        .unwrap()
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// A resolver over a list of public JWKs (the keys of a case): by thumbprint.
fn resolver(keys: &Value) -> impl FnMut(&Header) -> Result<PublicJwk, String> {
    let list: Vec<PublicJwk> = keys
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|k| PublicJwk::from_json(k).ok())
        .collect();
    move |h: &Header| {
        list.iter()
            .find(|k| k.thumbprint() == h.kid)
            .cloned()
            .ok_or_else(|| format!("key_not_found: no key with thumbprint {}", h.kid))
    }
}

/// The verify codes that the signing README lets a verifier report for each reason.
fn accepted(reason: &str) -> &'static [&'static str] {
    match reason {
        "wrong_key" | "payload_changed" | "signature_truncated" | "bad_signature" => &[
            "bad_signature",
            "wrong_key",
            "payload_changed",
            "signature_truncated",
        ],
        "payload_mismatch" => &["payload_mismatch", "payload_changed"],
        _ => &[],
    }
}

fn reason_ok(want: &str, got: &str) -> bool {
    want == got || accepted(want).contains(&got)
}

// ---- signing/ ----

#[test]
fn signing_jcs() {
    for c in load("signing/jcs.json").as_array().unwrap() {
        let v: Value = serde_json::from_str(text(&c["input_text"])).unwrap();
        assert_eq!(
            jcs::canonical(&v).unwrap(),
            text(&c["canonical"]),
            "{}",
            c["name"]
        );
    }
}

#[test]
fn signing_thumbprints() {
    for c in load("signing/thumbprint.json").as_array().unwrap() {
        let k = PublicJwk::from_json(&c["jwk"]).unwrap_or_else(|e| panic!("{}: {e}", c["name"]));
        assert_eq!(k.thumbprint(), text(&c["thumbprint"]), "{}", c["name"]);
    }
}

#[test]
fn signing_payloads() {
    for c in load("signing/payload.json").as_array().unwrap() {
        let s = &c["set"];
        let files: Vec<(String, String)> = s["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| (text(&f["path"]).to_string(), text(&f["sha256"]).to_string()))
            .collect();
        let p = jws::set_payload(
            text(&s["type"]),
            text(&s["tenant"]),
            text(&s["namespace"]),
            text(&s["name"]),
            text(&s["hash"]),
            &files,
        );
        assert_eq!(
            String::from_utf8(p.clone()).unwrap(),
            text(&c["canonical"]),
            "{}",
            c["name"]
        );
        assert_eq!(
            crate::snippet::files::hex_sha256(&p),
            text(&c["sha256"]),
            "{}",
            c["name"]
        );
    }
}

#[test]
fn signing_jws() {
    for c in load("signing/jws.json").as_array().unwrap() {
        let name = text(&c["name"]);
        let mut r = resolver(&c["keys"]);
        let got = jws::verify_set(&c["jws"], text(&c["payload"]).as_bytes(), &mut r);
        match (text(&c["expect"]), got) {
            ("valid", Ok(_)) => {}
            ("invalid", Err(e)) => {
                let want = text(&c["reason"]);
                assert!(reason_ok(want, code(&e)), "{name}: want {want}, got {e}");
            }
            (want, got) => panic!("{name}: want {want}, got {got:?}"),
        }
    }
}

// ---- keys/ ----

fn entry_bytes(c: &Value) -> Vec<u8> {
    match text(&c["encoding"]) {
        "base64" => STANDARD.decode(text(&c["content"])).unwrap(),
        _ => text(&c["content"]).as_bytes().to_vec(),
    }
}

#[test]
fn keys_valid_entries() {
    let now = entry::now_text();
    for c in load("keys/cases.json")["valid"].as_array().unwrap() {
        let name = text(&c["name"]);
        let bytes = entry_bytes(c);
        assert_eq!(entry::private_material(&bytes, ""), None, "{name}");
        let t = EntryType::parse(text(&c["type"])).unwrap();
        let infos = entry::inspect(t, &bytes, &now).unwrap_or_else(|e| panic!("{name}: {e}"));
        let e = &c["entry"];
        let want: Vec<&Value> = match e["keys"].as_array() {
            Some(keys) => keys.iter().collect(),
            None if e["certs"].is_array() => e["certs"].as_array().unwrap().iter().collect(),
            None => vec![e],
        };
        assert_eq!(infos.len(), want.len(), "{name}");
        for (i, w) in infos.iter().zip(want) {
            assert_eq!(i.fingerprint, text(&w["fingerprint"]), "{name}");
            if let Some(alg) = w["alg"].as_str() {
                assert_eq!(i.alg, alg, "{name}");
            }
            if let Some(x) = w["expired"].as_bool() {
                assert_eq!(i.expired, x, "{name}");
            }
        }
    }
}

#[test]
fn keys_invalid_entries() {
    let now = entry::now_text();
    for c in load("keys/cases.json")["invalid"].as_array().unwrap() {
        let name = text(&c["name"]);
        let bytes = entry_bytes(c);
        assert_eq!(entry::private_material(&bytes, ""), None, "{name}");
        let t = EntryType::parse(text(&c["type"])).unwrap();
        let e = entry::inspect(t, &bytes, &now)
            .err()
            .unwrap_or_else(|| panic!("{name}: passed"));
        assert_eq!(e, text(&c["reason"]), "{name}");
    }
}

#[test]
fn keys_private_material() {
    for c in load("keys/cases.json")["private_material"]
        .as_array()
        .unwrap()
    {
        let name = text(&c["name"]);
        let entries: Vec<Value> = match c["entries"].as_array() {
            Some(list) => list.clone(),
            None => vec![c.clone()],
        };
        let found = entries
            .iter()
            .enumerate()
            .find_map(|(i, e)| entry::private_material(&entry_bytes(e), "").map(|p| (i, p)));
        let (index, p) = found.unwrap_or_else(|| panic!("{name}: not found"));
        assert_eq!(index as u64, c["index"].as_u64().unwrap(), "{name}");
        assert_eq!(p.kind, text(&c["kind"]), "{name}");
        assert_eq!(
            entry::private_message(index, &p),
            text(&c["message"]),
            "{name}"
        );
    }
}

#[test]
fn keys_version_hashes() {
    for c in load("keys/cases.json")["version_hashes"]
        .as_array()
        .unwrap()
    {
        let list: Vec<(EntryType, Vec<u8>)> = c["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (EntryType::parse(text(&e["type"])).unwrap(), entry_bytes(e)))
            .collect();
        assert_eq!(
            entry::version_hash(&list),
            text(&c["hash"]),
            "{}",
            c["name"]
        );
    }
}

// ---- a2a/ ----

fn card_file(file: &str) -> Vec<u8> {
    std::fs::read(dir().join("a2a/cards").join(file)).unwrap()
}

#[test]
fn a2a_field_table_is_the_pinned_proto() {
    let v = load("a2a/card-fields.json");
    let mut want = Vec::new();
    for (m, body) in v["messages"].as_object().unwrap() {
        for f in body["fields"].as_array().unwrap() {
            want.push((
                m.clone(),
                text(&f["json"]).to_string(),
                f["required"] == true,
                f["optional"] == true,
                f["repeated"] == true,
                f["oneof"].as_str().map(str::to_string),
            ));
        }
    }
    let mut got: Vec<_> = card::table()
        .into_iter()
        .map(|(m, j, r, o, rep, one)| {
            (
                m.to_string(),
                j.to_string(),
                r,
                o,
                rep,
                one.map(str::to_string),
            )
        })
        .collect();
    want.sort();
    got.sort();
    assert_eq!(got, want);
}

#[test]
fn a2a_card_rule() {
    let cases = load("a2a/cases.json");
    for c in cases["valid"].as_array().unwrap() {
        let v: Value = serde_json::from_slice(&card_file(text(&c["file"]))).unwrap();
        card::check(&v).unwrap_or_else(|p| panic!("{}: {p:?}", c["name"]));
    }
    for c in cases["invalid"].as_array().unwrap() {
        let got = match serde_json::from_slice::<Value>(&card_file(text(&c["file"]))) {
            Err(_) => ("".to_string(), "not valid JSON".to_string()),
            Ok(v) => match card::check(&v) {
                Err(card::Problem::Invalid { path, reason }) => (path, reason),
                other => panic!("{}: {other:?}", c["name"]),
            },
        };
        assert_eq!(
            got,
            (text(&c["path"]).to_string(), text(&c["reason"]).to_string()),
            "{}",
            c["name"]
        );
    }
    for c in cases["v03"].as_array().unwrap() {
        let file = text(&c["file"]);
        let v: Value = serde_json::from_slice(&card_file(file)).unwrap();
        let p = card::check(&v).err().unwrap();
        assert_eq!(
            p,
            card::Problem::V03(text(&c["reason"]).to_string()),
            "{}",
            c["name"]
        );
        // The message names the card file of the push; the vectors use the file name.
        assert_eq!(p.message(file), text(&c["message"]), "{}", c["name"]);
    }
}

#[test]
fn a2a_card_signatures() {
    for c in load("a2a/cases.json")["signed"].as_array().unwrap() {
        let name = text(&c["name"]);
        let v: Value = serde_json::from_slice(&card_file(text(&c["file"]))).unwrap();
        let input = card::signing_input(&v).unwrap();
        if name != "changed-after-signing" && name != "defaults-not-removed" {
            assert_eq!(
                String::from_utf8(input.clone()).unwrap(),
                text(&c["signing_input"]),
                "{name}"
            );
        }
        let push = &c["push"];
        let result: Result<(), (String, String)> = (|| {
            if let Some((t, ns, s)) = card::source(&v) {
                if (t.as_str(), ns.as_str(), s.as_str())
                    != (
                        text(&push["tenant"]),
                        text(&push["namespace"]),
                        text(&push["set"]),
                    )
                {
                    return Err(("source_mismatch".into(), String::new()));
                }
            }
            let sigs = v["signatures"].as_array().cloned().unwrap_or_default();
            if sigs.is_empty() {
                return Err(("signature_required".into(), String::new()));
            }
            let mut r = resolver(&c["keys"]);
            let mut last = String::new();
            for s in &sigs {
                let res = jws::card_header(s)
                    .and_then(|h| r(&h))
                    .and_then(|k| jws::verify_card(&input, s, &k));
                match res {
                    Ok(_) => return Ok(()),
                    Err(e) => last = e,
                }
            }
            Err(("signature_invalid".into(), code(&last).to_string()))
        })();
        match (text(&c["expect"]), result) {
            ("valid", Ok(())) => {}
            ("invalid", Err((err, reason))) => {
                assert_eq!(err, text(&c["error"]), "{name}");
                if let Some(want) = c["reason"].as_str() {
                    assert!(
                        reason_ok(want, &reason),
                        "{name}: want {want}, got {reason}"
                    );
                }
            }
            (want, got) => panic!("{name}: want {want}, got {got:?}"),
        }
    }
}

#[test]
fn a2a_sets() {
    for c in load("a2a/cases.json")["sets"].as_array().unwrap() {
        let name = text(&c["name"]);
        let d = dir().join("a2a").join(text(&c["dir"]));
        let cards: Vec<(String, Vec<u8>)> = c["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| (text(f).to_string(), std::fs::read(d.join(text(f))).unwrap()))
            .collect();
        let push = &c["push"];
        let r = SnipRef {
            tenant: text(&push["tenant"]).into(),
            namespace: text(&push["namespace"]).into(),
            name: text(&push["set"]).into(),
            version: None,
        };
        let (hash, payload) = a2a::hash_and_payload(&r, &cards).unwrap();
        assert_eq!(hash, text(&c["hash"]), "{name}");
        if name != "set-signed-for-other-set" {
            assert_eq!(
                String::from_utf8(payload.clone()).unwrap(),
                text(&c["set_payload"]),
                "{name}"
            );
        }
        let result = match c["set_jws"].as_str() {
            None => Err("signature_required".to_string()),
            Some(p) => {
                let sig: Value =
                    serde_json::from_slice(&std::fs::read(dir().join("a2a").join(p)).unwrap())
                        .unwrap();
                let mut res = resolver(&c["keys"]);
                jws::verify_set(&sig, &payload, &mut res)
                    .map(|_| ())
                    .map_err(|e| code(&e).to_string())
            }
        };
        match (text(&c["expect"]), result) {
            ("valid", Ok(())) => {}
            ("invalid", Err(e)) if text(&c["error"]) == "signature_required" => {
                assert_eq!(e, "signature_required", "{name}")
            }
            ("invalid", Err(e)) => assert!(reason_ok(text(&c["reason"]), &e), "{name}: {e}"),
            (want, got) => panic!("{name}: want {want}, got {got:?}"),
        }
    }
}

#[test]
fn a2a_upgrade() {
    for c in load("a2a/cases.json")["upgrade"].as_array().unwrap() {
        let name = text(&c["name"]);
        assert_eq!(text(&c["default_out_file"]), "agent-card.json", "{name}");
        let input: Value =
            serde_json::from_slice(&std::fs::read(dir().join("a2a").join(text(&c["in"]))).unwrap())
                .unwrap();
        match (upgrade::upgrade(&input), c["error"].is_null()) {
            (Ok(u), true) => {
                let want: Value = serde_json::from_slice(
                    &std::fs::read(dir().join("a2a").join(text(&c["out"]))).unwrap(),
                )
                .unwrap();
                assert_eq!(u.card, want, "{name}");
                card::check(&u.card).unwrap();
            }
            (Err(s), false) => {
                assert_eq!(s.field, text(&c["error"]["field"]), "{name}");
                assert_eq!(s.reason, text(&c["error"]["reason"]), "{name}");
            }
            (got, _) => panic!("{name}: {:?}", got.map(|u| u.card)),
        }
    }
}
