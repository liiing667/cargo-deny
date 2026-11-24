use cargo_deny::diag::{Check, Pack};
use cargo_deny::test_utils::*;
use cargo_deny::{assert_field_eq, field_eq};

fn gather(config: &str) -> Vec<serde_json::Value> {
    gather_bans(
        "uid39098_build_identity",
        KrateGather {
            name: "uid39098-script-identity",
            targets: &["x86_64-unknown-linux-gnu"],
            ..Default::default()
        },
        Config::new(config),
    )
}

#[test]
fn build_check_info_exposes_real_script_and_crate_identity() {
    let krates = KrateGather {
        name: "uid39098-script-identity",
        targets: &["x86_64-unknown-linux-gnu"],
        ..Default::default()
    }
    .gather();
    let config = Config::new(
        r#"
[build]
include-workspace = true
allow-build-scripts = ["uid39098-script-identity"]
executables = "allow"
"#,
    );
    let ctx = setup::<cargo_deny::bans::cfg::Config, cargo_deny::bans::cfg::ValidConfig>(
        &krates,
        "script_identity_api",
        config,
    );
    let valid = &ctx.valid_cfg;
    let build = valid.build.as_ref().expect("build config should be valid");
    let krate = krates
        .krates()
        .find(|k| k.name == "uid39098-script-identity")
        .expect("test crate should be in graph");
    let mut pack = Pack::with_kid(Check::Bans, krate.id.clone());

    let info = cargo_deny::bans::check_build(valid.file_id, build, None, krate, &krates, &mut pack);

    let identity = info
        .script_identity()
        .expect("custom build target should have a script identity");
    assert_eq!(identity.name(), "uid39098-script-identity");
    assert_eq!(identity.version(), "0.1.0");
    assert!(identity.source().starts_with("path+file://"));
    assert!(
        identity
            .path()
            .expect("script path should be present")
            .as_str()
            .ends_with("builder/main.rs")
    );
    assert_eq!(
        identity
            .checksum()
            .expect("script should be hashed")
            .to_string(),
        "536e506bb90914c243a12b397b9a998f85ae2cbd9ba02dfd03a9e155ca5ca0f4"
    );
}

#[test]
fn allowed_script_identity_and_stale_path_glob_are_evidenced() {
    let diags = gather(
        r#"
[build]
include-workspace = true
allow-build-scripts = ["uid39098-script-identity"]
executables = "allow"

[[build.bypass]]
name = "uid39098-script-identity"
allow = [{ path = "missing.sh" }]
allow-globs = ["missing/**"]
"#,
    );

    let path_miss = diags
        .iter()
        .find(|d| field_eq!(d, "/fields/code", "unmatched-path-bypass"))
        .expect("path whitelist miss should leave evidence");
    assert_field_eq!(
        path_miss,
        "/fields/graphs/0/Krate/name",
        "uid39098-script-identity"
    );

    let glob_miss = diags
        .iter()
        .find(|d| field_eq!(d, "/fields/code", "unmatched-glob"))
        .expect("glob whitelist miss should leave evidence");
    assert_field_eq!(
        glob_miss,
        "/fields/graphs/0/Krate/name",
        "uid39098-script-identity"
    );

    assert!(
        !diags
            .iter()
            .any(|d| field_eq!(d, "/fields/code", "build-script-not-allowed")),
        "ordinary allowed script should not be denied: {diags:#?}"
    );
    assert!(
        !diags
            .iter()
            .any(|d| field_eq!(d, "/fields/code", "detected-executable")),
        "executables = allow should retain ordinary allowed behavior: {diags:#?}"
    );
}

#[test]
fn unmatched_bypass_reports_nested_path_and_glob_evidence() {
    let diags = gather(
        r#"
[[build.bypass]]
name = "absent-identity-crate"
allow = [{ path = "missing.sh" }]
allow-globs = ["missing/**"]
"#,
    );

    assert!(
        diags
            .iter()
            .any(|d| field_eq!(d, "/fields/code", "unmatched-bypass")),
        "missing bypass should be reported: {diags:#?}"
    );

    let path_miss = diags
        .iter()
        .find(|d| field_eq!(d, "/fields/code", "unmatched-path-bypass"))
        .expect("nested path miss should be reported");
    assert_field_eq!(
        path_miss,
        "/fields/notes/0",
        "bypass crate = 'absent-identity-crate'"
    );

    let glob_miss = diags
        .iter()
        .find(|d| field_eq!(d, "/fields/code", "unmatched-glob"))
        .expect("nested glob miss should be reported");
    assert_field_eq!(
        glob_miss,
        "/fields/notes/0",
        "bypass crate = 'absent-identity-crate'"
    );
}

#[test]
fn ordinary_allowed_script_can_still_be_checksum_checked() {
    let diags = gather(
        r#"
[build]
include-workspace = true
allow-build-scripts = ["uid39098-script-identity"]
executables = "allow"

[[build.bypass]]
name = "uid39098-script-identity"
build-script = "536e506bb90914c243a12b397b9a998f85ae2cbd9ba02dfd03a9e155ca5ca0f4"
"#,
    );

    let m = diags
        .iter()
        .find(|d| field_eq!(d, "/fields/code", "checksum-match"))
        .expect("allowed script should still be checksum checked");
    assert_field_eq!(m, "/fields/graphs/0/Krate/name", "uid39098-script-identity");
    assert!(
        !diags
            .iter()
            .any(|d| field_eq!(d, "/fields/code", "build-script-not-allowed")),
        "allowed script should not be denied: {diags:#?}"
    );
}

#[test]
fn stale_checksum_on_otherwise_allowed_script_leaves_mismatch_evidence() {
    let diags = gather(
        r#"
[build]
include-workspace = true
allow-build-scripts = ["uid39098-script-identity"]
executables = "allow"

[[build.bypass]]
name = "uid39098-script-identity"
build-script = "00abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef00"
"#,
    );

    let mismatch = diags
        .iter()
        .find(|d| field_eq!(d, "/fields/code", "checksum-mismatch"))
        .expect("stale script checksum should be reported");
    assert_field_eq!(
        mismatch,
        "/fields/graphs/0/Krate/name",
        "uid39098-script-identity"
    );
    assert!(
        !diags
            .iter()
            .any(|d| field_eq!(d, "/fields/code", "build-script-not-allowed")),
        "crate-level allowance should remain valid while stale script evidence is reported: {diags:#?}"
    );
}

#[test]
fn trusted_checksum_still_reports_unmatched_glob_evidence() {
    let diags = gather(
        r#"
[build]
include-workspace = true

[[build.bypass]]
name = "uid39098-script-identity"
build-script = "536e506bb90914c243a12b397b9a998f85ae2cbd9ba02dfd03a9e155ca5ca0f4"
allow-globs = ["missing/**"]
"#,
    );

    let glob_miss = diags
        .iter()
        .find(|d| field_eq!(d, "/fields/code", "unmatched-glob"))
        .expect("unmatched glob should still leave evidence");
    assert_field_eq!(
        glob_miss,
        "/fields/graphs/0/Krate/name",
        "uid39098-script-identity"
    );
    assert!(
        !diags
            .iter()
            .any(|d| field_eq!(d, "/fields/code", "build-script-not-allowed")),
        "matching checksum bypass should retain its existing trust behavior: {diags:#?}"
    );
}
