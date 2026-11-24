//! End-to-end tests for git source policy results retaining the repository, the
//! requested ref, and the precise commit from the lockfile.
//!
//! The tests use a local `file://` git repository so they can run offline.

use std::path::{Path, PathBuf};
use std::process::Command;

use cargo_deny::{Krates, sources, test_utils as tu};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "cargo-deny-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(cmd: &mut Command) -> String {
    let output = cmd.output().expect("failed to spawn command");
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Creates a local git repository with a single crate, and a consumer that
/// depends on it with an explicit `rev`. Returns the consumer's metadata plus
/// the resolved commit.
fn fixture(root: &Path) -> (serde_json::Value, String) {
    let dep = root.join("dep");
    std::fs::create_dir_all(dep.join("src")).unwrap();
    std::fs::write(
        dep.join("Cargo.toml"),
        "[package]\nname = \"git-dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(dep.join("src/lib.rs"), "").unwrap();

    for args in [
        &["init", "--initial-branch=main"][..],
        &["config", "user.email", "test@example.com"][..],
        &["config", "user.name", "Test"][..],
        &["add", "."][..],
        &["commit", "-m", "one"][..],
    ] {
        run(Command::new("git").arg("-C").arg(&dep).args(args));
    }
    let commit = run(Command::new("git")
        .arg("-C")
        .arg(&dep)
        .args(["rev-parse", "HEAD"]));
    let rev = &commit.trim()[..12];

    let consumer = root.join("consumer");
    std::fs::create_dir_all(consumer.join("src")).unwrap();
    std::fs::write(
        consumer.join("Cargo.toml"),
        format!(
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\ngit-dep = {{ git = \"file://{}\", rev = \"{rev}\" }}\n",
            dep.display()
        ),
    )
    .unwrap();
    std::fs::write(consumer.join("src/lib.rs"), "").unwrap();

    let cargo_home = root.join("cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()));
    cmd.args(["metadata", "--format-version", "1", "--manifest-path"])
        .arg(consumer.join("Cargo.toml"))
        .env("CARGO_HOME", &cargo_home);

    let metadata = serde_json::from_str(&run(&mut cmd)).unwrap();
    (metadata, commit.trim().to_owned())
}

fn krates(metadata: serde_json::Value) -> Krates {
    let metadata: krates::cm::Metadata = serde_json::from_value(metadata).unwrap();
    krates::Builder::new()
        .build_with_metadata(metadata, krates::NoneFilter)
        .unwrap()
}

fn check(krates: &Krates, cfg: impl Into<String>) -> Vec<serde_json::Value> {
    tu::gather_diagnostics::<sources::cfg::Config, _, _>(
        krates,
        "git-source-policy",
        tu::Config::new(cfg),
        |ctx, tx| sources::check(ctx, tx),
    )
}

fn codes(diags: &[serde_json::Value]) -> Vec<&str> {
    diags
        .iter()
        .filter_map(|d| d.pointer("/fields/code").and_then(|v| v.as_str()))
        .collect()
}

fn source_span(diags: &[serde_json::Value]) -> &str {
    diags
        .iter()
        .find_map(|d| {
            d.pointer("/fields/labels/0/span")
                .and_then(|v| v.as_str())
                .filter(|s| s.contains("git-dep") || s.contains("file://"))
        })
        .expect("no source label")
}

#[test]
fn allowed_git_source_retains_repo_ref_and_commit() {
    let root = TempDir::new("git-policy");
    let (metadata, commit) = fixture(root.path());
    let krates = krates(metadata);

    let allowed =
        cargo_deny::Url::parse(&format!("file://{}", root.path().join("dep").display())).unwrap();

    let cfg = format!(
        "unknown-registry = 'allow'\nunknown-git = 'allow'\nallow-git = [\"{allowed}\"]\nrequired-git-spec = 'rev'"
    );
    let diags = check(&krates, cfg);

    let codes = codes(&diags);
    // Explicitly allowed git dependencies must still be checked, even when
    // both unknown-* levels are `allow` (ie. no early return).
    assert!(
        codes.contains(&"allowed-source"),
        "allowed git source was not checked: {diags:#?}"
    );
    // The rev matches the locked commit, so there must be no mismatch.
    assert!(
        !codes.contains(&"git-source-commit-mismatch"),
        "valid rev was rejected: {diags:#?}"
    );

    let span = source_span(&diags);
    assert!(
        span.starts_with("git+file://") && span.ends_with(&format!("#{commit}")),
        "finding did not retain the repository and locked commit: {span}"
    );
    assert!(
        span.contains(&format!("?rev={}", &commit[..12])),
        "finding did not retain the requested ref: {span}"
    );
    assert!(
        span.contains(&root.path().join("dep").display().to_string()),
        "finding did not retain the repository: {span}"
    );
}

#[test]
fn git_source_commit_mismatch_is_reported() {
    let root = TempDir::new("git-policy-mismatch");
    let (mut metadata, commit) = fixture(root.path());

    // Simulate the lockfile and the requested rev belonging to different
    // generations. A real metadata file can also be this way when a cached
    // metadata/lock pair is reused after a ref moved.
    let fake = "1111111111111111111111111111111111111111";
    let real = format!("#{commit}");
    let fake_source = format!("#{fake}");
    for pkg in metadata["packages"].as_array_mut().unwrap() {
        if pkg["name"] == "git-dep" {
            for key in ["source", "id"] {
                if let Some(source) = pkg[key].as_str() {
                    pkg[key] = serde_json::Value::String(source.replace(&real, &fake_source));
                }
            }
        }
    }

    let krates = krates(metadata);
    let allowed =
        cargo_deny::Url::parse(&format!("file://{}", root.path().join("dep").display())).unwrap();
    let cfg = format!("unknown-git = 'deny'\nallow-git = [\"{allowed}\"]");
    let diags = check(&krates, cfg);

    let codes = codes(&diags);
    assert!(
        codes.contains(&"git-source-commit-mismatch"),
        "mismatched rev/commit was not reported: {diags:#?}"
    );
    assert!(
        codes.contains(&"allowed-source"),
        "explicitly allowed git source was skipped: {diags:#?}"
    );

    let span = source_span(&diags);
    assert!(
        span.contains(fake) && span.contains(&commit[..12]),
        "finding did not retain the requested ref and locked commit: {span}"
    );
}
