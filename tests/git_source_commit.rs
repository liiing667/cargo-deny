//! Tests for binding git dependency sources to their repository, ref, and the
//! precise commit cargo locked them to.
//!
//! These intentionally only use the crate's public API and the `git` cli so
//! they can run without network access.

use std::collections::BTreeMap;
use std::process::Command;

use cargo_deny::git::{self, FetchResult};
use cargo_deny::{Kid, Krate, PathBuf, Source, Url, Version};

fn krate_with_source(source: Source) -> Krate {
    Krate {
        name: "krates".to_owned(),
        id: Kid::default(),
        version: Version::new(0, 12, 6),
        source: Some(source),
        authors: Vec::new(),
        repository: None,
        description: None,
        manifest_path: PathBuf::new(),
        license: None,
        license_file: None,
        deps: Vec::new(),
        features: BTreeMap::new(),
        targets: Vec::new(),
        publish: None,
        rust_version: None,
    }
}

#[test]
fn git_source_identity_retains_locked_commit() {
    let raw = "git+https://github.com/EmbarkStudios/spdx?tag=0.7.0#c3e1a50787768a1df103ee93466986063bfb9122";
    let source = Source::from_metadata(raw.to_owned(), None).unwrap();
    let git = source.git().expect("git source");

    assert_eq!(
        git.commit(),
        Some("c3e1a50787768a1df103ee93466986063bfb9122")
    );
    assert_eq!(
        source.git_commit(),
        Some("c3e1a50787768a1df103ee93466986063bfb9122")
    );
    assert_eq!(git.spec(), cargo_deny::sources::cfg::GitSpec::Tag);
    assert_eq!(git.spec_value(), Some("0.7.0"));
    assert_eq!(git.identity(), raw);
    assert_eq!(source.to_string(), raw);

    // The commit is not part of the repository url used for matching.
    assert_eq!(
        git.url().as_str(),
        "https://github.com/EmbarkStudios/spdx?tag=0.7.0"
    );
    assert!(git.url().fragment().is_none());
}

#[test]
fn allow_git_still_matches_repository_not_commit() {
    let raw = "git+https://github.com/EmbarkStudios/krates?branch=main#6aa02ee69d69444c910f0ca04ccebb949d76e738";
    let source = Source::from_metadata(raw.to_owned(), None).unwrap();
    let krate = krate_with_source(source);

    // This is exactly how an `allow-git` entry is parsed/normalized.
    let allowed = Url::parse("https://github.com/EmbarkStudios/krates").unwrap();
    assert!(krate.matches_url(&allowed, true));

    // Matching is by repository, not by the specific branch or locked commit.
    let mut other_ref = Url::parse("https://github.com/EmbarkStudios/krates").unwrap();
    other_ref.set_query(Some("branch=other"));
    assert!(krate.matches_url(&other_ref, true));

    assert!(!krate.matches_url(
        &Url::parse("https://github.com/EmbarkStudios/krates-extra").unwrap(),
        true
    ));
}

#[test]
fn rev_must_match_locked_commit() {
    let source = Source::from_metadata(
        "git+https://github.com/EmbarkStudios/krates?rev=6aa02ee69d69#6aa02ee69d69444c910f0ca04ccebb949d76e738".to_owned(),
        None,
    )
    .unwrap();
    assert!(source.git().unwrap().rev_matches_commit());

    let source = Source::from_metadata(
        "git+https://github.com/EmbarkStudios/krates?rev=deadbeefdead#6aa02ee69d69444c910f0ca04ccebb949d76e738".to_owned(),
        None,
    )
    .unwrap();
    assert!(!source.git().unwrap().rev_matches_commit());

    // Non-hex revision expressions can't be verified offline and must not be
    // rejected just because they aren't a commit prefix.
    let source = Source::from_metadata(
        "git+https://github.com/EmbarkStudios/krates?rev=HEAD~1#6aa02ee69d69444c910f0ca04ccebb949d76e738".to_owned(),
        None,
    )
    .unwrap();
    assert!(source.git().unwrap().rev_matches_commit());
}

fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("failed to run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn temp_root() -> std::path::PathBuf {
    let unique = format!(
        "cargo-deny-git-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn fetch_repo_binds_and_preserves_commit() {
    let root = temp_root();
    let remote = root.join("remote.git");
    let work = root.join("work");
    let checkout = root.join("checkout");

    std::fs::create_dir_all(&work).unwrap();
    run_git(
        root.as_path(),
        &["init", "--bare", remote.to_str().unwrap()],
    );
    run_git(work.as_path(), &["init", "--initial-branch=main"]);
    run_git(
        work.as_path(),
        &["config", "user.email", "test@example.com"],
    );
    run_git(work.as_path(), &["config", "user.name", "Test"]);
    std::fs::write(work.join("file.txt"), "one").unwrap();
    run_git(work.as_path(), &["add", "."]);
    run_git(work.as_path(), &["commit", "-m", "one"]);
    run_git(
        work.as_path(),
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    run_git(work.as_path(), &["push", "-u", "origin", "main"]);
    let commit_one = run_git(work.as_path(), &["rev-parse", "HEAD"]);

    let checkout_path = cargo_deny::PathBuf::from_path_buf(checkout.clone()).unwrap();
    let res = git::fetch_repo(remote.to_str().unwrap(), &checkout_path, "main").unwrap();
    assert!(matches!(res, FetchResult::Cloned(_)));
    assert_eq!(res.commit(), commit_one);
    assert_eq!(
        git::head_commit(&checkout_path).unwrap().as_str(),
        commit_one
    );

    std::fs::write(work.join("file.txt"), "two").unwrap();
    run_git(work.as_path(), &["add", "."]);
    run_git(work.as_path(), &["commit", "-m", "two"]);
    run_git(work.as_path(), &["push", "origin", "main"]);
    let commit_two = run_git(work.as_path(), &["rev-parse", "HEAD"]);
    assert_ne!(commit_one, commit_two);

    let res = git::fetch_repo(remote.to_str().unwrap(), &checkout_path, "main").unwrap();
    assert!(matches!(res, FetchResult::Fetched(_)));
    assert_eq!(res.commit(), commit_two);
    assert_eq!(
        git::head_commit(&checkout_path).unwrap().as_str(),
        commit_two
    );

    // A failed fetch must not move the checkout to a different generation.
    std::fs::rename(&remote, root.join("remote-gone.git")).unwrap();
    assert!(git::fetch_repo(remote.to_str().unwrap(), &checkout_path, "main").is_err());
    assert_eq!(
        git::head_commit(&checkout_path).unwrap().as_str(),
        commit_two
    );
}

#[test]
fn failed_clone_leaves_no_partial_repository() {
    let root = temp_root();
    let checkout = root.join("checkout");

    let checkout_path = cargo_deny::PathBuf::from_path_buf(checkout.clone()).unwrap();
    assert!(
        git::fetch_repo(
            root.join("does-not-exist").to_str().unwrap(),
            &checkout_path,
            "main"
        )
        .is_err()
    );
    assert!(!checkout.exists());

    for entry in std::fs::read_dir(&root).unwrap() {
        let entry = entry.unwrap();
        assert!(
            !entry.file_name().to_string_lossy().contains(".tmp-"),
            "left a temporary clone behind: {:?}",
            entry.path()
        );
    }
}
