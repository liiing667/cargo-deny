//! Functionality for cloning, fetching and getting timestamps via `git`
//!
//! We explicitly use `git` since it's almost certainly available on the machine running cargo-deny, and the usage isn't
//! enough to warrant pulling in a library dependency
//!
//! - `git2`
//!   - C/unsafe/etc
//!   - large
//!   - slow compile time
//! - `gix`
//!   - extremely frequent version bumps
//!   - very large with many sub-crates, many dependencies, often brings in multiple versions
//!   - slow compile time

use crate::Path;
use anyhow::Context;
use std::{
    fs,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

/// Used to ensure that temporary repositories created by concurrent
/// cargo-deny processes never collide.
static TEMP_REPO_ID: AtomicU64 = AtomicU64::new(0);

/// Runs a git command, capturing its output
pub fn capture(mut cmd: Command) -> anyhow::Result<String> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = cmd
        // We need to clear the environment to avoid things like pre-commit hooks influencing where the advisory db
        // is located https://git-scm.com/book/en/v2/Git-Internals-Environment-Variables
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .spawn()
        .context("failed to spawn git")?
        .wait_with_output()
        .context("failed to wait on git output")?;

    if output.status.success() {
        String::from_utf8(output.stdout)
            .or_else(|_err| Ok("git command succeeded but gave non-utf8 output".to_owned()))
    } else {
        let args: Vec<_> = cmd.get_args().collect();
        match String::from_utf8(output.stderr) {
            Ok(err) => {
                anyhow::bail!("{args:?}\n{err}");
            }
            Err(_err) => {
                anyhow::bail!("{args:?}\ngit command failed and gave non-utf8 output");
            }
        }
    }
}

/// Attempts to determine the timestamp of the last fully applied fetch
/// (`FETCH_HEAD`)
///
/// If `FETCH_HEAD` doesn't correspond to the checked out generation, or is
/// unavailable, attempts to fallback to the timestamp of `HEAD`
pub fn get_fetch_time(repo: &Path) -> anyhow::Result<jiff::Timestamp> {
    let path = repo.join(".git");
    let file_timestamp = |name: &str| -> anyhow::Result<jiff::Timestamp> {
        let path = path.join(name);
        let attr =
            fs::metadata(path).with_context(|| format!("failed to get '{name}' metadata"))?;
        attr.modified()
            .with_context(|| format!("failed to get '{name}' modification time"))?
            .try_into()
            .with_context(|| format!("failed to convert file timestamp for '{name}'"))
    };

    let commit_timestamp = || -> anyhow::Result<jiff::Timestamp> {
        let mut cmd = Command::new("git");
        cmd.arg("-C")
            .arg(repo)
            .args(["show", "-s", "--format=%cI", "HEAD"]);

        let ts = capture(cmd).context("failed to get HEAD timestamp")?;
        ts.trim()
            .parse()
            .with_context(|| format!("failed to parse ISO-8601 timestamp '{}'", ts.trim()))
    };

    let fetch_head = path.join("FETCH_HEAD");
    let timestamp = match fs::read_to_string(&fetch_head) {
        Ok(contents) if fetch_head_is_complete(repo, &contents) => {
            // The fetch was applied successfully, so the FETCH_HEAD
            // modification time is the completion time of this generation.
            file_timestamp("FETCH_HEAD")?
        }
        Ok(_) => {
            // FETCH_HEAD was written by a fetch that was not fully applied,
            // meaning the checkout is still the previous generation. Use the
            // time of the checkout, not the newer FETCH_HEAD modification
            // time, so that a failed update isn't reported as a successful one.
            log::debug!(
                "FETCH_HEAD does not describe the checked out advisory database generation"
            );
            file_timestamp("HEAD").or_else(|_| commit_timestamp())?
        }
        Err(fh_err) => {
            // If we can't get the mod time of the FETCH_HEAD file, fallback
            // to getting the timestamp of the head commit. However, this
            // is not as good as FETCH_HEAD mod time since a database could
            // have been fetched within the time window, but the HEAD at that
            // time was out of the time window
            //
            // However, to mitigate this problem, we use the HEAD time if it is
            // newer than the commit time, as a fresh clone with git will NOT
            // have the FETCH_HEAD, but the fresh clone will have just written
            // HEAD and thus can be used as a fallback, but still defer to head
            // if something weird has happened
            match commit_timestamp() {
                Ok(commit_ts) => {
                    let file_head_ts = file_timestamp("HEAD").unwrap_or_default();
                    std::cmp::max(commit_ts, file_head_ts)
                }
                Err(hc_err) => {
                    return Err(hc_err).context(fh_err);
                }
            }
        }
    };

    Ok(timestamp)
}

/// Returns true if `FETCH_HEAD` points to the currently checked out commit and
/// the working tree and index are clean.
///
/// A fetch can write `FETCH_HEAD` and update refs before failing to reset the
/// checkout. In that state the database still contains the previous complete
/// generation, so the `FETCH_HEAD` modification time must not be used as the
/// time the database was last updated.
fn fetch_head_is_complete(repo: &Path, contents: &str) -> bool {
    let Ok(head) = git(repo, &["rev-parse", "HEAD"]) else {
        return false;
    };
    let head = head.trim();

    if !contents.split_whitespace().any(|token| token == head) {
        return false;
    }

    match git(repo, &["status", "--porcelain"]) {
        Ok(status) => status.trim().is_empty(),
        Err(_) => false,
    }
}

#[derive(Debug)]
pub enum FetchResult {
    /// The repo was fetched
    Fetched,
    /// The repo was cloned
    Cloned,
}

impl std::fmt::Display for FetchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetched => f.write_str("fetched"),
            Self::Cloned => f.write_str("cloned"),
        }
    }
}

/// Runs a git command inside of `repo`
fn git(repo: &Path, args: &[&str]) -> anyhow::Result<String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).args(args);

    capture(cmd)
}

/// Creates a unique temporary path next to `repo_path`, on the same file
/// system so that it can be renamed into place atomically.
fn temp_repo_path(repo_path: &Path, kind: &str) -> anyhow::Result<crate::PathBuf> {
    let parent = repo_path
        .parent()
        .with_context(|| format!("invalid directory: {repo_path}"))?;
    let name = repo_path
        .file_name()
        .with_context(|| format!("invalid directory: {repo_path}"))?;

    let pid = std::process::id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    // The id alone is enough for a single process, the timestamp handles
    // processes that have reused a pid, and the path is checked so that a
    // process that crashed while updating doesn't cause us to reuse its
    // partially updated directory.
    for _ in 0..100 {
        let id = TEMP_REPO_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{name}.{kind}-{pid}-{now}-{id}"));

        if !candidate.exists() {
            return Ok(candidate);
        }
    }

    anyhow::bail!("unable to create a temporary path for '{repo_path}'")
}

fn clone_repo(url: &str, repo_path: &Path, branch: &str) -> anyhow::Result<FetchResult> {
    let mut cmd = Command::new("git");
    cmd.args(["clone", "--depth=1", "--branch", branch])
        .arg(url)
        .arg(repo_path);

    capture(cmd).with_context(|| format!("failed to clone '{url}' into '{repo_path}'"))?;

    Ok(FetchResult::Cloned)
}

/// Returns the git directory for `repo_path`, if it is a valid repository.
fn git_dir(repo_path: &Path) -> Option<crate::PathBuf> {
    let dir = git(repo_path, &["rev-parse", "--git-dir"]).ok()?;
    let dir = crate::PathBuf::from(dir.trim());

    Some(if dir.is_absolute() {
        dir
    } else {
        repo_path.join(dir)
    })
}

/// Refuse to update a repository that another git process is currently
/// mutating. Without this, a stale lock would be invisible to the staging
/// clone and we could replace the live database while the other process still
/// assumes it has exclusive access.
fn ensure_not_locked(repo_path: &Path, branch: &str) -> anyhow::Result<()> {
    let Some(git_dir) = git_dir(repo_path) else {
        return Ok(());
    };

    for lock in [
        "index.lock",
        "HEAD.lock",
        "FETCH_HEAD.lock",
        "packed-refs.lock",
    ] {
        let lock_path = git_dir.join(lock);
        anyhow::ensure!(
            !lock_path.exists(),
            "advisory database repository '{repo_path}' is locked by another git process ('{lock_path}')"
        );
    }

    let branch_lock = git_dir
        .join("refs")
        .join("heads")
        .join(format!("{branch}.lock"));
    anyhow::ensure!(
        !branch_lock.exists(),
        "advisory database repository '{repo_path}' is locked by another git process ('{branch_lock}')"
    );

    Ok(())
}

fn fetch_repo_in_place(
    url: &str,
    repo_path: &Path,
    staging: &Path,
    branch: &str,
) -> anyhow::Result<FetchResult> {
    // Copy the currently installed generation into a staging directory. This
    // is a local clone, so the objects from the existing generation are
    // reused, but the live database is never mutated, meaning a failed fetch
    // or reset can't leave it in a half updated state, and an existing offline
    // cache remains usable.
    let mut cmd = Command::new("git");
    cmd.args(["clone", "--local"]).arg(repo_path).arg(staging);

    match capture(cmd) {
        Ok(_) => {}
        Err(err) => {
            // The existing directory may not be a valid repository, for example
            // if a previous version of cargo-deny was killed while cloning it.
            // In that case just start from a fresh clone of the remote.
            log::debug!(
                "failed to copy existing advisory database '{repo_path}', cloning '{url}' instead: {err:#}"
            );

            if let Err(cleanup_err) = fs::remove_dir_all(staging)
                && staging.exists()
            {
                log::debug!(
                    "failed to remove temporary advisory database '{}': {cleanup_err}",
                    staging
                );
            }

            clone_repo(url, staging, branch)?;
            return Ok(FetchResult::Fetched);
        }
    }

    // A local clone points its origin at the local directory, so make sure the
    // staging repository fetches from the actual remote.
    if git(staging, &["remote", "set-url", "origin", url]).is_err() {
        git(staging, &["remote", "add", "origin", url])
            .context("failed to set the advisory database remote")?;
    }

    let rspec = format!("+{branch}:{branch}");

    // Pull the latest changes into the staging directory
    git(staging, &["fetch", "--depth=1", "-u", "origin", &rspec])
        .context("failed to fetch latest changes")?;

    // Reset the staging directory to the remote HEAD
    git(staging, &["reset", "--hard", "FETCH_HEAD"]).context("failed to reset to FETCH_HEAD")?;

    Ok(FetchResult::Fetched)
}

/// Replaces `repo_path` with the fully prepared `staging` repository.
///
/// The previous generation is only removed after the new generation has been
/// successfully moved into place, and is restored if the move fails.
fn install_staging(staging: &Path, repo_path: &Path, repo_existed: bool) -> anyhow::Result<()> {
    if !repo_existed {
        return fs::rename(staging, repo_path)
            .with_context(|| format!("failed to install advisory database at '{repo_path}'"));
    }

    let previous = temp_repo_path(repo_path, "previous")?;

    fs::rename(repo_path, &previous).with_context(|| {
        format!("failed to move the previous advisory database generation '{repo_path}'")
    })?;

    match fs::rename(staging, repo_path) {
        Ok(()) => {
            if let Err(err) = fs::remove_dir_all(&previous) {
                log::warn!(
                    "failed to remove previous advisory database generation '{}': {err}",
                    previous
                );
            }

            Ok(())
        }
        Err(err) => {
            // Try to put the previous complete generation back. If this also
            // fails there isn't anything else we can do, but report both errors
            // so the user knows the database needs to be repaired.
            match fs::rename(&previous, repo_path) {
                Ok(()) => Err(err).with_context(|| {
                    format!("failed to install advisory database at '{repo_path}'")
                }),
                Err(restore_err) => Err(err).context(format!(
                    "failed to install advisory database at '{repo_path}', and failed to restore the previous generation from '{}': {restore_err}",
                    previous
                )),
            }
        }
    }
}

/// Attempts to clone or fetch a remote repo into the specified path
///
/// Updates are performed in a staging directory that is only moved into place
/// once the repository has been fully updated. A failure at any point leaves
/// the previous complete generation untouched so that offline checks can still
/// use it and a subsequent scan can never observe a half updated repository.
pub fn fetch_repo(url: &str, repo_path: &Path, branch: &str) -> anyhow::Result<FetchResult> {
    if let Some(parent) = repo_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create advisory database directory {parent}"))?;
    } else {
        anyhow::bail!("invalid directory: {repo_path}");
    }

    let repo_existed = repo_path.exists();

    if repo_existed && !repo_path.is_dir() {
        anyhow::bail!("advisory database path '{repo_path}' is not a directory");
    }

    if repo_existed {
        ensure_not_locked(repo_path, branch)?;
    }

    let staging = temp_repo_path(repo_path, "staging")?;

    let result = if repo_existed {
        fetch_repo_in_place(url, repo_path, &staging, branch)
    } else {
        clone_repo(url, &staging, branch)
    };

    let fetch_result = match result {
        Ok(result) => result,
        Err(err) => {
            if let Err(cleanup_err) = fs::remove_dir_all(&staging)
                && staging.exists()
            {
                log::debug!(
                    "failed to remove temporary advisory database '{}': {cleanup_err}",
                    staging
                );
            }

            return Err(err);
        }
    };

    // Make sure the staging repository is actually usable before replacing the
    // existing generation with it.
    if let Err(err) = git(&staging, &["rev-parse", "--verify", "HEAD"])
        .context("temporary advisory database does not have a valid HEAD")
    {
        let _ = fs::remove_dir_all(&staging);
        return Err(err);
    }

    if let Err(err) = install_staging(&staging, repo_path, repo_existed) {
        let _ = fs::remove_dir_all(&staging);
        return Err(err);
    }

    Ok(fetch_result)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(crate::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let mut path = crate::PathBuf::from_path_buf(std::env::temp_dir()).unwrap();
            path.push(format!(
                "cargo-deny-git-{name}-{}-{}",
                std::process::id(),
                TEMP_REPO_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();

            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn run(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn init_repo(repo: &Path, file: &str, contents: &str) {
        fs::create_dir_all(repo).unwrap();
        run(repo, &["init", "-q", "-b", "main"]);
        fs::write(repo.join(file), contents).unwrap();
        run(repo, &["add", "."]);
        run(
            repo,
            &[
                "-c",
                "user.name=cargo-deny",
                "-c",
                "user.email=cargo-deny@example.com",
                "commit",
                "-qm",
                "initial",
            ],
        );
    }

    fn commit(repo: &Path, file: &str, contents: &str) {
        fs::write(repo.join(file), contents).unwrap();
        run(repo, &["add", "."]);
        run(
            repo,
            &[
                "-c",
                "user.name=cargo-deny",
                "-c",
                "user.email=cargo-deny@example.com",
                "commit",
                "-qm",
                "update",
            ],
        );
    }

    #[test]
    fn clones_and_fetches() {
        let td = TempDir::new("updates");
        let remote = td.path().join("remote");
        init_repo(&remote, "advisory.md", "one");

        let db = td.path().join("db");
        assert!(matches!(
            fetch_repo(remote.as_str(), &db, "main").unwrap(),
            FetchResult::Cloned
        ));
        assert_eq!(fs::read_to_string(db.join("advisory.md")).unwrap(), "one");

        commit(&remote, "advisory.md", "two");

        assert!(matches!(
            fetch_repo(remote.as_str(), &db, "main").unwrap(),
            FetchResult::Fetched
        ));
        assert_eq!(fs::read_to_string(db.join("advisory.md")).unwrap(), "two");
    }

    #[test]
    fn failed_fetch_preserves_previous_generation() {
        let td = TempDir::new("failed-fetch");
        let remote = td.path().join("remote");
        init_repo(&remote, "advisory.md", "one");

        let db = td.path().join("db");
        fetch_repo(remote.as_str(), &db, "main").unwrap();

        let head = git(&db, &["rev-parse", "HEAD"]).unwrap();
        let fetch_time = get_fetch_time(&db).unwrap();
        commit(&remote, "advisory.md", "two");

        let missing = td.path().join("missing");
        assert!(fetch_repo(missing.as_str(), &db, "main").is_err());

        // The failed update must not have touched the live database, so the
        // previous complete generation is still available to offline checks.
        assert_eq!(git(&db, &["rev-parse", "HEAD"]).unwrap(), head);
        assert_eq!(fs::read_to_string(db.join("advisory.md")).unwrap(), "one");
        assert_eq!(get_fetch_time(&db).unwrap(), fetch_time);

        // No staging directory should be left behind after the failure.
        let leftovers: Vec<_> = fs::read_dir(td.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".db."))
            .collect();
        assert!(leftovers.is_empty(), "leftover staging dirs: {leftovers:?}");
    }

    #[test]
    fn failed_initial_clone_leaves_no_partial_database() {
        let td = TempDir::new("failed-clone");
        let db = td.path().join("db");
        let missing = td.path().join("missing");

        assert!(fetch_repo(missing.as_str(), &db, "main").is_err());
        assert!(!db.exists(), "a failed clone must not install a partial db");
    }

    #[test]
    fn locked_database_is_not_updated() {
        let td = TempDir::new("locked");
        let remote = td.path().join("remote");
        init_repo(&remote, "advisory.md", "one");

        let db = td.path().join("db");
        fetch_repo(remote.as_str(), &db, "main").unwrap();

        let head = git(&db, &["rev-parse", "HEAD"]).unwrap();
        let fetch_time = get_fetch_time(&db).unwrap();
        commit(&remote, "advisory.md", "two");

        // A process that died with the index locked would previously have its
        // fetch update the repository before failing to reset it.
        let lock = db.join(".git").join("index.lock");
        fs::write(&lock, "").unwrap();

        assert!(fetch_repo(remote.as_str(), &db, "main").is_err());
        assert_eq!(git(&db, &["rev-parse", "HEAD"]).unwrap(), head);
        assert_eq!(fs::read_to_string(db.join("advisory.md")).unwrap(), "one");
        assert_eq!(get_fetch_time(&db).unwrap(), fetch_time);

        fs::remove_file(lock).unwrap();
    }

    #[test]
    fn half_applied_fetch_does_not_report_new_completion_time() {
        let td = TempDir::new("half-applied");
        let remote = td.path().join("remote");
        init_repo(&remote, "advisory.md", "one");

        let db = td.path().join("db");
        fetch_repo(remote.as_str(), &db, "main").unwrap();

        let fetch_time = get_fetch_time(&db).unwrap();
        commit(&remote, "advisory.md", "two");

        // Reproduce the state left behind by a fetch that updates the ref and
        // FETCH_HEAD but fails before resetting the checkout.
        run(&db, &["fetch", "--depth=1", "-u", "origin", "+main:main"]);

        assert_eq!(fs::read_to_string(db.join("advisory.md")).unwrap(), "one");
        assert_eq!(get_fetch_time(&db).unwrap(), fetch_time);
    }
}
