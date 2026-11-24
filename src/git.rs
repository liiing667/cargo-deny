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
    fmt, fs,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

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

/// Attempts to determine the timestamp of the last fetch (`FETCH_HEAD`)
///
/// If unavailable, attempts to fallback to the timestamp of `HEAD`
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

    let timestamp = match file_timestamp("FETCH_HEAD") {
        Ok(ts) => ts,
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

/// The identity of a specific commit in a git repository.
///
/// This is a validated hexadecimal commit sha (full, or a shortened prefix as
/// reported by git). It exists so that the commit a repository is actually
/// checked out at can be carried along with the result of a fetch, instead of
/// being inferred later from mutable state such as `FETCH_HEAD` or a timestamp.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitIdentity {
    commit: String,
}

impl CommitIdentity {
    /// Validates and normalizes a commit sha.
    ///
    /// Both full and abbreviated (but at least 4 character) hexadecimal commit
    /// shas are accepted, and are normalized to lowercase.
    pub fn new(commit: impl AsRef<str>) -> anyhow::Result<Self> {
        let commit = commit.as_ref().trim();

        anyhow::ensure!(
            (4..=64).contains(&commit.len()) && commit.bytes().all(|b| b.is_ascii_hexdigit()),
            "'{commit}' is not a valid git commit identity"
        );

        Ok(Self {
            commit: commit.to_ascii_lowercase(),
        })
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.commit
    }
}

impl fmt::Display for CommitIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.commit)
    }
}

impl AsRef<str> for CommitIdentity {
    fn as_ref(&self) -> &str {
        &self.commit
    }
}

pub enum FetchResult {
    /// The repo was fetched, and is now checked out at the specified commit
    Fetched(CommitIdentity),
    /// The repo was cloned, and is checked out at the specified commit
    Cloned(CommitIdentity),
}

impl FetchResult {
    /// The identity of the commit the repository is checked out at.
    ///
    /// Callers that publish, cache, or report the contents of the repository
    /// should use this commit instead of re-reading `HEAD` or `FETCH_HEAD`,
    /// which could have moved (or been left half-updated) by a concurrent or
    /// later operation.
    #[inline]
    pub fn commit_identity(&self) -> &CommitIdentity {
        match self {
            Self::Fetched(commit) | Self::Cloned(commit) => commit,
        }
    }

    /// The commit sha the repository is checked out at.
    #[inline]
    pub fn commit(&self) -> &str {
        self.commit_identity().as_str()
    }

    /// Takes the commit identity out of the result.
    #[inline]
    pub fn into_commit(self) -> CommitIdentity {
        match self {
            Self::Fetched(commit) | Self::Cloned(commit) => commit,
        }
    }
}

impl fmt::Display for FetchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetched(commit) => write!(f, "fetched ({commit})"),
            Self::Cloned(commit) => write!(f, "cloned ({commit})"),
        }
    }
}

/// Resolves a revision in the specified repository to a validated commit identity
fn resolve_commit(repo: &Path, rev: &str) -> anyhow::Result<CommitIdentity> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", &format!("{rev}^{{commit}}")]);

    let commit = capture(cmd).with_context(|| format!("failed to resolve '{rev}' in {repo}"))?;

    CommitIdentity::new(commit)
}

/// Returns the commit the repository is currently checked out at.
pub fn head_commit(repo: &Path) -> anyhow::Result<CommitIdentity> {
    resolve_commit(repo, "HEAD")
}

fn validate_branch(branch: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!branch.is_empty(), "git branch must not be empty");
    anyhow::ensure!(
        !branch.starts_with('-'),
        "'{branch}' is not a valid git branch"
    );
    Ok(())
}

/// Attempts to clone or fetch a remote repo into the specified path.
///
/// The update is performed atomically from the perspective of the caller: a
/// fresh clone is staged in a temporary directory and only moved into place
/// once it has succeeded, while an existing repository is only reset to the
/// fetched commit after the fetch has completed. If any step fails the
/// repository is left at its previous commit, and the error is returned instead
/// of a result that could be mistaken for a successfully updated generation.
pub fn fetch_repo(url: &str, repo_path: &Path, branch: &str) -> anyhow::Result<FetchResult> {
    validate_branch(branch)?;

    let Some(parent) = repo_path.parent() else {
        anyhow::bail!("invalid directory: {repo_path}");
    };

    if !parent.is_dir() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create repository parent directory {parent}"))?;
    }

    if repo_path.exists() {
        return fetch_existing(url, repo_path, branch);
    }

    clone_fresh(url, repo_path, branch)
}

fn fetch_existing(url: &str, repo_path: &Path, branch: &str) -> anyhow::Result<FetchResult> {
    let run = |args: &[&str]| {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(repo_path);
        cmd.args(args);

        capture(cmd)
    };

    // Remember which generation we are currently on, so that we can restore it
    // if we are unable to check out the newly fetched one.
    let previous_commit = head_commit(repo_path).ok();

    // Make sure the path is clean. We don't fail if we can't reset since it
    // _may_ still be possible to fetch, but we do not publish a new generation
    // unless the final checkout succeeds.
    match run(&["reset", "--hard"]) {
        Ok(_reset) => log::debug!("reset {url}"),
        Err(err) => log::error!("failed to reset {url}: {err}"),
    }

    // Fetch the requested branch without updating any local refs. FETCH_HEAD is
    // only used to resolve the commit; the working tree is not touched until we
    // know which commit we actually fetched.
    run(&["fetch", "--depth=1", "origin", branch]).context("failed to fetch latest changes")?;

    let fetched =
        resolve_commit(repo_path, "FETCH_HEAD").context("failed to resolve the fetched commit")?;

    if let Err(reset_err) = run(&["reset", "--hard", fetched.as_str()]) {
        // Restore the previous generation so the repository never exposes a
        // mix of the old contents and the new ref/commit.
        let restored = previous_commit
            .as_ref()
            .is_some_and(|previous| run(&["reset", "--hard", previous.as_str()]).is_ok());

        return Err(reset_err).context(if restored {
            "failed to reset to the fetched commit, restored the previous commit"
        } else {
            "failed to reset to the fetched commit, and failed to restore the previous commit"
        });
    }

    Ok(FetchResult::Fetched(fetched))
}

fn clone_fresh(url: &str, repo_path: &Path, branch: &str) -> anyhow::Result<FetchResult> {
    static CLONE_COUNTER: AtomicU64 = AtomicU64::new(0);

    let file_name = repo_path.file_name().unwrap_or("repo");
    let nonce = CLONE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!("{file_name}.tmp-{}-{nonce}", std::process::id(),);
    let temp_path = repo_path.with_file_name(temp_name);

    anyhow::ensure!(
        !temp_path.exists(),
        "temporary clone path '{temp_path}' already exists"
    );

    let mut cmd = Command::new("git");
    cmd.args(["clone", "--depth=1", "--branch", branch])
        .arg(url)
        .arg(&temp_path);

    if let Err(err) = capture(cmd) {
        // Never leave a partially cloned repository behind, otherwise a retry
        // would take the "existing repository" path and could reuse the
        // half-written generation.
        let _ = fs::remove_dir_all(&temp_path);
        return Err(err).context("failed to clone");
    }

    let commit = match head_commit(&temp_path) {
        Ok(commit) => commit,
        Err(err) => {
            let _ = fs::remove_dir_all(&temp_path);
            return Err(err).context("failed to resolve cloned commit");
        }
    };

    if let Err(err) = fs::rename(&temp_path, repo_path) {
        let _ = fs::remove_dir_all(&temp_path);
        return Err(err).with_context(|| format!("failed to install clone at {repo_path}"));
    }

    Ok(FetchResult::Cloned(commit))
}
