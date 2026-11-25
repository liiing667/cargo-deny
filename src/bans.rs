pub mod cfg;
mod diags;
mod graph;
pub mod replacements;

use self::cfg::{ValidBuildConfig, ValidConfig, ValidTreeSkip};
use crate::{
    Kid, Krate, Krates, LintLevel,
    cfg::{PackageSpec, Reason, Span, Spanned},
    diag::{self, CfgCoord, FileId, KrateCoord},
};
use anyhow::Error;
pub use diags::Code;
use krates::DepKind;
use krates::cm::DependencyKind;
use semver::VersionReq;
use std::fmt;

struct ReqMatch<'vr> {
    specr: &'vr SpecAndReason,
    index: usize,
}

pub(crate) struct SpecAndReason {
    pub(crate) spec: PackageSpec,
    pub(crate) reason: Option<Reason>,
    pub(crate) use_instead: Option<Spanned<String>>,
    pub(crate) file_id: FileId,
}

#[cfg(test)]
impl serde::Serialize for SpecAndReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("spec", &self.spec)?;
        map.serialize_entry("reason", &self.reason)?;
        map.serialize_entry("use-instead", &self.use_instead)?;
        map.end()
    }
}

struct SpecsAndReasons(Vec<SpecAndReason>);

impl SpecsAndReasons {
    /// Returns the specs that match the specified crate
    #[inline]
    fn matches<'s>(&'s self, details: &Krate) -> Option<Vec<ReqMatch<'s>>> {
        let matches: Vec<_> = self
            .0
            .iter()
            .enumerate()
            .filter_map(|(index, req)| {
                crate::match_krate(details, &req.spec).then_some(ReqMatch { specr: req, index })
            })
            .collect();

        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }
}

struct SkipRoot {
    specr: SpecAndReason,
    skip_crates: Vec<Kid>,
    skip_hits: BitVec,
}

use bitvec::prelude::*;

// If trees are being skipped, walk each one down to the specified depth and add
// each dependency as a skipped crate at the specific version
struct TreeSkipper {
    roots: Vec<SkipRoot>,
}

impl TreeSkipper {
    fn build(skip_roots: Vec<ValidTreeSkip>, krates: &Krates, cfg_file_id: FileId) -> (Self, Pack) {
        let mut roots = Vec::with_capacity(skip_roots.len());

        let mut pack = Pack::new(Check::Bans);

        for ts in skip_roots {
            let num_roots = roots.len();

            for nid in krates.krates_by_name(&ts.spec.name.value).filter_map(|km| {
                crate::match_req(&km.krate.version, ts.spec.version_req.as_ref())
                    .then_some(km.node_id)
            }) {
                roots.push(Self::build_skip_root(ts.clone(), cfg_file_id, nid, krates));
            }

            // If no roots were added, add a diagnostic that the user's configuration
            // is outdated so they can fix or clean it up
            if roots.len() == num_roots {
                pack.push(diags::UnmatchedSkipRoot {
                    skip_root_cfg: CfgCoord {
                        file: cfg_file_id,
                        span: ts.spec.name.span,
                    },
                });
            }
        }

        (Self { roots }, pack)
    }

    fn build_skip_root(
        ts: ValidTreeSkip,
        file_id: FileId,
        krate_id: krates::NodeId,
        krates: &Krates,
    ) -> SkipRoot {
        let (max_depth, reason) = ts.inner.map_or((usize::MAX, None), |inn| {
            (inn.depth.unwrap_or(usize::MAX), inn.reason)
        });

        let mut skip_crates = Vec::with_capacity(10);

        let graph = krates.graph();

        let mut pending = vec![(krate_id, 1)];
        while let Some((node_id, depth)) = pending.pop() {
            let pkg_id = if let krates::Node::Krate { id, .. } = &graph[node_id] {
                id
            } else {
                continue;
            };
            if let Err(i) = skip_crates.binary_search(pkg_id) {
                skip_crates.insert(i, pkg_id.clone());

                if depth < max_depth {
                    for dep in krates.direct_dependencies(node_id) {
                        pending.push((dep.node_id, depth + 1));
                    }
                }
            }
        }

        let skip_hits = BitVec::repeat(false, skip_crates.len());

        SkipRoot {
            specr: SpecAndReason {
                spec: ts.spec,
                reason,
                use_instead: None,
                file_id,
            },
            skip_crates,
            skip_hits,
        }
    }

    fn matches(&mut self, krate: &Krate, pack: &mut Pack) -> bool {
        let mut skip = false;

        for root in &mut self.roots {
            if let Ok(i) = root.skip_crates.binary_search(&krate.id) {
                pack.push(diags::SkippedByRoot {
                    krate,
                    skip_root_cfg: &root.specr,
                });

                root.skip_hits.as_mut_bitslice().set(i, true);
                skip = true;
            }
        }

        skip
    }
}

#[derive(Clone, Default)]
pub struct DupGraph {
    pub duplicate: String,
    pub graph: String,
    /// Stable description of which crate versions, dependency edges and scopes
    /// produced this duplicate finding.
    ///
    /// The graph string above is meant for humans, but it deliberately only
    /// contains the versions that survived the `skip`/dev filtering. Consumers
    /// (JSON output, SARIF, third party tooling) need a structured identity so
    /// they can tell findings apart and, importantly, map a filtered finding
    /// back to the original dependency edges it came from.
    pub scope_identity: ScopeIdentity,
}

impl fmt::Debug for DupGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.graph)
    }
}

impl DupGraph {
    /// The structured identity for this duplicate finding.
    #[inline]
    pub fn scope_identity(&self) -> &ScopeIdentity {
        &self.scope_identity
    }

    /// Alias for [`Self::scope_identity`].
    #[inline]
    pub fn identity(&self) -> &ScopeIdentity {
        &self.scope_identity
    }

    /// Alias for [`Self::scope_identity`].
    #[inline]
    pub fn scope(&self) -> &ScopeIdentity {
        &self.scope_identity
    }

    /// The versions that are part of this finding.
    #[inline]
    pub fn versions(&self) -> &[VersionScope] {
        self.scope_identity.versions()
    }
}

/// The graph scope a duplicate version was found in.
///
/// A version can be both a workspace member and reachable through dev edges;
/// [`ScopeKind::Workspace`] takes precedence because workspace members are
/// always roots of the cargo dependency graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeKind {
    /// The crate is a member of the workspace.
    Workspace,
    /// The crate is reachable through at least one normal or build edge.
    Transitive,
    /// The crate is only reachable through one or more dev dependency edges.
    Dev,
}

impl ScopeKind {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Transitive => "transitive",
            Self::Dev => "dev",
        }
    }
}

impl fmt::Display for ScopeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The dependency kind of an original graph edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeKind {
    /// A normal dependency edge.
    Normal,
    /// A build dependency edge.
    Build,
    /// A dev dependency edge.
    Dev,
}

impl EdgeKind {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Build => "build",
            Self::Dev => "dev",
        }
    }

    /// Returns the edge kind as a `krates` dependency kind.
    #[inline]
    pub fn dep_kind(self) -> DepKind {
        match self {
            Self::Normal => DepKind::Normal,
            Self::Build => DepKind::Build,
            Self::Dev => DepKind::Dev,
        }
    }
}

impl From<DepKind> for EdgeKind {
    #[inline]
    fn from(kind: DepKind) -> Self {
        match kind {
            DepKind::Normal => Self::Normal,
            DepKind::Build => Self::Build,
            DepKind::Dev => Self::Dev,
        }
    }
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A dependency edge from another crate to the version in a duplicate finding.
///
/// `edge_id` and `cfg` are copied straight from the original `krates` graph;
/// filtering a version out of the duplicate set never removes these edges, so
/// the original inclusion path remains auditable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeEdge {
    /// The crate that declares the dependency.
    pub parent: Kid,
    /// The kind of the original Cargo dependency edge.
    pub kind: EdgeKind,
    /// The target-specific configuration attached to the edge, if any.
    pub cfg: Option<String>,
    /// The index of the edge in the original `krates` dependency graph.
    pub edge_id: usize,
}

impl ScopeEdge {
    /// The parent crate for this edge.
    #[inline]
    pub fn parent(&self) -> &Kid {
        &self.parent
    }

    /// The original dependency kind.
    #[inline]
    pub fn kind(&self) -> EdgeKind {
        self.kind
    }

    /// The original graph edge id.
    #[inline]
    pub fn edge_id(&self) -> usize {
        self.edge_id
    }

    /// Whether this is a dev dependency edge.
    #[inline]
    pub fn is_dev(&self) -> bool {
        self.kind == EdgeKind::Dev
    }
}

impl serde::Serialize for ScopeEdge {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("ScopeEdge", 4)?;
        state.serialize_field("parent", &self.parent.repr)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("cfg", &self.cfg)?;
        state.serialize_field("edge_id", &self.edge_id)?;
        state.end()
    }
}

/// Why a version did or did not participate in a duplicate finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionStatus {
    /// The version is part of the public finding.
    Included,
    /// The version was explicitly skipped by configuration.
    Skipped,
    /// The version was removed because dev dependencies are ignored.
    DevFiltered,
}

impl VersionStatus {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Included => "included",
            Self::Skipped => "skipped",
            Self::DevFiltered => "dev-filtered",
        }
    }
}

/// The identity of one crate version in a duplicate finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionScope {
    /// The exact package id, including name, version and source.
    pub krate: Kid,
    /// The scope the version was attributed to.
    pub scope: ScopeKind,
    /// How this version relates to the public finding.
    pub status: VersionStatus,
    /// Original dependency edges that reach this version.
    pub edges: Vec<ScopeEdge>,
}

impl VersionScope {
    /// The exact package id for this version.
    #[inline]
    pub fn krate(&self) -> &Kid {
        &self.krate
    }

    /// The crate name.
    #[inline]
    pub fn name(&self) -> &str {
        self.krate.name()
    }

    /// The locked crate version.
    #[inline]
    pub fn version(&self) -> &str {
        self.krate.version()
    }

    /// The source id for this version.
    #[inline]
    pub fn source(&self) -> &str {
        self.krate.source()
    }

    /// The scope this version belongs to.
    #[inline]
    pub fn scope(&self) -> ScopeKind {
        self.scope
    }

    /// The original dependency edges reaching this version.
    #[inline]
    pub fn edges(&self) -> &[ScopeEdge] {
        &self.edges
    }

    /// Whether the version survived dev-dependency filtering for this finding.
    #[inline]
    pub fn is_included(&self) -> bool {
        self.status == VersionStatus::Included
    }

    /// Whether the version was only reachable through dev edges.
    #[inline]
    pub fn is_dev(&self) -> bool {
        self.scope == ScopeKind::Dev
    }
}

impl serde::Serialize for VersionScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("VersionScope", 7)?;
        state.serialize_field("krate", &self.krate.repr)?;
        state.serialize_field("name", self.name())?;
        state.serialize_field("version", self.version())?;
        state.serialize_field("source", self.source())?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("edges", &self.edges)?;
        state.end()
    }
}

/// Stable identity for a duplicate-version finding.
///
/// The included versions are the ones reported to users, while
/// [`Self::filtered_versions`] and [`Self::skipped_versions`] retain the
/// versions and original edges that were removed by the corresponding scope
/// filter, so a consumer can still explain where the finding came from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeIdentity {
    /// The duplicate crate name.
    pub duplicate: String,
    /// Versions that are part of the reported finding.
    pub versions: Vec<VersionScope>,
    /// Versions removed because dev dependencies are excluded.
    pub filtered_versions: Vec<VersionScope>,
    /// Versions removed by an explicit `skip`/`skip-tree` rule.
    pub skipped_versions: Vec<VersionScope>,
}

impl ScopeIdentity {
    /// The duplicate crate name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.duplicate
    }

    /// Versions that are part of the finding.
    #[inline]
    pub fn versions(&self) -> &[VersionScope] {
        &self.versions
    }

    /// Versions removed by dev filtering, with their original edges intact.
    #[inline]
    pub fn filtered_versions(&self) -> &[VersionScope] {
        &self.filtered_versions
    }

    /// Versions removed by explicit skip configuration.
    #[inline]
    pub fn skipped_versions(&self) -> &[VersionScope] {
        &self.skipped_versions
    }

    /// Whether the identity contains any reported version.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// The number of versions in the finding.
    #[inline]
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Iterate over the versions in the finding.
    pub fn iter(&self) -> impl Iterator<Item = &VersionScope> {
        self.versions.iter()
    }
}

impl std::ops::Deref for ScopeIdentity {
    type Target = [VersionScope];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.versions
    }
}

impl<'a> IntoIterator for &'a ScopeIdentity {
    type Item = &'a VersionScope;
    type IntoIter = std::slice::Iter<'a, VersionScope>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.versions.iter()
    }
}

impl serde::Serialize for ScopeIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("ScopeIdentity", 4)?;
        state.serialize_field("duplicate", &self.duplicate)?;
        state.serialize_field("versions", &self.versions)?;
        state.serialize_field("filtered_versions", &self.filtered_versions)?;
        state.serialize_field("skipped_versions", &self.skipped_versions)?;
        state.end()
    }
}

/// Chooses the strongest dependency kind when the same parent reaches a crate
/// through more than one edge.
///
/// Normal edges are what make a dependency part of the regular workspace graph,
/// followed by build edges, and finally dev edges. Choosing deterministically is
/// important because the text dotgraph and JSON inclusion graph must report the
/// same scope for a crate that is both a normal and a dev dependency.
#[inline]
pub(crate) fn strongest_kind(a: DepKind, b: DepKind) -> DepKind {
    #[inline]
    fn rank(kind: DepKind) -> u8 {
        match kind {
            DepKind::Normal => 3,
            DepKind::Build => 2,
            DepKind::Dev => 1,
        }
    }

    if rank(a) >= rank(b) { a } else { b }
}

/// Collects every original crate dependency edge that points at `krate`.
///
/// This intentionally does not collapse parallel normal/dev/build edges. The
/// returned edges are sorted by edge id so the identity is deterministic.
fn scope_edges(krates: &Krates, krate: &Krate) -> Vec<ScopeEdge> {
    use krates::petgraph::{Direction, visit::EdgeRef};

    let graph = krates.graph();
    let Some(nid) = krates.nid_for_kid(&krate.id) else {
        return Vec::new();
    };

    let mut edges = Vec::new();
    let mut stack = vec![nid];
    let mut visited = std::collections::BTreeSet::new();

    while let Some(nid) = stack.pop() {
        if !visited.insert(nid) {
            continue;
        }

        for edge in graph.edges_directed(nid, Direction::Incoming) {
            match &graph[edge.source()] {
                krates::Node::Krate { krate: parent, .. } => {
                    if let krates::Edge::Dep { kind, cfg }
                    | krates::Edge::DepFeature { kind, cfg } = edge.weight()
                    {
                        edges.push(ScopeEdge {
                            parent: parent.id.clone(),
                            kind: (*kind).into(),
                            cfg: cfg.clone(),
                            edge_id: edge.id().index(),
                        });
                    }
                }
                krates::Node::Feature { krate_index, .. } if *krate_index == nid => {
                    stack.push(edge.source());
                }
                _ => {}
            }
        }
    }

    edges.sort_unstable_by_key(|edge| edge.edge_id);
    edges
}

fn version_scope(
    krates: &Krates,
    krate: &Krate,
    status: VersionStatus,
    is_workspace_member: bool,
    dev_only: bool,
) -> VersionScope {
    let scope = if is_workspace_member {
        ScopeKind::Workspace
    } else if dev_only {
        ScopeKind::Dev
    } else {
        ScopeKind::Transitive
    };

    VersionScope {
        krate: krate.id.clone(),
        scope,
        status,
        edges: scope_edges(krates, krate),
    }
}

pub type OutputGraph = dyn Fn(DupGraph) -> Result<(), Error> + Send + Sync;

use crate::diag::{Check, Diag, Pack, Severity};

pub fn check(
    ctx: crate::CheckCtx<'_, ValidConfig>,
    output_graph: Option<Box<OutputGraph>>,
    sink: impl Into<diag::ErrorSink>,
) {
    let ValidConfig {
        file_id,
        denied,
        denied_multiple_versions,
        allowed,
        allow_workspace,
        features,
        workspace_default_features,
        external_default_features,
        skipped,
        multiple_versions,
        multiple_versions_include_dev,
        workspace_dependencies,
        highlight,
        tree_skipped,
        wildcards,
        allow_wildcard_paths,
        build,
        std_replacements,
    } = ctx.cfg;

    let mut sink = sink.into();
    let krate_spans = &ctx.krate_spans;
    let (mut tree_skipper, build_diags) = TreeSkipper::build(tree_skipped, ctx.krates, file_id);

    if !build_diags.is_empty() {
        sink.push(build_diags);
    }

    use std::collections::BTreeMap;

    struct BanWrappers {
        map: BTreeMap<usize, (usize, Vec<Spanned<String>>)>,
        hits: BitVec,
    }

    impl BanWrappers {
        fn new(mut map: BTreeMap<usize, (usize, Vec<Spanned<String>>)>) -> Self {
            let hits = BitVec::repeat(
                false,
                map.values_mut().fold(0, |sum, v| {
                    v.0 = sum;
                    sum + v.1.len()
                }),
            );

            Self { map, hits }
        }

        #[inline]
        fn has_wrappers(&self, i: usize) -> bool {
            self.map.contains_key(&i)
        }

        #[inline]
        fn check(&mut self, i: usize, name: &str) -> Option<Span> {
            let (offset, wrappers) = &self.map[&i];
            if let Some(pos) = wrappers.iter().position(|wrapper| wrapper.value == name) {
                self.hits.set(*offset + pos, true);
                Some(wrappers[pos].span)
            } else {
                None
            }
        }
    }

    let (denied_ids, mut ban_wrappers) = {
        let mut bw = BTreeMap::new();

        (
            SpecsAndReasons(
                denied
                    .into_iter()
                    .enumerate()
                    .map(|(i, kb)| {
                        let (reason, use_instead) = if let Some(ext) = kb.inner {
                            if let Some(wrappers) = ext.wrappers.filter(|w| !w.is_empty()) {
                                bw.insert(i, (0, wrappers));
                            }

                            (ext.reason, ext.use_instead)
                        } else {
                            (None, None)
                        };

                        SpecAndReason {
                            spec: kb.spec,
                            reason,
                            use_instead,
                            file_id,
                        }
                    })
                    .collect(),
            ),
            BanWrappers::new(bw),
        )
    };

    let (feature_ids, features): (Vec<_>, Vec<_>) = features
        .into_iter()
        .map(|cf| {
            (
                SpecAndReason {
                    spec: cf.spec,
                    reason: cf.reason,
                    use_instead: None,
                    file_id,
                },
                cf.features,
            )
        })
        .unzip();

    let feature_ids = SpecsAndReasons(feature_ids);

    // Keep track of all the crates we skip, and emit a warning if
    // we encounter a skip that didn't actually match any crate version
    // so that people can clean up their config files
    let mut skip_hit: BitVec = BitVec::repeat(false, skipped.len());

    struct MultiDetector<'a> {
        name: &'a str,
        dupes: smallvec::SmallVec<[(usize, bool); 4]>,
        // Keep track of the crates that actually have > 1 version, regardless of skips
        // if a skip is encountered for a krate that only has 1 version, warn about it
        krates_with_dupes: Vec<&'a str>,
    }

    let mut multi_detector = MultiDetector {
        name: &ctx.krates.krates().next().unwrap().name,
        dupes: smallvec::SmallVec::new(),
        krates_with_dupes: Vec::new(),
    };

    let filtered_krates = ctx.krates.krates_filtered(krates::DepKind::Dev);

    // A crate is dev-only when removing dev edges from the workspace roots
    // removes it from the graph. Keep the original graph intact; this predicate
    // is only used to decide whether a version participates in the finding.
    let is_dev_only = |kid: &Kid| {
        filtered_krates
            .binary_search_by(|krate| krate.id.cmp(kid))
            .is_err()
    };

    // If we're not counting dev dependencies as duplicates, create a separate
    // set of krates with dev dependencies filtered out
    let should_add_dupe = |kid| multiple_versions_include_dev || !is_dev_only(kid);

    // Group every version by name up front. Some versions never make it into
    // `multi_detector.dupes` because they are dev-only, but we still need them
    // to decide whether an explicitly denied crate has a hidden duplicate, and
    // to retain the original edges in the finding identity.
    let krates_by_name: BTreeMap<&str, Vec<usize>> = {
        let mut map = BTreeMap::<&str, Vec<usize>>::new();
        for (i, krate) in ctx.krates.krates().enumerate() {
            map.entry(krate.name.as_str()).or_default().push(i);
        }
        map
    };

    let dmv = SpecsAndReasons(
        denied_multiple_versions
            .into_iter()
            .map(|spec| SpecAndReason {
                spec,
                reason: None,
                use_instead: None,
                file_id,
            })
            .collect(),
    );

    let allowed = SpecsAndReasons(
        allowed
            .into_iter()
            .map(|all| SpecAndReason {
                spec: all.spec,
                reason: all.inner,
                use_instead: None,
                file_id,
            })
            .collect(),
    );

    let skipped = SpecsAndReasons(
        skipped
            .into_iter()
            .map(|skip| SpecAndReason {
                spec: skip.spec,
                reason: skip.inner,
                use_instead: None,
                file_id,
            })
            .collect(),
    );

    let all_workspace_members: std::collections::HashSet<Kid> = ctx
        .krates
        .workspace_members()
        .filter_map(|node| {
            if let krates::Node::Krate { id, .. } = node {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect();

    // Collect workspace members if allow_workspace is enabled
    let workspace_members = if allow_workspace {
        all_workspace_members.clone()
    } else {
        std::collections::HashSet::new()
    };

    let report_duplicates = |multi_detector: &mut MultiDetector<'_>, sink: &mut diag::ErrorSink| {
        let all_indices = krates_by_name
            .get(multi_detector.name)
            .map(Vec::as_slice)
            .unwrap_or_default();

        let already_selected: std::collections::BTreeSet<usize> = multi_detector
            .dupes
            .iter()
            .map(|(index, _)| *index)
            .collect();

        // These versions exist in the real graph but were removed by the
        // default dev-dependency filter. They are not part of the public
        // finding unless an explicit `deny-multiple-versions` rule requires
        // them, but we retain their identity and original edges for evidence.
        let dev_filtered_indices: Vec<usize> = all_indices
            .iter()
            .copied()
            .filter(|index| !already_selected.contains(index))
            .collect();

        let mut selected = multi_detector.dupes.to_vec();

        // `multiple-versions = 'deny'` still follows the documented dev
        // filtering behavior, but an explicit per-crate
        // `deny-multiple-versions = true` must not be hidden merely because
        // the other version is only reachable through a dev edge.
        let explicitly_denied = all_indices
            .iter()
            .any(|index| dmv.matches(&ctx.krates[*index]).is_some());
        if explicitly_denied && !multiple_versions_include_dev && !dev_filtered_indices.is_empty() {
            log::debug!(
                "crate '{}' has an explicitly denied duplicate that is only reachable through dev edges",
                multi_detector.name
            );
            selected.extend(dev_filtered_indices.iter().map(|index| (*index, false)));
        }

        if selected.len() != 1 {
            // Filter out crates that depend on another version of themselves https://github.com/dtolnay/semver-trick
            selected.retain(|(index, _)| {
                let krate = &ctx.krates[*index];

                // We _could_ just see if this crate's dependencies is another
                // version of itself, but that means if there are other versions
                // of the crate then the version that is doing the trick is not
                // reported, so we do the more expensive check for the direct
                // dependents
                let direct = ctx
                    .krates
                    .direct_dependents(ctx.krates.nid_for_kid(&krate.id).unwrap());

                let res = !direct.iter().all(|dir| dir.krate.name == krate.name);

                if !res {
                    log::debug!("ignoring duplicate crate '{krate}', its only dependents was another version of itself");
                }

                res
            });
        }

        let skipped = selected.iter().filter(|(_, skipped)| *skipped).count();
        if selected.len() > 1 {
            multi_detector.krates_with_dupes.push(multi_detector.name);
        }

        if selected.len() - skipped <= 1 {
            return;
        }

        let lint_level = if selected.iter().any(|(kindex, skipped)| {
            if *skipped {
                return false;
            }

            let krate = &ctx.krates[*kindex];
            dmv.matches(krate).is_some()
        }) {
            LintLevel::Deny
        } else {
            multiple_versions
        };

        let severity = match lint_level {
            LintLevel::Warn => Severity::Warning,
            LintLevel::Deny => Severity::Error,
            LintLevel::Allow => return,
        };

        let mut all_start = usize::MAX;
        let mut all_end = 0;

        struct Dupe {
            /// Unique id, used for printing the actual diagnostic graphs
            id: Kid,
            /// Version, for deterministically ordering the duplicates
            version: semver::Version,
        }

        let mut kids = smallvec::SmallVec::<[Dupe; 2]>::new();

        for dup in selected
            .iter()
            .filter_map(|(ind, skipped)| (!*skipped).then_some(*ind))
        {
            let krate = &ctx.krates[dup];

            let span = &ctx.krate_spans.lock_span(&krate.id).total;
            all_start = all_start.min(span.start);
            all_end = all_end.max(span.end);

            if let Err(i) = kids.binary_search_by(|other| match other.version.cmp(&krate.version) {
                std::cmp::Ordering::Equal => other.id.cmp(&krate.id),
                ord => ord,
            }) {
                kids.insert(
                    i,
                    Dupe {
                        id: krate.id.clone(),
                        version: krate.version.clone(),
                    },
                );
            }
        }

        {
            let mut diag: Diag = diags::Duplicates {
                krate_name: multi_detector.name,
                num_dupes: kids.len(),
                krates_coord: KrateCoord {
                    file: krate_spans.lock_id,
                    span: (all_start..all_end).into(),
                },
                severity,
            }
            .into();

            diag.graph_nodes = kids
                .into_iter()
                .map(|dupe| crate::diag::GraphNode {
                    kid: dupe.id,
                    feature: None,
                })
                .collect();

            let mut pack = Pack::new(Check::Bans);
            pack.push(diag);

            sink.push(pack);
        }

        let selected_set: std::collections::BTreeSet<usize> =
            selected.iter().map(|(index, _)| *index).collect();
        let mut scope_identity = ScopeIdentity {
            duplicate: multi_detector.name.to_owned(),
            ..Default::default()
        };

        for (index, skipped) in &selected {
            let krate = &ctx.krates[*index];
            let status = if *skipped {
                VersionStatus::Skipped
            } else {
                VersionStatus::Included
            };
            let version = version_scope(
                ctx.krates,
                krate,
                status,
                all_workspace_members.contains(&krate.id),
                is_dev_only(&krate.id),
            );

            if *skipped {
                scope_identity.skipped_versions.push(version);
            } else {
                scope_identity.versions.push(version);
            }
        }

        for index in &dev_filtered_indices {
            if selected_set.contains(index) {
                continue;
            }

            let krate = &ctx.krates[*index];
            scope_identity.filtered_versions.push(version_scope(
                ctx.krates,
                krate,
                VersionStatus::DevFiltered,
                all_workspace_members.contains(&krate.id),
                true,
            ));
        }

        let by_krate = |a: &VersionScope, b: &VersionScope| a.krate.cmp(&b.krate);
        scope_identity.versions.sort_unstable_by(by_krate);
        scope_identity.filtered_versions.sort_unstable_by(by_krate);
        scope_identity.skipped_versions.sort_unstable_by(by_krate);

        if let Some(og) = &output_graph {
            match graph::create_graph(multi_detector.name, highlight, ctx.krates, &scope_identity) {
                Ok(graph) => {
                    if let Err(err) = og(DupGraph {
                        duplicate: multi_detector.name.to_owned(),
                        graph,
                        scope_identity,
                    }) {
                        log::error!("{err}");
                    }
                }
                Err(err) => {
                    log::error!("unable to create graph for {}: {err}", multi_detector.name);
                }
            };
        }
    };

    struct BuildCheckCtx {
        bypasses: parking_lot::Mutex<BitVec>,
        allowed: Option<parking_lot::Mutex<BitVec>>,
        diag_packs: parking_lot::Mutex<std::collections::BTreeMap<usize, Pack>>,
        cargo_home: Option<crate::PathBuf>,
        build_config: ValidBuildConfig,
    }

    let build_check_ctx = build.map(|build_config| {
        // Make all paths reported in build diagnostics be relative to cargo_home
        let cargo_home = crate::cargo_home()
            .inspect_err(|error| {
                log::error!("{error:#}");
            })
            .ok();

        // Keep track of the individual crate configs so we can emit warnings
        // if they're configured but not actually used
        let bypasses =
            parking_lot::Mutex::<BitVec>::new(BitVec::repeat(false, build_config.bypass.len()));
        let allowed = build_config
            .allow_build_scripts
            .as_ref()
            .map(|abs| parking_lot::Mutex::<BitVec>::new(BitVec::repeat(false, abs.len() * 2)));

        BuildCheckCtx {
            cargo_home,
            bypasses,
            allowed,
            diag_packs: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            build_config,
        }
    });

    let mut replacements = None;

    let mut ws_duplicate_packs = Vec::new();

    rayon::scope(|scope| {
        if let Some(rctx) = std_replacements.map(replacements::ReplacementCtx::new) {
            scope.spawn(|_s| {
                replacements = rctx.process(ctx.krates);
            });
        }

        scope.spawn(|scope| {
            let last = ctx.krates.len() - 1;

            for (i, krate) in ctx.krates.krates().enumerate() {
                let mut pack = Pack::with_kid(Check::Bans, krate.id.clone());

                // Check if the crate has been explicitly banned
                if let Some(matches) = denied_ids.matches(krate) {
                    let is_workspace_member = workspace_members.contains(&krate.id);

                    for rm in matches {
                        let ban_cfg = CfgCoord {
                            file: file_id,
                            span: rm.specr.spec.name.span,
                        };

                        // If allow_workspace is enabled and this is a workspace member,
                        // skip the ban (workspace members take precedence over explicit bans)
                        if is_workspace_member && allow_workspace {
                            continue;
                        }

                        // The crate is banned, but it might be allowed if it's
                        // wrapped by one or more particular crates
                        let is_allowed_by_wrapper = if ban_wrappers.has_wrappers(rm.index) {
                            let nid = ctx.krates.nid_for_kid(&krate.id).unwrap();

                            // Ensure that every single crate that has a direct dependency
                            // on the banned crate is an allowed wrapper, note we
                            // check every one even after a failure so we don't get
                            // extra warnings about unmatched wrappers
                            let mut all = true;
                            for src in ctx.krates.direct_dependents(nid) {
                                let (diag, is_allowed): (Diag, _) =
                                    match ban_wrappers.check(rm.index, &src.krate.name) {
                                        Some(span) => (
                                            diags::BannedAllowedByWrapper {
                                                ban_cfg: ban_cfg.clone(),
                                                ban_exception_cfg: CfgCoord {
                                                    file: file_id,
                                                    span,
                                                },
                                                banned_krate: krate,
                                                wrapper_krate: src.krate,
                                            }
                                            .into(),
                                            true,
                                        ),
                                        None => (
                                            diags::BannedUnmatchedWrapper {
                                                ban_cfg: rm.specr,
                                                banned_krate: krate,
                                                parent_krate: src.krate,
                                            }
                                            .into(),
                                            false,
                                        ),
                                    };

                                pack.push(diag);
                                all = all && is_allowed;
                            }

                            all
                        } else {
                            false
                        };

                        if !is_allowed_by_wrapper {
                            pack.push(diags::ExplicitlyBanned {
                                krate,
                                ban_cfg: rm.specr,
                            });
                        }
                    }
                }

                if !allowed.0.is_empty() {
                    // Since only allowing specific crates is pretty draconian,
                    // also emit which allow filters actually passed each crate
                    let is_workspace_member = workspace_members.contains(&krate.id);

                    match allowed.matches(krate) {
                        Some(matches) => {
                            for rm in matches {
                                pack.push(diags::ExplicitlyAllowed {
                                    krate,
                                    allow_cfg: rm.specr,
                                });
                            }
                        }
                        None => {
                            // If allow_workspace is enabled and this is a workspace member,
                            // automatically allow it without requiring explicit configuration
                            if is_workspace_member && allow_workspace {
                                // Workspace member is automatically allowed, no diagnostic needed
                            } else {
                                pack.push(diags::NotAllowed { krate });
                            }
                        }
                    }
                }

                let enabled_features = ctx.krates.get_enabled_features(&krate.id).unwrap();

                let default_lint_level = if enabled_features.contains("default") {
                    if ctx.krates.workspace_members().any(|n| {
                        if let krates::Node::Krate { id, .. } = n {
                            id == &krate.id
                        } else {
                            false
                        }
                    }) {
                        workspace_default_features.as_ref()
                    } else {
                        external_default_features.as_ref()
                    }
                } else {
                    None
                };

                if let Some(ll) = default_lint_level
                    && ll.value == LintLevel::Warn
                {
                    pack.push(diags::DefaultFeatureEnabled {
                        krate,
                        level: ll,
                        file_id,
                    });
                }

                // Check if the crate has had features denied/allowed or are required to be exact
                if let Some(matches) = feature_ids.matches(krate) {
                    for rm in matches {
                        let feature_bans = &features[rm.index];

                        let feature_set_allowed = {
                            // Gather features that were present, but not explicitly allowed
                            let not_explicitly_allowed: Vec<_> = enabled_features
                                .iter()
                                .filter_map(|ef| {
                                    if !feature_bans.allow.value.iter().any(|af| &af.value == ef) {
                                        if ef == "default"
                                            && let Some(ll) = default_lint_level
                                            && ll.value != LintLevel::Deny
                                        {
                                            return None;
                                        }

                                        Some(ef.as_str())
                                    } else {
                                        None
                                    }
                                })
                                .collect();

                            if feature_bans.exact.value {
                                // Gather features allowed, but not present
                                let missing_allowed: Vec<_> = feature_bans
                                    .allow
                                    .value
                                    .iter()
                                    .filter_map(|af| {
                                        if !enabled_features.contains(&af.value) {
                                            Some(CfgCoord {
                                                file: file_id,
                                                span: af.span,
                                            })
                                        } else {
                                            None
                                        }
                                    })
                                    .collect();

                                if missing_allowed.is_empty() && not_explicitly_allowed.is_empty() {
                                    true
                                } else {
                                    pack.push(diags::ExactFeaturesMismatch {
                                        missing_allowed,
                                        not_allowed: &not_explicitly_allowed,
                                        exact_coord: CfgCoord {
                                            file: file_id,
                                            span: feature_bans.exact.span,
                                        },
                                        krate,
                                    });
                                    false
                                }
                            } else {
                                // Mark the number of current diagnostics, if we add more
                                // the check has failed
                                let diag_count = pack.len();

                                // Add diagnostics if features were explicitly allowed,
                                // but didn't contain 1 or more features that were enabled
                                if !feature_bans.allow.value.is_empty() {
                                    for feature in &not_explicitly_allowed {
                                        // Since the user has not specified `exact` we
                                        // can also look at the full tree of features to
                                        // determine if the feature is covered by an allowed
                                        // parent feature
                                        fn has_feature(
                                            map: &std::collections::BTreeMap<String, Vec<String>>,
                                            parent: &str,
                                            feature: &str,
                                        ) -> bool {
                                            if let Some(parent) = map.get(parent) {
                                                parent.iter().any(|f| {
                                                    let pf =
                                                        krates::ParsedFeature::from(f.as_str());

                                                    if let krates::Feature::Simple(feat) = pf.feat()
                                                    {
                                                        if feat == feature {
                                                            true
                                                        } else {
                                                            has_feature(map, feat, feature)
                                                        }
                                                    } else {
                                                        false
                                                    }
                                                })
                                            } else {
                                                false
                                            }
                                        }

                                        if !feature_bans.allow.value.iter().any(|allowed| {
                                            has_feature(
                                                &krate.features,
                                                allowed.value.as_str(),
                                                feature,
                                            )
                                        }) {
                                            pack.push(diags::FeatureNotExplicitlyAllowed {
                                                krate,
                                                feature,
                                                allowed: CfgCoord {
                                                    file: file_id,
                                                    span: feature_bans.allow.span,
                                                },
                                            });
                                        }
                                    }
                                }

                                // If the default feature has been denied at a global
                                // level but not at the crate level, emit an error with
                                // the global span, otherwise the crate level setting,
                                // if the default feature was banned explicitly, takes
                                // precedence
                                if let Some(ll) = default_lint_level
                                    && ll.value == LintLevel::Deny
                                    && !feature_bans
                                        .allow
                                        .value
                                        .iter()
                                        .any(|d| d.value == "default")
                                    && !feature_bans.deny.iter().any(|d| d.value == "default")
                                {
                                    pack.push(diags::DefaultFeatureEnabled {
                                        krate,
                                        level: ll,
                                        file_id,
                                    });
                                }

                                for feature in feature_bans
                                    .deny
                                    .iter()
                                    .filter(|feat| enabled_features.contains(&feat.value))
                                {
                                    pack.push(diags::FeatureBanned {
                                        krate,
                                        feature,
                                        file_id,
                                    });
                                }

                                diag_count <= pack.len()
                            }
                        };

                        // If the crate isn't actually banned, but does reference
                        // features that don't exist, emit warnings about them so
                        // the user can cleanup their config. We _could_ emit these
                        // warnings if the crate is banned, but feature graphs in
                        // particular can be massive and adding warnings into the mix
                        // will just make parsing the error graphs harder
                        if feature_set_allowed {
                            for feature in feature_bans
                                .allow
                                .value
                                .iter()
                                .chain(feature_bans.deny.iter())
                            {
                                if !krate.features.contains_key(&feature.value) {
                                    pack.push(diags::UnknownFeature {
                                        krate,
                                        feature,
                                        file_id,
                                    });
                                }
                            }
                        }
                    }
                } else if let Some(ll) = default_lint_level
                    && ll.value == LintLevel::Deny
                {
                    pack.push(diags::DefaultFeatureEnabled {
                        krate,
                        level: ll,
                        file_id,
                    });
                }

                if should_add_dupe(&krate.id) {
                    if let Some(matches) = skipped.matches(krate) {
                        if multi_detector.name != krate.name {
                            report_duplicates(&mut multi_detector, &mut sink);

                            multi_detector.name = &krate.name;
                            multi_detector.dupes.clear();
                        }

                        multi_detector.dupes.push((i, true));

                        for rm in matches {
                            pack.push(diags::Skipped {
                                krate,
                                skip_cfg: rm.specr,
                            });

                            // Mark each skip filter that is hit so that we can report unused
                            // filters to the user so that they can cleanup their configs as
                            // their dependency graph changes over time
                            skip_hit.as_mut_bitslice().set(rm.index, true);
                        }
                    } else if !tree_skipper.matches(krate, &mut pack) {
                        if multi_detector.name != krate.name {
                            report_duplicates(&mut multi_detector, &mut sink);

                            multi_detector.name = &krate.name;
                            multi_detector.dupes.clear();
                        }

                        multi_detector.dupes.push((i, false));

                        'wildcards: {
                            if wildcards != LintLevel::Allow && !krate.is_git_source() {
                                let severity = match wildcards {
                                    LintLevel::Warn => Severity::Warning,
                                    LintLevel::Deny => Severity::Error,
                                    LintLevel::Allow => unreachable!(),
                                };

                                let Some(manifest) = ctx.krate_spans.manifest(&krate.id) else {
                                    break 'wildcards;
                                };
                                let is_private = krate.is_private(&[]);
                                let mut labels = Vec::new();
                                let mut pack = Pack::with_kid(Check::Bans, krate.id.clone());

                                for mdep in manifest.deps(false) {
                                    if mdep.dep.req != VersionReq::STAR {
                                        continue;
                                    }

                                    // Wildcards are allowed for path or git dependencies, if the krate
                                    // is private, or it's only a dev-dependency
                                    //
                                    // OR
                                    //
                                    // The dependency is actually for the same crate, extremely rare but allowed by cargo
                                    if allow_wildcard_paths
                                        && !mdep.krate.is_registry()
                                        && (is_private
                                            || mdep.dep.kind == DependencyKind::Development)
                                        || mdep.krate.id == krate.id
                                    {
                                        continue;
                                    }

                                    labels.push(
                                        crate::diag::Label::primary(
                                            manifest.id,
                                            mdep.version_req
                                                .as_ref()
                                                .map_or(mdep.value_span, |vr| vr.span),
                                        )
                                        .with_message("wildcard dependency"),
                                    );

                                    // If the dependency is a workspace dependency we also want to show
                                    // the bad version requirement for the workspace declaration
                                    if let Some(workspace) = &mdep.workspace {
                                        if !workspace.value {
                                            continue;
                                        }

                                        if let Some(ws_dep) =
                                            ctx.krate_spans.workspace_span(&mdep.krate.id)
                                        {
                                            labels.push(
                                                crate::diag::Label::secondary(
                                                    ctx.krate_spans.workspace_id.unwrap(),
                                                    ws_dep
                                                        .version
                                                        .as_ref()
                                                        .map_or(ws_dep.value, |vr| vr.span),
                                                )
                                                .with_message("workspace dependency"),
                                            );
                                        } else {
                                            // This indicates a bug because we were unable to resolve the workspace dependency
                                            // to an appropriate crate, even though cargo did
                                            pack.push(diags::UnresolveWorkspaceDependency {
                                                manifest,
                                                dep: mdep,
                                            });
                                        }
                                    }
                                }

                                sink.push(pack);

                                if !labels.is_empty() {
                                    sink.push(diags::Wildcards {
                                        krate,
                                        severity,
                                        labels,
                                        allow_wildcard_paths,
                                    });
                                }
                            }
                        }
                    }
                }

                if i == last {
                    report_duplicates(&mut multi_detector, &mut sink);
                }

                if let Some(build_ctx) = &build_check_ctx {
                    scope.spawn(move |_s| {
                        let bci = check_build(
                            ctx.cfg.file_id,
                            &build_ctx.build_config,
                            build_ctx.cargo_home.as_deref(),
                            krate,
                            ctx.krates,
                            &mut pack,
                        );

                        if let Some(bcc) = bci.bypass_index {
                            build_ctx.bypasses.lock().set(bcc, true);
                        }

                        if let Some(mut l) = build_ctx.allowed.as_ref().map(|a| a.lock())
                            && let Some((index, has_build_script)) = bci.allowed
                        {
                            let ind = index * 2;
                            l.set(ind, true);
                            l.set(ind + 1, has_build_script);
                        }

                        if !pack.is_empty() {
                            build_ctx.diag_packs.lock().insert(i, pack);
                        }
                    });
                } else {
                    sink.push(pack);
                }
            }
        });

        // Check the workspace to detect dependencies that are used more than once
        // but don't use a shared [workspace.[dev-/build-]dependencies] declaration
        if let Some(ws_deps) = &workspace_dependencies
            && ws_deps.duplicates != LintLevel::Allow
        {
            scope.spawn(|_| {
                check_workspace_duplicates(
                    ctx.krates,
                    ctx.krate_spans,
                    ws_deps,
                    &mut ws_duplicate_packs,
                );
            });
        }
    });

    if let Some(bcc) = build_check_ctx {
        for bp in bcc.diag_packs.into_inner().into_values() {
            sink.push(bp);
        }

        let mut pack = Pack::new(Check::Bans);
        for ve in bcc
            .bypasses
            .into_inner()
            .into_iter()
            .zip(bcc.build_config.bypass)
            .filter_map(|(hit, ve)| if !hit { Some(ve) } else { None })
        {
            pack.push(diags::UnmatchedBypass {
                unmatched: &ve,
                file_id,
            });
        }

        if let Some((allowed, config)) = bcc.allowed.zip(bcc.build_config.allow_build_scripts) {
            let allowed = allowed.into_inner();
            for (i, acfg) in config.into_iter().enumerate() {
                if allowed[i * 2] {
                    if !allowed[i * 2 + 1] {
                        pack.push(diags::AllowedScriptWithNoScript {
                            missing: &acfg,
                            file_id,
                        });
                    }
                } else {
                    pack.push(diags::UnmatchedAllowBuildScript {
                        unmatched: &acfg,
                        file_id,
                    });
                }
            }
        }

        sink.push(pack);
    }

    for pack in ws_duplicate_packs {
        sink.push(pack);
    }

    if let Some(ws_deps) = workspace_dependencies
        && ws_deps.unused != LintLevel::Allow
        && let Some(id) = krate_spans
            .workspace_id
            .filter(|_id| !krate_spans.unused_workspace_deps.is_empty())
    {
        sink.push(diags::UnusedWorkspaceDependencies {
            id,
            unused: &krate_spans.unused_workspace_deps,
            level: ws_deps.unused,
        });
    }

    let mut pack = Pack::new(Check::Bans);

    for (hit, skip) in skip_hit.into_iter().zip(skipped.0) {
        if !hit {
            pack.push(diags::UnmatchedSkip { skip_cfg: &skip });
        } else if multi_detector
            .krates_with_dupes
            .binary_search(&skip.spec.name.value.as_str())
            .is_err()
        {
            pack.push(diags::UnnecessarySkip { skip_cfg: &skip });
        }
    }

    for wrapper in ban_wrappers
        .hits
        .into_iter()
        .zip(ban_wrappers.map.into_values().flat_map(|(_, w)| w))
        .filter_map(|(hit, wrapper)| (!hit).then_some(wrapper))
    {
        pack.push(diags::UnusedWrapper {
            wrapper_cfg: CfgCoord {
                file: file_id,
                span: wrapper.span,
            },
        });
    }

    sink.push(pack);

    if let Some(replacements) = replacements {
        replacements.emit_diagnostics(ctx.krates, &mut sink, file_id, ctx.colorize);
    }
}

pub struct BuildCheckInfo {
    /// The index of the bypass configuration for the particular crate
    pub bypass_index: Option<usize>,
    /// The index of the allow-build-scripts config, and a bool indicating if it actually contained a build script or not
    pub allowed: Option<(usize, bool)>,
}

pub fn check_build(
    file_id: FileId,
    config: &ValidBuildConfig,
    home: Option<&crate::Path>,
    krate: &Krate,
    krates: &Krates,
    pack: &mut Pack,
) -> BuildCheckInfo {
    use krates::cm::TargetKind;

    let (build_script_allowed, allowed) =
        if let Some(allow_build_scripts) = &config.allow_build_scripts {
            let has_build_script = krate
                .targets
                .iter()
                .any(|t| t.kind.contains(&TargetKind::CustomBuild));

            let pos = allow_build_scripts
                .iter()
                .position(|id| crate::match_krate(krate, id));

            (
                !has_build_script || pos.is_some(),
                pos.map(|p| (p, has_build_script)),
            )
        } else {
            (true, None)
        };

    if build_script_allowed && config.executables == LintLevel::Allow {
        return BuildCheckInfo {
            bypass_index: None,
            allowed,
        };
    }

    #[inline]
    fn executes_at_buildtime(krate: &Krate) -> bool {
        krate.targets.iter().any(|t| {
            t.kind
                .iter()
                .any(|k| matches!(*k, TargetKind::CustomBuild | TargetKind::ProcMacro))
        })
    }

    fn needs_checking(krate: krates::NodeId, krates: &Krates) -> bool {
        // Dev-dependencies can form cycles in the graph, so each node is visited once
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![krate];

        while let Some(nid) = stack.pop() {
            if !visited.insert(nid) {
                continue;
            }

            if executes_at_buildtime(&krates[nid]) {
                return true;
            }

            for dd in krates.direct_dependents(nid) {
                stack.push(dd.node_id);
            }
        }

        false
    }

    // Check if the krate is either a proc-macro, has a build-script, OR is a dependency
    // of a crate that is/does
    if !config.include_workspace
        && krates.workspace_members().any(|n| {
            if let krates::Node::Krate { id, .. } = n {
                id == &krate.id
            } else {
                false
            }
        })
        || (!config.include_dependencies && !executes_at_buildtime(krate))
        || (config.include_dependencies
            && !needs_checking(krates.nid_for_kid(&krate.id).unwrap(), krates))
    {
        return BuildCheckInfo {
            bypass_index: None,
            allowed,
        };
    }

    let (bypass_index, krate_config) = config
        .bypass
        .iter()
        .enumerate()
        .find_map(|(i, ae)| crate::match_krate(krate, &ae.spec).then_some((i, ae)))
        .unzip();

    let ret = BuildCheckInfo {
        bypass_index,
        allowed,
    };

    let build_script_path = krate.targets.iter().find_map(|t| {
        t.kind
            .contains(&TargetKind::CustomBuild)
            .then_some(&t.src_path)
    });

    // If the build script hashes to the same value and required features are not actually
    // set on the crate, we can skip it
    if let Some(kc) = krate_config
        && let Some(bsc) = &kc.build_script
        && let Some(path) = build_script_path
    {
        let root = &krate.manifest_path.parent().unwrap();
        match bsc.value.validate_checksum(path) {
            Ok((true, _)) => {
                pack.push(diags::ChecksumMatch {
                    path: diags::HomePath { path, root, home },
                    checksum: bsc,
                    severity: None,
                    file_id,
                });

                // Emit an error if the user specifies features that don't exist
                for rfeat in &kc.required_features {
                    if !krate.features.contains_key(&rfeat.value) {
                        pack.push(diags::UnknownFeature {
                            krate,
                            feature: rfeat,
                            file_id,
                        });
                    }
                }

                let enabled = krates.get_enabled_features(&krate.id).unwrap();

                let enabled_features: Vec<_> = kc
                    .required_features
                    .iter()
                    .filter(|f| enabled.contains(&f.value))
                    .collect();

                // If none of the required-features are present then we
                // can skip the rest of the check
                if enabled_features.is_empty() {
                    return ret;
                }

                pack.push(diags::FeaturesEnabled {
                    enabled_features,
                    file_id,
                });
            }
            Ok((false, calculated)) => {
                pack.push(diags::ChecksumMismatch {
                    path: diags::HomePath { path, root, home },
                    checksum: bsc,
                    severity: Some(Severity::Warning),
                    error: None,
                    calculated: Some(calculated),
                    file_id,
                });
            }
            Err(err) => {
                pack.push(diags::ChecksumMismatch {
                    path: diags::HomePath { path, root, home },
                    checksum: bsc,
                    severity: Some(Severity::Warning),
                    error: Some(format!("build script failed checksum: {err:#}")),
                    calculated: None,
                    file_id,
                });
            }
        }
    }

    if !build_script_allowed {
        let build_script = build_script_path.and_then(|path| {
            let root = krate.manifest_path.parent().unwrap();
            cfg::Checksum::checksum_file(path)
                .ok()
                .map(|checksum| (diags::HomePath { path, root, home }, checksum))
        });

        pack.push(diags::BuildScriptNotAllowed {
            krate,
            build_script,
        });

        return ret;
    }

    let root = krate.manifest_path.parent().unwrap();

    let (tx, rx) = crossbeam::channel::unbounded();

    let (_, checksum_diags) = rayon::join(
        || {
            // Avoids doing a ton of heap allocations when doing globset matching
            let mut matches = Vec::new();
            let is_git_src = krate.is_git_source();

            let mut allow_hit: BitVec =
                BitVec::repeat(false, krate_config.map_or(0, |kc| kc.allow.len()));
            let mut glob_hit: BitVec = BitVec::repeat(
                false,
                krate_config.map_or(0, |kc| {
                    kc.allow_globs.as_ref().map_or(0, |ag| ag.patterns.len())
                }),
            );

            for entry in walkdir::WalkDir::new(root)
                .sort_by_file_name()
                .into_iter()
                .filter_entry(|entry| {
                    // Skip git folders for git sources, they won't be present in
                    // regular packages, and the example scripts in typical
                    // clones are...not interesting
                    !is_git_src
                        || (entry.path().file_name() == Some(std::ffi::OsStr::new(".git"))
                            && entry.path().parent() == Some(root.as_std_path()))
                })
            {
                let Ok(entry) = entry else {
                    continue;
                };

                if entry.file_type().is_dir() {
                    continue;
                }

                let absolute_path = match crate::PathBuf::from_path_buf(entry.into_path()) {
                    Ok(p) => p,
                    Err(path) => {
                        pack.push(diags::NonUtf8Path { path: &path });
                        continue;
                    }
                };

                let path = &absolute_path;

                let Ok(rel_path) = path.strip_prefix(root) else {
                    pack.push(diags::NonRootPath { path, root });
                    continue;
                };

                let candidate = globset::Candidate::new(rel_path);

                if let Some(kc) = krate_config {
                    // First just check if the file has been explicitly allowed without a
                    // checksum so we don't even need to bother going more in depth
                    let ae = kc
                        .allow
                        .binary_search_by(|ae| ae.path.value.as_path().cmp(rel_path))
                        .ok()
                        .map(|i| {
                            allow_hit.set(i, true);
                            &kc.allow[i]
                        });

                    if let Some(ae) = ae
                        && ae.checksum.is_none()
                    {
                        pack.push(diags::ExplicitPathAllowance {
                            allowed: ae,
                            file_id,
                        });
                        continue;
                    }

                    // Check if the path matches an allowed glob pattern
                    if let Some(ag) = &kc.allow_globs
                        && let Some(globs) = ag.matches(&candidate, &mut matches)
                    {
                        for &i in &matches {
                            glob_hit.set(i, true);
                        }

                        pack.push(diags::GlobAllowance {
                            path: diags::HomePath { path, root, home },
                            globs,
                            file_id,
                        });
                        continue;
                    }

                    // If the file had a checksum specified, verify it still matches,
                    // otherwise fail
                    if let Some(checksum) = ae.as_ref().and_then(|ae| ae.checksum.as_ref()) {
                        let _ = tx.send((absolute_path, checksum));
                        continue;
                    }
                }

                // Check if the file matches a disallowed glob pattern
                if let Some(globs) = config.script_extensions.matches(&candidate, &mut matches) {
                    pack.push(diags::DeniedByExtension {
                        path: diags::HomePath { path, root, home },
                        globs,
                        file_id,
                    });
                    continue;
                }

                // Save the most ambiguous/expensive check for last, does this look
                // like a native executable or script without extension?
                let diag: Diag = match check_is_executable(path, !config.include_archives) {
                    Ok(None) => continue,
                    Ok(Some(exe_kind)) => diags::DetectedExecutable {
                        path: diags::HomePath { path, root, home },
                        interpreted: config.interpreted,
                        exe_kind,
                    }
                    .into(),
                    Err(error) => diags::UnableToCheckPath {
                        path: diags::HomePath { path, root, home },
                        error,
                    }
                    .into(),
                };

                pack.push(diag);
            }

            if let Some(ae) = krate_config.map(|kc| &kc.allow) {
                for ae in allow_hit
                    .into_iter()
                    .zip(ae.iter())
                    .filter_map(|(hit, ae)| if !hit { Some(ae) } else { None })
                {
                    pack.push(diags::UnmatchedPathBypass {
                        unmatched: ae,
                        file_id,
                    });
                }
            }

            if let Some(vgs) = krate_config.and_then(|kc| kc.allow_globs.as_ref()) {
                for gp in glob_hit
                    .into_iter()
                    .zip(vgs.patterns.iter())
                    .filter_map(|(hit, gp)| {
                        if !hit && let cfg::GlobPattern::User(gp) = gp {
                            return Some(gp);
                        }

                        None
                    })
                {
                    pack.push(diags::UnmatchedGlob {
                        unmatched: gp,
                        file_id,
                    });
                }
            }

            drop(tx);
        },
        || {
            // Note that since we ship off the checksum validation to threads the order is
            // not guaranteed, so we just put them in a btreemap so they are consistently
            // ordered and don't trigger test errors or cause confusing output for users
            let checksum_diags = parking_lot::Mutex::new(std::collections::BTreeMap::new());
            rayon::scope(|s| {
                while let Ok((path, checksum)) = rx.recv() {
                    s.spawn(|_s| {
                        let absolute_path = path;
                        let path = &absolute_path;

                        let diag: Diag = match checksum.value.validate_checksum(&absolute_path) {
                            Ok((true, _)) => diags::ChecksumMatch {
                                path: diags::HomePath { path, root, home },
                                checksum,
                                severity: None,
                                file_id,
                            }
                            .into(),
                            Ok((false, calculated)) => diags::ChecksumMismatch {
                                path: diags::HomePath { path, root, home },
                                checksum,
                                severity: None,
                                error: None,
                                calculated: Some(calculated),
                                file_id,
                            }
                            .into(),
                            Err(error) => diags::ChecksumMismatch {
                                path: diags::HomePath { path, root, home },
                                checksum,
                                severity: None,
                                error: Some(format!("{error:#}")),
                                calculated: None,
                                file_id,
                            }
                            .into(),
                        };

                        checksum_diags.lock().insert(absolute_path, diag);
                    });
                }
            });

            checksum_diags.into_inner().into_values()
        },
    );

    for diag in checksum_diags {
        pack.push(diag);
    }

    ret
}

pub(crate) enum ExecutableKind {
    Native(goblin::Hint),
    Interpreted(String),
}

fn check_is_executable(
    path: &crate::Path,
    exclude_archives: bool,
) -> anyhow::Result<Option<ExecutableKind>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut header = [0u8; 16];
    let read = file.read(&mut header)?;
    if read != header.len() {
        return Ok(None);
    }

    use goblin::Hint;

    match goblin::peek_bytes(&header)
        .map_err(|err| anyhow::format_err!("failed to peek bytes: {err}"))?
    {
        // Archive objects/libraries are not great (generally) to have in
        // crate packages, but they are not as easily
        Hint::Archive if exclude_archives => Ok(None),
        Hint::Unknown(_) => {
            // Check for shebang scripts
            if header[..2] != [0x23, 0x21] {
                return Ok(None);
            }

            // If we have a shebang, look to see if we have the newline, otherwise we need to read more bytes
            let mut hdr = [0u8; 256];
            let header = if !header.contains(&b'\n') {
                hdr[..16].copy_from_slice(&header);
                let read = file.read(&mut hdr[16..])?;
                &hdr[..read + 16]
            } else {
                &header[..]
            };

            let parse = || {
                let line_end = header.iter().position(|b| *b == b'\n')?;
                let line = std::str::from_utf8(&header[..line_end]).ok()?;

                // If it's a rust file, ignore it if the shebang is actually
                // an inner attribute
                if path.extension() == Some("rs") && line.starts_with("#![") {
                    return None;
                }

                // Shebangs scripts can't have any spaces in the actual interpreter, but there
                // can be an optional space between the shebang and the start of the interpreter
                let mut items = line.split(' ');
                let maybe_interpreter = items.next()?;
                let interpreter = if maybe_interpreter.ends_with("#!") {
                    items.next()?
                } else {
                    maybe_interpreter
                };

                // Handle (typically) /usr/bin/env being used as level of indirection
                // to make running scripts more friendly to run on a variety
                // of systems
                if interpreter.ends_with("/env") {
                    items.next()
                } else if let Some((_, bin)) = interpreter.rsplit_once('/') {
                    Some(bin)
                } else {
                    Some(interpreter)
                }
            };

            Ok(parse().map(|s| ExecutableKind::Interpreted(s.to_owned())))
        }
        Hint::COFF => Ok(None),
        hint => Ok(Some(ExecutableKind::Native(hint))),
    }
}

impl cfg::Checksum {
    fn checksum_file(path: &crate::Path) -> anyhow::Result<Self> {
        use std::io::Read;

        let mut file = std::fs::File::open(path)?;

        let digest = {
            let mut dc = ring::digest::Context::new(&ring::digest::SHA256);
            let mut chunk = [0; 8 * 1024];
            loop {
                let read = file.read(&mut chunk)?;
                if read == 0 {
                    break;
                }
                dc.update(&chunk[..read]);
            }
            dc.finish()
        };

        let mut bytes = [0; 32];
        bytes.copy_from_slice(digest.as_ref());
        Ok(Self(bytes))
    }

    /// Validates the files matches the expected SHA-256 checksum
    #[inline]
    fn validate_checksum(&self, path: &crate::Path) -> anyhow::Result<(bool, Self)> {
        let actual = Self::checksum_file(path)?;
        Ok((actual == *self, actual))
    }
}

fn check_workspace_duplicates(
    krates: &Krates,
    krate_spans: &crate::diag::KrateSpans<'_>,
    cfg: &cfg::WorkspaceDepsConfig,
    diags: &mut Vec<Pack>,
) {
    use crate::diag::Label;

    // Note this will ignore cases where a dependency is used as more than 1 kind etc,
    // but this check is not really meant for such simple cases
    if krates.workspace_members().count() <= 1 {
        return;
    }

    // Gather any direct dependencies that are declared more than once
    let mut deps = std::collections::BTreeMap::<
        _,
        Vec<(
            &crate::diag::ManifestDep<'_>,
            &crate::Krate,
            crate::diag::FileId,
        )>,
    >::new();

    for wsm in krates.workspace_members() {
        let krates::Node::Krate { id, krate, .. } = wsm else {
            continue; /* unreachable */
        };

        let Some(man) = krate_spans.manifest(id) else {
            continue;
        };

        for mdep in man.deps(true) {
            if mdep.dep.path.is_some() && !cfg.include_path_dependencies {
                continue;
            }

            deps.entry(&mdep.krate.id)
                .or_default()
                .push((mdep, krate, man.id));
        }
    }

    // Strip out any direct dependencies that aren't referenced multiple times in the workspace
    // Note this will retain in cases where the dependency is only used
    // by 1 crate, but as different dependency kinds, which is still useful
    // to catch
    deps.retain(|_, parents| parents.len() > 1);

    for (kid, parents) in deps {
        let total = parents.len();
        let mut labels = Vec::new();

        if let Some((ws_span, ws_id)) = krate_spans
            .workspace_span(kid)
            .zip(krate_spans.workspace_id)
        {
            labels.push(
                Label::secondary(ws_id, ws_span.key).with_message(format_args!(
                    "{}workspace dependency",
                    if ws_span.patched.is_some() {
                        "patched "
                    } else {
                        ""
                    }
                )),
            );

            if let Some(patched) = ws_span.patched {
                labels.push(
                    Label::secondary(ws_id, patched)
                        .with_message("note this is the original dependency that is patched"),
                );
            }

            if let Some(rename) = &ws_span.rename {
                labels.push(
                    Label::secondary(ws_id, rename.span)
                        .with_message("note the workspace dependency is renamed"),
                );
            }
        }

        let llen = labels.len();
        let has_workspace_declaration = llen != 0;

        for (mdep, _parent, id) in parents {
            // Unfortunately cargo doesn't allow `workspace = false`, so if
            // there are situations where the user wants to explicitly opt out
            // of the lint for a specific crate/crates/manifest they need to use
            // [package.metadata.cargo-deny.workspace-duplicates]
            // TODO: ...actually support this https://github.com/EmbarkStudios/cargo-deny/issues/677
            if mdep.workspace.is_some() {
                continue;
            }

            // A renamed dependency can never satisfy this lint by switching to
            // `workspace = true`: cargo does not support combining workspace
            // inheritance with a `package` rename (rust-lang/cargo#14673), so
            // this crate has no way to declare it that would not be flagged.
            // `parents` is already grouped by resolved krate id (see above), so
            // a rename here is not evidence of drift from the shared workspace
            // dependency -- it still resolves to the exact same crate.
            if mdep.rename.is_some() {
                continue;
            }

            labels.push(Label::primary(id, mdep.key_span));
        }

        if llen >= labels.len() {
            continue;
        }

        let Some(duplicate) = krates.node_for_kid(kid) else {
            log::error!("failed to find node for {kid}");
            continue;
        };

        let krates::Node::Krate {
            krate: duplicate, ..
        } = duplicate
        else {
            log::error!("{kid} pointed a crate feature, this should be impossible");
            continue;
        };

        let mut pack = Pack::with_kid(Check::Bans, duplicate.id.clone());
        pack.push(diags::WorkspaceDuplicate {
            duplicate,
            labels,
            severity: cfg.duplicates,
            has_workspace_declaration,
            total_uses: total,
        });
        diags.push(pack);
    }
}
