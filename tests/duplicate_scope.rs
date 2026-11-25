use cargo_deny::{bans, test_utils::*};

fn duplicates(cfg: &str) -> (Vec<serde_json::Value>, Vec<bans::DupGraph>) {
    let krates = KrateGather::new("duplicate_scope").gather();
    let graphs = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    let graph_sink = graphs.clone();

    let diags = gather_diagnostics::<bans::cfg::Config, _, _>(
        &krates,
        "duplicate_scope",
        cfg.to_owned().into(),
        move |ctx, tx| {
            bans::check(
                ctx,
                Some(Box::new(move |graph| {
                    graph_sink.lock().push(graph);
                    Ok(())
                })),
                tx,
            );
        },
    );

    let graphs = std::mem::take(&mut *graphs.lock());
    (diags, graphs)
}

fn duplicate_diag(diags: &[serde_json::Value]) -> &serde_json::Value {
    diags
        .iter()
        .find(|diag| {
            diag.pointer("/fields/code").and_then(|code| code.as_str()) == Some("duplicate")
        })
        .expect("expected a duplicate diagnostic")
}

fn version<'a>(identity: &'a bans::ScopeIdentity, version: &str) -> &'a bans::VersionScope {
    identity
        .versions()
        .iter()
        .find(|scope| scope.version() == version)
        .unwrap_or_else(|| panic!("expected version {version} in the finding"))
}

/// Dev-only versions are removed from the default finding, but their identity
/// and original dependency edges are still retained.
#[test]
fn filtered_dev_version_keeps_original_edges() {
    let (diags, graphs) = duplicates(
        r#"
multiple-versions = 'deny'
multiple-versions-include-dev = false
"#,
    );

    let diag = duplicate_diag(&diags);
    let graph_versions = diag
        .pointer("/fields/graphs")
        .and_then(|graphs| graphs.as_array())
        .unwrap()
        .iter()
        .filter_map(|graph| graph.pointer("/Krate/version").and_then(|v| v.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(graph_versions, ["0.1.0", "0.3.0"]);

    let graph = graphs.last().expect("expected a dotgraph");
    assert_eq!(graph.scope_identity.name(), "dupe");

    let v1 = version(&graph.scope_identity, "0.1.0");
    assert_eq!(v1.scope(), bans::ScopeKind::Transitive);
    assert_eq!(
        v1.edges()
            .iter()
            .map(|edge| edge.kind())
            .collect::<Vec<_>>(),
        // Both original edges are retained even though only the normal edge
        // makes this version part of the non-dev finding.
        [bans::EdgeKind::Normal, bans::EdgeKind::Dev]
    );

    let filtered = graph.scope_identity.filtered_versions();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].version(), "0.2.0");
    assert_eq!(filtered[0].status, bans::VersionStatus::DevFiltered);
    assert_eq!(filtered[0].scope(), bans::ScopeKind::Dev);
    assert!(
        filtered[0]
            .edges()
            .iter()
            .any(|edge| edge.kind() == bans::EdgeKind::Dev && edge.edge_id() > 0)
    );

    let serialized = serde_json::to_value(&graph.scope_identity).unwrap();
    assert_eq!(serialized["filtered_versions"][0]["version"], "0.2.0");
    assert_eq!(serialized["filtered_versions"][0]["scope"], "dev");
}

/// A crate with `deny-multiple-versions` must not be hidden just because the
/// other version is only reachable through a dev edge.
#[test]
fn deny_multiple_versions_reaches_dev_scope() {
    let (diags, graphs) = duplicates(
        r#"
multiple-versions = 'allow'
multiple-versions-include-dev = false

[[deny]]
name = "dupe"
deny-multiple-versions = true
"#,
    );

    let diag = duplicate_diag(&diags);
    assert_eq!(
        diag.pointer("/fields/severity")
            .and_then(|sev| sev.as_str()),
        Some("error")
    );

    let graph = graphs.last().expect("expected a dotgraph");
    let v2 = version(&graph.scope_identity, "0.2.0");
    assert_eq!(v2.scope(), bans::ScopeKind::Dev);
    assert!(
        v2.edges()
            .iter()
            .any(|edge| edge.kind() == bans::EdgeKind::Dev)
    );
}

/// Text and JSON inclusion graphs agree when the same version is reached via
/// both normal and dev edges from one parent.
#[test]
fn text_and_json_graphs_use_same_scope() {
    let (diags, graphs) = duplicates(
        r#"
multiple-versions = 'deny'
multiple-versions-include-dev = true
"#,
    );

    let diag = duplicate_diag(&diags);
    let json_graphs = diag
        .pointer("/fields/graphs")
        .and_then(|graphs| graphs.as_array())
        .unwrap();

    fn count_dev_kinds(value: &serde_json::Value, count: &mut usize) {
        match value {
            serde_json::Value::Object(map) => {
                if map.get("kind").and_then(|kind| kind.as_str()) == Some("dev") {
                    *count += 1;
                }
                for value in map.values() {
                    count_dev_kinds(value, count);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    count_dev_kinds(value, count);
                }
            }
            _ => {}
        }
    }

    let mut json_dev_edges = 0;
    count_dev_kinds(
        &serde_json::Value::Array(json_graphs.clone()),
        &mut json_dev_edges,
    );
    assert_eq!(json_dev_edges, 1, "only dupe 0.2.0 is dev scoped");

    let graph = graphs.last().expect("expected a dotgraph");
    assert_eq!(graph.graph.matches("label=\"dev\"").count(), 1);

    let v1 = version(&graph.scope_identity, "0.1.0");
    assert_eq!(
        v1.edges()
            .iter()
            .map(|edge| edge.kind())
            .collect::<Vec<_>>(),
        [bans::EdgeKind::Normal, bans::EdgeKind::Dev]
    );
}
