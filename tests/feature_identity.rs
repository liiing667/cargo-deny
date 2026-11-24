use cargo_deny::{
    Krates,
    test_utils::{self, Config},
};

fn load_metadata() -> krates::cm::Metadata {
    let contents =
        std::fs::read_to_string("tests/test_data/features-galore/metadata.json").unwrap();
    serde_json::from_str(&contents).unwrap()
}

fn gather(target: &str, config: &str) -> Vec<serde_json::Value> {
    let mut builder = krates::Builder::new();
    builder.include_targets(std::iter::once((target, vec![])));

    let krates: Krates = builder
        .build_with_metadata(load_metadata(), krates::NoneFilter)
        .unwrap();

    test_utils::gather_diagnostics::<cargo_deny::bans::cfg::Config, _, _>(
        &krates,
        cargo_deny::func_name!(),
        Config::new(config),
        |ctx, tx| cargo_deny::bans::check(ctx, None, tx),
    )
}

fn codes(diags: &[serde_json::Value]) -> Vec<&str> {
    diags
        .iter()
        .filter_map(|diag| diag.pointer("/fields/code").and_then(|code| code.as_str()))
        .collect()
}

#[test]
fn matching_exact_allow_list_passes() {
    let diags = gather(
        "x86_64-unknown-linux-gnu",
        "features = [{ name = 'features-galore', exact = true, allow = ['default', 'json', 'simple'] }]",
    );

    assert!(diags.is_empty(), "unexpected diagnostics: {diags:#?}");
}

#[test]
fn denied_feature_is_not_swallowed_by_exact_allow_list() {
    let diags = gather(
        "x86_64-unknown-linux-gnu",
        "features = [{ name = 'features-galore', exact = true, allow = ['default'], deny = ['json'] }]",
    );

    assert!(
        codes(&diags).contains(&"feature-banned"),
        "the denied default feature was swallowed: {diags:#?}"
    );
}

#[test]
fn unused_allow_is_reported() {
    let diags = gather(
        "x86_64-unknown-linux-gnu",
        "features = [{ name = 'features-galore', allow = ['default', 'json', 'simple', 'ssh'] }]",
    );

    assert!(
        codes(&diags).contains(&"unused-feature"),
        "the unused allow was not reported: {diags:#?}"
    );
}

#[test]
fn denied_feature_findings_keep_the_crate_version_identity() {
    let diags = gather(
        "x86_64-pc-windows-msvc",
        "multiple-versions = 'allow'\nfeatures = [{ name = 'windows-sys', deny = ['Win32_System_LibraryLoader'] }]",
    );

    let messages: Vec<_> = diags
        .iter()
        .filter(|diag| {
            diag.pointer("/fields/code").and_then(|code| code.as_str()) == Some("feature-banned")
        })
        .filter_map(|diag| {
            diag.pointer("/fields/message")
                .and_then(|message| message.as_str())
        })
        .collect();

    assert!(
        messages.iter().any(|m| m.contains("windows-sys = 0.36.1"))
            && messages.iter().any(|m| m.contains("windows-sys = 0.42.0")),
        "feature findings did not retain the crate versions: {diags:#?}"
    );
}
