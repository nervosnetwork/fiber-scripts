const CI_WORKFLOW: &str = include_str!("../../.github/workflows/ci.yml");
const FIND_CLANG: &str = include_str!("../../scripts/find_clang");
const MAKEFILE: &str = include_str!("../../Makefile");

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected project validation config to contain `{needle}`"
    );
}

#[test]
fn ci_workflow_validates_pull_requests_to_main() {
    assert_contains(CI_WORKFLOW, "pull_request:");
    assert_contains(CI_WORKFLOW, "branches: [ \"main\" ]");
}

#[test]
fn ci_workflow_runs_pr_validation_layers() {
    for required_step in [
        "make prepare",
        "make fmt-check",
        "make clippy CARGO_ARGS=\"--all-targets\"",
        "scripts/reproducible_build_docker",
        "make test",
    ] {
        assert_contains(CI_WORKFLOW, required_step);
    }
}

#[test]
fn makefile_exposes_local_pr_validation_entrypoint() {
    for required_target in [
        "fmt-check:",
        "pr-verify: fmt-check",
        "$(MAKE) build",
        "$(MAKE) test",
    ] {
        assert_contains(MAKEFILE, required_target);
    }
}

#[test]
fn clang_discovery_rejects_apple_clang_for_riscv_contract_builds() {
    assert_contains(FIND_CLANG, "Apple clang");
}
