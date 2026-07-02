# Containment + full workspace validation transcript (M1 gate)

Captured on the `xsy-0008-docs-m1-gate` worktree from a clean build.
This is the canonical validation command CI runs (`just check` = fmt,
clippy `-D warnings`, nextest, doc, audit).

```
cargo fmt --all -- --check
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets -- -D warnings
    Checking cfg-if v1.0.4
    Checking itoa v1.0.18
    Checking once_cell v1.21.4
    Checking pin-project-lite v0.2.17
    Checking futures-core v0.3.32
    Checking bytes v1.12.0
    Checking log v0.4.33
    Checking memchr v2.8.2
    Checking bitflags v2.13.0
    Checking futures-task v0.3.32
    Checking libc v0.2.186
    Checking serde_core v1.0.228
    Checking zmij v1.0.21
    Checking slab v0.4.12
    Checking stable_deref_trait v1.2.1
    Checking thiserror v2.0.18
    Checking zerofrom v0.1.8
    Checking smallvec v1.15.2
   Compiling num-traits v0.2.19
    Checking fastrand v2.4.1
    Checking litemap v0.8.2
    Checking writeable v0.6.3
    Checking utf8_iter v1.0.4
    Checking ryu v1.0.23
    Checking core-foundation-sys v0.8.7
    Checking yoke v0.8.3
    Checking tracing-core v0.1.36
    Checking percent-encoding v2.3.2
    Checking futures-util v0.3.32
    Checking zeroize v1.9.0
    Checking tower-service v0.3.3
    Checking icu_properties_data v2.2.0
    Checking zerocopy v0.8.52
    Checking icu_normalizer_data v2.2.0
    Checking untrusted v0.9.0
    Checking equivalent v1.0.2
    Checking rustls-pki-types v1.15.0
    Checking hashbrown v0.17.1
    Checking zerovec v0.11.6
    Checking zerotrie v0.2.4
    Checking try-lock v0.2.5
    Checking regex-syntax v0.8.11
    Checking iana-time-zone v0.1.65
    Checking form_urlencoded v1.2.2
    Checking httparse v1.10.1
    Checking sync_wrapper v1.0.2
    Checking want v0.3.1
    Checking futures-channel v0.3.32
    Checking atomic-waker v1.1.2
    Checking httpdate v1.0.3
    Checking num-conv v0.2.2
    Checking powerfmt v0.2.0
    Checking http v1.4.2
    Checking deranged v0.5.8
    Checking tracing v0.1.44
    Checking time-core v0.1.9
    Checking unsafe-libyaml v0.2.11
    Checking tower-layer v0.3.3
    Checking ipnet v2.12.0
    Checking subtle v2.6.1
    Checking base64 v0.22.1
    Checking utf8parse v0.2.2
    Checking anstyle v1.0.14
    Checking anstyle-parse v1.0.0
    Checking colorchoice v1.0.5
    Checking anstyle-query v1.1.5
    Checking is_terminal_polyfill v1.70.2
    Checking webpki-roots v1.0.8
    Checking clap_lex v1.1.0
    Checking mime v0.3.17
    Checking lazy_static v1.5.0
    Checking tinystr v0.8.3
    Checking potential_utf v0.1.5
    Checking indexmap v2.14.0
    Checking anstream v1.0.0
    Checking strsim v0.11.1
    Checking sharded-slab v0.1.7
    Checking tracing-log v0.2.0
    Checking errno v0.3.14
    Checking socket2 v0.6.4
    Checking mio v1.2.1
    Checking getrandom v0.4.3
    Checking signal-hook-registry v1.4.8
    Checking rustix v1.1.4
    Checking icu_locale_core v2.2.0
    Checking nix v0.30.1
    Checking icu_collections v2.2.0
    Checking getrandom v0.3.4
    Checking getrandom v0.2.17
    Checking clap_builder v4.6.0
    Checking http-body v1.0.1
    Checking thread_local v1.1.9
    Checking rand_core v0.9.5
    Checking ring v0.17.14
    Checking http-body-util v0.1.3
    Checking tokio v1.52.3
    Checking matchit v0.8.4
    Checking nu-ansi-term v0.50.3
    Checking anyhow v1.0.103
    Checking hex v0.4.3
    Checking wait-timeout v0.2.1
    Checking axum-core v0.5.6
    Checking bit-vec v0.8.0
    Checking fnv v1.0.7
    Checking time v0.3.53
    Checking quick-error v1.2.3
    Checking rand_xorshift v0.4.0
    Checking unarray v0.1.4
    Checking bit-set v0.8.0
    Checking icu_provider v2.2.0
    Checking icu_normalizer v2.2.0
    Checking icu_properties v2.2.0
    Checking tempfile v3.27.0
    Checking regex-automata v0.4.14
    Checking rusty-fork v0.3.1
    Checking serde v1.0.228
    Checking serde_json v1.0.150
    Checking serde_path_to_error v0.1.20
    Checking rustls-webpki v0.103.13
    Checking chrono v0.4.45
    Checking serde_yaml v0.9.34+deprecated
    Checking serde_urlencoded v0.7.1
    Checking clap v4.6.1
    Checking rustls v0.23.41
    Checking idna_adapter v1.2.2
    Checking x0x-symphony-core v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-core)
    Checking idna v1.1.0
    Checking url v2.5.8
    Checking matchers v0.2.0
    Checking tracing-subscriber v0.3.23
    Checking ppv-lite86 v0.2.21
    Checking rand_chacha v0.9.0
    Checking rand v0.9.4
    Checking x0x-symphony-tracker-git-jsonl v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-tracker-git-jsonl)
    Checking proptest v1.11.0
    Checking hyper v1.10.1
    Checking tower v0.5.3
    Checking x0x-symphony-runner-shell v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-runner-shell)
    Checking x0x-symphony-workspace v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-workspace)
    Checking x0x-symphony-orchestrator v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-orchestrator)
    Checking tower-http v0.6.11
    Checking tokio-rustls v0.26.4
    Checking hyper-util v0.1.20
    Checking hyper-rustls v0.27.9
    Checking axum v0.8.9
    Checking reqwest v0.12.28
    Checking x0x-symphony-bin v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-bin)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.21s
RUSTFLAGS="-D warnings" cargo nextest run --workspace --all-features
   Compiling regex-syntax v0.8.11
   Compiling num-traits v0.2.19
   Compiling tokio v1.52.3
   Compiling wait-timeout v0.2.1
   Compiling fnv v1.0.7
   Compiling quick-error v1.2.3
   Compiling bit-vec v0.8.0
   Compiling rand_xorshift v0.4.0
   Compiling unarray v0.1.4
   Compiling rusty-fork v0.3.1
   Compiling bit-set v0.8.0
   Compiling chrono v0.4.45
   Compiling regex-automata v0.4.14
   Compiling proptest v1.11.0
   Compiling x0x-symphony-tracker-git-jsonl v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-tracker-git-jsonl)
   Compiling matchers v0.2.0
   Compiling tracing-subscriber v0.3.23
   Compiling hyper v1.10.1
   Compiling x0x-symphony-workspace v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-workspace)
   Compiling x0x-symphony-runner-shell v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-runner-shell)
   Compiling tower v0.5.3
   Compiling tokio-rustls v0.26.4
   Compiling x0x-symphony-orchestrator v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-orchestrator)
   Compiling tower-http v0.6.11
   Compiling x0x-symphony-core v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-core)
   Compiling hyper-util v0.1.20
   Compiling hyper-rustls v0.27.9
   Compiling axum v0.8.9
   Compiling reqwest v0.12.28
   Compiling x0x-symphony-bin v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-bin)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 5.73s
────────────
 Nextest run ID c3ebe95a-9ae2-415b-95d9-405fa22f0b8f with nextest profile: default
    Starting 71 tests across 19 binaries
        PASS [   0.011s] ( 1/71) x0x-symphony-bin::bind rejects_unspecified_bind_address
        PASS [   0.010s] ( 2/71) x0x-symphony-core::stub_round_trip stub_traits_support_round_trip
        PASS [   0.011s] ( 3/71) x0x-symphony-orchestrator reconcile::tests::stale_self_past_ttl
        PASS [   0.011s] ( 4/71) x0x-symphony-bin::bind accepts_loopback_bind_address
        PASS [   0.013s] ( 5/71) x0x-symphony-orchestrator reconcile::tests::fresh_self_within_ttl
        PASS [   0.012s] ( 6/71) x0x-symphony-orchestrator concurrency::tests::per_state_cap_is_independent_of_global
        PASS [   0.012s] ( 7/71) x0x-symphony-orchestrator concurrency::tests::global_cap_limits_acquires
        PASS [   0.012s] ( 8/71) x0x-symphony-orchestrator reconcile::tests::foreign_claim_is_never_self
        PASS [   0.012s] ( 9/71) x0x-symphony-orchestrator concurrency::tests::untracked_state_uses_only_global_cap
        PASS [   0.014s] (10/71) x0x-symphony-bin::config_check repository_workflow_passes_config_check
        PASS [   0.016s] (11/71) x0x-symphony-bin::cli_snapshots config_show_snapshot
        PASS [   0.018s] (12/71) x0x-symphony-bin::cli_snapshots routes_snapshot
        PASS [   0.017s] (13/71) x0x-symphony-orchestrator reconcile::tests::bad_heartbeat_is_an_error
        PASS [   0.018s] (14/71) x0x-symphony-bin::cli_snapshots tasks_snapshot
        PASS [   0.017s] (15/71) x0x-symphony-bin::cli_snapshots status_snapshot
        PASS [   0.017s] (16/71) x0x-symphony-bin::cli_snapshots proofs_list_snapshot
        PASS [   0.018s] (17/71) x0x-symphony-bin::api_auth symphony_routes_require_bearer_token
        PASS [   0.019s] (18/71) x0x-symphony-bin::config_check missing_required_blocks_fail_config_check
        PASS [   0.011s] (19/71) x0x-symphony-orchestrator retry::tests::exhaustion_is_attempts_capped
        PASS [   0.011s] (20/71) x0x-symphony-orchestrator retry::tests::max_attempts_clamped_to_one
        PASS [   0.011s] (21/71) x0x-symphony-orchestrator retry::tests::backoff_doubles_then_caps
        PASS [   0.013s] (22/71) x0x-symphony-orchestrator::orchestration reconcile_releases_stale_and_keeps_fresh_self_claims
        PASS [   0.013s] (23/71) x0x-symphony-orchestrator::orchestration budget_slot_released_on_workspace_create_error
        PASS [   0.010s] (24/71) x0x-symphony-runner-shell::presets claude_code_preset_resolves_expected_command_args_env
        PASS [   0.013s] (25/71) x0x-symphony-orchestrator::orchestration concurrency_cap_one_claims_only_one_of_two
        PASS [   0.013s] (26/71) x0x-symphony-orchestrator::orchestration end_to_end_smoke_todo_to_review
        PASS [   0.009s] (27/71) x0x-symphony-runner-shell::presets codex_preset_resolves_expected_command_args_env
        PASS [   0.009s] (28/71) x0x-symphony-runner-shell::presets glm_preset_yaml_resolves_to_runnable_spec
        PASS [   0.009s] (29/71) x0x-symphony-runner-shell::presets kimi_preset_yaml_resolves_to_runnable_spec
        PASS [   0.009s] (30/71) x0x-symphony-runner-shell::presets pi_preset_yaml_resolves_to_runnable_spec
        PASS [   0.009s] (31/71) x0x-symphony-runner-shell::presets workflow_yaml_overrides_claude_code_without_template_rendering
        PASS [   0.010s] (32/71) x0x-symphony-runner-shell::presets minimax_preset_yaml_resolves_to_runnable_spec
        PASS [   0.016s] (33/71) x0x-symphony-orchestrator::orchestration retry_exhaustion_moves_issue_to_blocked
        PASS [   0.008s] (34/71) x0x-symphony-runner-shell::run_smoke secret_like_workflow_env_requires_explicit_allowlist
        PASS [   0.007s] (35/71) x0x-symphony-workspace::containment accepts_non_reserved_dotted_identifier
        PASS [   0.009s] (36/71) x0x-symphony-tracker-git-jsonl::git_jsonl multiprocess_claim_child
        PASS [   0.011s] (37/71) x0x-symphony-tracker-git-jsonl::git_jsonl schema_violation_is_structured
        PASS [   0.018s] (38/71) x0x-symphony-runner-shell::run_smoke argv_is_static_and_prompt_is_only_issue_content_channel
        PASS [   0.009s] (39/71) x0x-symphony-workspace::containment cleanup_preserves_non_terminal_and_deletes_terminal
        PASS [   0.011s] (40/71) x0x-symphony-tracker-git-jsonl::git_jsonl fetch_candidates_resolves_blockers_live_by_id
        PASS [   0.009s] (41/71) x0x-symphony-workspace::containment destroy_refuses_replaced_root_symlink
        PASS [   0.008s] (42/71) x0x-symphony-workspace::containment destroy_refuses_symlink_escape_after_create
        PASS [   0.008s] (43/71) x0x-symphony-workspace::containment hook_sensitive_env_denied_without_explicit_allowlist
        PASS [   0.013s] (44/71) x0x-symphony-workspace::containment hook_pipefail_is_enforced
        PASS [   0.013s] (45/71) x0x-symphony-workspace::containment hook_sensitive_env_allowed_when_explicitly_allowlisted
        PASS [   0.013s] (46/71) x0x-symphony-workspace::containment poisoned_parent_environment_does_not_leak_to_hook
        PASS [   0.012s] (47/71) x0x-symphony-workspace::containment rejects_absolute_path_identifier
        PASS [   0.013s] (48/71) x0x-symphony-workspace::containment rejects_4096_byte_identifier
        PASS [   0.009s] (49/71) x0x-symphony-workspace::containment rejects_dangerous_shell_env_variables
        PASS [   0.008s] (50/71) x0x-symphony-workspace::containment rejects_nested_parent_traversal_identifier_a_dotdot_b
        PASS [   0.030s] (51/71) x0x-symphony-runner-shell::run_smoke shell_runner_streams_prompt_to_arbitrary_child_process
        PASS [   0.033s] (52/71) x0x-symphony-runner-shell::run_smoke poisoned_parent_environment_does_not_leak_to_child_env
        PASS [   0.007s] (53/71) x0x-symphony-workspace::containment rejects_trailing_dot_identifier
        PASS [   0.009s] (54/71) x0x-symphony-workspace::containment rejects_parent_traversal_identifier_dotdot_etc
        PASS [   0.009s] (55/71) x0x-symphony-workspace::containment rejects_root_itself_identifier
        PASS [   0.010s] (56/71) x0x-symphony-workspace::containment rejects_preplanted_symlink_inside_root_pointing_outside
        PASS [   0.009s] (57/71) x0x-symphony-workspace::containment rejects_slash_and_nul_identifiers
        PASS [   0.008s] (58/71) x0x-symphony-workspace::containment rejects_unicode_fullwidth_dot_identifier
        PASS [   0.008s] (59/71) x0x-symphony-workspace::containment rejects_windows_reserved_device_name_identifier
        PASS [   0.009s] (60/71) x0x-symphony-workspace::containment workspace_path_is_deterministic_from_sanitized_issue_id
        PASS [   0.037s] (61/71) x0x-symphony-workspace::containment hook_timeout_produces_structured_outcome
        PASS [   0.062s] (62/71) x0x-symphony-tracker-git-jsonl::git_jsonl release_transition_returns_issue_to_todo_without_git
        PASS [   0.076s] (63/71) x0x-symphony-orchestrator::orchestration shutdown_mid_run_releases_claim_and_preserves_workspace
        PASS [   0.090s] (64/71) x0x-symphony-tracker-git-jsonl::git_jsonl unknown_fields_are_byte_stable_after_parse_serialize
        PASS [   0.212s] (65/71) x0x-symphony-runner-shell::run_smoke proof_timeout_kills_forked_children_process_group
        PASS [   0.214s] (66/71) x0x-symphony-workspace::hook_process_group proof_hook_timeout_kills_forked_child_process_group
        PASS [   0.253s] (67/71) x0x-symphony-runner-shell::run_smoke proof_chatty_child_does_not_grow_output_memory_unboundedly
        PASS [   0.268s] (68/71) x0x-symphony-tracker-git-jsonl::git_jsonl block_and_fetch_claimed_round_trip_blocked_reason_survives
        PASS [   0.318s] (69/71) x0x-symphony-tracker-git-jsonl::git_jsonl round_trip_create_claim_heartbeat_handoff_review
        PASS [   0.351s] (70/71) x0x-symphony-tracker-git-jsonl::git_jsonl multiprocess_claims_serialize_on_git_index_lock
        PASS [   0.516s] (71/71) x0x-symphony-orchestrator::orchestration heartbeat_keeps_claim_fresh_during_long_run
────────────
     Summary [   0.530s] 71 tests run: 71 passed, 0 skipped
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
    Checking bitflags v2.13.0
    Checking num-traits v0.2.19
    Checking tokio v1.52.3
    Checking x0x-symphony-core v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-core)
    Checking regex-syntax v0.8.11
 Documenting x0x-symphony-core v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-core)
    Checking nix v0.30.1
    Checking chrono v0.4.45
    Checking regex-automata v0.4.14
    Checking x0x-symphony-tracker-git-jsonl v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-tracker-git-jsonl)
 Documenting x0x-symphony-tracker-git-jsonl v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-tracker-git-jsonl)
    Checking matchers v0.2.0
    Checking tracing-subscriber v0.3.23
    Checking hyper v1.10.1
    Checking tower v0.5.3
    Checking tokio-rustls v0.26.4
    Checking x0x-symphony-runner-shell v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-runner-shell)
    Checking x0x-symphony-orchestrator v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-orchestrator)
    Checking x0x-symphony-workspace v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-workspace)
 Documenting x0x-symphony-orchestrator v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-orchestrator)
 Documenting x0x-symphony-runner-shell v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-runner-shell)
 Documenting x0x-symphony-workspace v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-workspace)
    Checking tower-http v0.6.11
    Checking hyper-util v0.1.20
    Checking hyper-rustls v0.27.9
    Checking axum v0.8.9
    Checking reqwest v0.12.28
    Checking x0x-symphony-bin v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-bin)
 Documenting x0x-symphony-bin v0.0.0 (/private/tmp/xsy-wave/wt-0008/crates/x0x-symphony-bin)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 3.58s
   Generated /private/tmp/xsy-wave/wt-0008/target/doc/x0x_symphony_bin/index.html and 7 other files
```
