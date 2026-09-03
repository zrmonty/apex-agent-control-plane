# GitHub Actions CI Speedup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Reduce repeat GitHub Actions wall-clock time by caching Rust and Docker artifacts, isolating the feature image, and overlapping independent live acceptance checks.

**Architecture:** Add job-scoped Cargo caches to the Rust workflows and a CI-only Compose overlay using GitHub's BuildKit cache backend per image scope. Add a separate feature-image service so the optional gateway artifact cannot overwrite the default runtime tag. Preserve all runtime proofs while overlapping only independent acceptance work and building the default control image early.

**Tech Stack:** GitHub Actions, actions/cache, Docker BuildKit/buildx, Docker Compose, Cargo workspace, Bash.

**Spec:** User-approved CI speedup design from the current conversation, based on the current workflow files.

## Global Constraints

- Preserve every existing Rust, SAST, live mTLS, Postgres, Valkey, Keycloak, adversarial, and overlay-validation gate.
- Keep release Docker builds and feature combinations; caching changes persistence, not coverage.
- Keep cache scopes separate for ingest, control, control-Postgres, and provider images.
- Keep GitHub-only cache configuration out of normal local Compose usage.
- Do not change application behavior, credentials, ports, base-image digests, or runtime security settings.

---

### Task 1: Add workflow cache and cancellation policy

**Files:**
- Modify: .github/workflows/ci.yml
- Modify: .github/workflows/live-mtls-e2e.yml

- [ ] Add a top-level concurrency group to both workflows, keyed by workflow and ref, with cancel-in-progress enabled.
- [ ] Add actions/cache@v5 to rust-ingest, rust-control-plane, and rust-agent-supervisor, and to the live workflow before Rust commands. Cache ~/.cargo/registry, ~/.cargo/git, and the repository-root target directory. Key by runner OS, job id, and hashFiles('**/Cargo.lock'); restore from the job prefix.
- [ ] Add pip caching and the SDK pyproject dependency path to Python setup steps that install SDK or SAST packages.
- [ ] Run git diff --check and search the workflow files for the new cache/concurrency entries.
- [ ] Commit as: ci: cache Rust and Python dependencies.

### Task 2: Add the CI-only BuildKit cache overlay and feature image

**Files:**
- Create: deploy/compose/compose.ci-cache.yaml
- Create: deploy/compose/live-mtls/compose.ci-cache.yaml
- Modify: .github/workflows/live-mtls-e2e.yml

- [ ] Create cache anchors for ingest, control, control-Postgres, and reference-provider images. Each anchor must use cache_from type=gha and cache_to type=gha,mode=max with a distinct scope.
- [ ] Override ingest-gateway, control-plane-api, clickhouse-projection, archive-provider, control-plane-api-pg-a, and control-plane-api-pg-b with the matching cache anchor.
- [ ] Add an ingest-gateway-feature-build service in the CI overlay. It must use image apex-event-ingest-pg-ref:latest, the repository-root context, apps/event-ingest/Dockerfile, the approved base-image arguments, CARGO_FEATURES valkey,postgres, and a ci-build profile. It must never be started.
- [ ] Add docker/setup-buildx-action@v4 to the live workflow and grant actions write permission needed to export the GitHub cache.
- [ ] Include compose.ci-cache.yaml as the last Compose file in every gateway/control build definition used by the live workflow.
- [ ] Replace the same-tag optional build with a build of ingest-gateway-feature-build. Remove the redundant default gateway rebuild.
- [ ] Validate both normal and ci-build Compose configurations with docker compose config --quiet. Do not use the GHA cache overlay for the local image build.
- [ ] Commit as: ci: persist BuildKit caches and isolate feature image.

### Task 3: Overlap safe live work and reuse the early control image

**Files:**
- Modify: .github/workflows/live-mtls-e2e.yml

- [ ] Include control-plane-api in the first parallel image build. Retain the later control build command as a cache-hit assertion before control startup.
- [ ] Replace sequential MinIO, Azure, and GCS acceptance steps with one Bash step. Run the three independent Python commands in the background, capture each output under RUNNER_TEMP, wait for all PIDs, print all logs, and fail if any command fails. Preserve --allow-missing-legal-hold for MinIO and the optional cloud environment for Azure/GCS.
- [ ] Update workflow comments so they describe the separate feature tag and early cached control build.
- [ ] Validate the base gateway Compose file, the full control overlay configuration, and git diff --check.
- [ ] Commit as: ci: overlap independent live acceptance gates.

### Task 4: Verify, integrate, and measure

**Files:**
- Verify: .github/workflows/ci.yml
- Verify: .github/workflows/live-mtls-e2e.yml
- Verify: deploy/compose/compose.ci-cache.yaml

- [ ] Run git diff master...HEAD --check.
- [ ] Run normal local default gateway/control image builds and the feature image build, confirming the default and feature tags remain separate.
- [ ] Fast-forward codex/ci-speedup onto master and push.
- [ ] Watch the new CI and Live runs with gh run watch --exit-status.
- [ ] Confirm the pushed commit matches origin/master and the working tree is clean.
- [ ] Report cache-hit evidence from the warm remote build and the measured runtime of the live workflow.
