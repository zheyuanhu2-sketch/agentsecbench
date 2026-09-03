# Changelog

All notable changes use semantic versioning.

## Unreleased

- Add five paired synthetic coding-agent threat families covering repository instructions, issue
  content, generated fixtures, dependency findings, and pull-request documents.
- Add a deterministic, self-contained HTML report generated from canonical content-free result
  artifacts, with semantic tables and explicit interpretation boundaries.
- Preserve byte-reproducible showcase evidence across default Windows and Linux Git checkouts with
  an enforced LF attribute contract.
- Add a 60-second reviewer route without making unsupported production-model or adoption claims.

## 1.0.0 - 2026-07-16

- Publish the first stable AgentSecBench release while keeping the frozen v0.1 catalog fingerprint,
  result schemas, experiment contract, and deterministic reference metrics unchanged.
- Regenerate the machine-verifiable showcase and citation metadata for the exact 1.0.0 package.
- Mark distribution metadata as production/stable and retain typed-package support across Python
  3.11 through 3.14.
- Fix the reproducible-build interpreter at Python 3.11 in both CI and the tag workflow.
- Add exact-commit-pinned GitHub SLSA provenance attestations for both checksummed release packages.
- Finalize the public security-reporting, release-verification, and repository-protection process.

## 0.9.0 - 2026-07-16

- Add a checked-in deterministic showcase with canonical unsafe/secure result artifacts, exact
  semantic and file SHA-256 values, a machine-readable manifest, and a generated explanatory page.
- Add a repository-only showcase generator whose check mode rebuilds every published example
  byte-for-byte and rejects stale or extra files.
- Add citation metadata and public issue forms for bugs, benchmark proposals, and security-report
  routing.
- Mark the runtime wheel as a PEP 561 typed package and require the marker and classifier in
  distribution validation.
- Extend source, CI, release, and source-distribution gates to require the showcase and citation
  contract.

## 0.8.0 - 2026-07-16

- Add a cross-platform source and distribution release gate covering version/changelog agreement,
  local documentation links, documented CLI commands, synthetic fixture domains, archive safety,
  package metadata, console entry points, stale artifacts, and canonical checksums.
- Expand CI to Python 3.11 through 3.14 with separate static, test, dependency/secret-scan, and
  reproducible-build jobs, plus checksum-pinned Actionlint workflow validation.
- Scan complete Git history with checksum-pinned Gitleaks 8.30.1 and audit the locked dependency
  graph with `uv audit`.
- Upgrade pytest to the fixed 9.x line after the dependency audit identified vulnerable temporary
  directory handling in 8.4.2.
- Refresh the strict type and coverage toolchain to mypy 2.3 and pytest-cov 7.1, with all versions
  represented in the locked dependency graph.
- Switch dependency updates to the uv-native, lockfile-only Dependabot ecosystem so automated
  updates preserve manifest constraints and produce `uv.lock` changes accepted by locked CI.
- Enable the GitHub dependency graph, Dependabot vulnerability alerts, and automated security
  fixes; the 0.8 candidate has no open dependency alerts.
- Add a tag-gated workflow that reruns every quality and security check, requires byte-identical
  repeated builds, verifies a clean wheel install, and publishes SHA-256-checksummed GitHub assets.
- Document the synthetic-data review, responsible disclosure path, release process, and remaining
  v1.0 publication gates.

## 0.7.0 - 2026-07-16

- Add a loopback-only OpenAI-compatible adapter for Ollama, LM Studio, vLLM, and equivalent local
  servers without DNS, proxy, redirect, retry, or non-loopback URL surfaces.
- Add backward-compatible `agentsecbench.result.v2` model artifacts with explicit UUID trial IDs.
- Add `local-smoke`, `local-evaluate`, and a bounded two-to-five-trial `bailian-batch` command.
- Preserve every batch trial as a redacted result artifact, share one total request/token budget,
  and emit one canonical confidence-interval experiment summary.
- Extract and test the shared strict OpenAI-compatible request/response contract.

## 0.6.0 - 2026-07-16

- Add `agentsecbench.experiment.v1` summaries for repeated result-artifact trials.
- Compute overall and per-task Wilson score intervals for utility, attack success, false blocks,
  leakage, model completion, and protocol errors.
- Enforce exact package/catalog/mode/policy/provider/model/turn/task comparability and reject
  duplicate artifact digests that cannot establish independent runs.
- Add canonical atomic experiment output, source digests, and total token accounting.

## 0.5.0 - 2026-07-16

- Add the strict `agentsecbench.scenario.v1` external synthetic-catalog format.
- Reject duplicate keys, unknown fields/tools, oversized or linked files, invalid paths,
  malformed tool arguments, broken cross-references, duplicate provenance/approvals, label
  contradictions, and non-synthetic sensitive canaries.
- Add `catalog-validate` and `catalog-evaluate`, a Draft 2020-12 JSON Schema, and a runnable
  normal/attack example catalog.
- Strengthen built-in catalog validation with exact tool argument and resource-reference checks.

## 0.4.0 - 2026-07-16

- Add canonical `agentsecbench.result.v1` artifacts for deterministic and model evaluations.
- Exclude prompts, arguments, tool outputs, synthetic values, timestamps, and machine paths.
- Add bounded duplicate-key-safe loading, schema/metric consistency checks, atomic owner-only
  writes, stable SHA-256 digests, and artifact comparison.
- Add `--output`, `artifact-verify`, and `artifact-compare` CLI workflows.

## 0.3.0 - 2026-07-16

- Add a bounded, strict-JSON model/tool evaluation loop.
- Derive action provenance in the runtime instead of trusting model output.
- Hide evaluator action names, approvals, and provenance behind opaque policy identifiers.
- Add opt-in Bailian normal/attack evaluation with safe metadata-only output.
- Add offline malicious-model regression tests and document the first two-task `qwen-plus` pilot.

## 0.2.0 - 2026-07-16

- Add provider-neutral model adapters, resource budgets, secret redaction, and exact-host HTTPS.
- Add the opt-in Alibaba Cloud Model Studio `qwen-plus` adapter and smoke check.

## 0.1.0 - 2026-07-15

- Freeze 30 synthetic mail/file scenarios and their catalog fingerprint.
- Add unsafe and secure reference policies, in-memory tools, metrics, CI, and a threat model.
