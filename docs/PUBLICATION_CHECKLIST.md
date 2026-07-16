# v1.0 publication checklist

The GitHub repository remained private until every required item was complete. A checked item has
current evidence; an old successful run does not cover later commits.

The completed evidence record is
[`RELEASE_EVIDENCE_V1.0.0.md`](RELEASE_EVIDENCE_V1.0.0.md).

## Repository contract

- [x] Complete and review the repository-grounded threat model.
- [x] Freeze and fingerprint the built-in scenario catalog.
- [x] Publish strict result-artifact, experiment-summary, and external-scenario contracts.
- [x] Confirm checked-in benchmark fixtures are synthetic; retain the review in `DATA_REVIEW.md`.
- [x] Document architecture, assumptions, model boundaries, statistics, and limitations.
- [x] Document the responsible-disclosure policy and maintainer route in `SECURITY.md`.
- [x] Publish a machine-verifiable showcase with canonical artifacts, exact hashes, and explicit
  interpretation limits.
- [x] Add machine-readable citation metadata and structured synthetic-only issue forms.

## Automated quality and security

- [x] Observe green CI for the candidate commit on Python 3.11 through 3.14.
- [x] Pin Python dependencies in `uv.lock` and GitHub Actions by full commit SHA.
- [x] Enable monthly dependency update review with Dependabot.
- [x] Enable the dependency graph, Dependabot alerts, and automated security fixes; verify zero
  open alerts for the candidate.
- [x] Audit the locked dependency graph with no known advisories.
- [x] Scan the complete Git history with a checksum-pinned Gitleaks release.
- [x] Verify README commands, local links, versions, Changelog, and synthetic fixture conventions.
- [x] Regenerate the checked-in showcase byte-for-byte in CI and the tag release gate.
- [x] Build the wheel and source distribution twice and require byte-identical output.
- [x] Validate distribution metadata/archive safety and execute a clean wheel install.

## Release and public GitHub settings

- [x] Add an exact-tag release workflow that reruns all gates and publishes `SHA256SUMS`.
- [x] Rotate the development provider key referenced in the private model-pilot notes.
- [x] Review and approve the exact v1.0.0 version, Changelog, and release commit.
- [x] Make the repository public after all other pre-publication items pass.
- [x] Enable and test GitHub private vulnerability reporting immediately after publication.
- [x] Enable a `main` ruleset requiring all CI jobs and blocking force push/deletion.
- [x] Push the exact `v1.0.0` tag and observe a green release workflow.
- [x] Publish and independently verify GitHub provenance attestations for both package archives.
- [x] Independently download and verify the wheel, source archive, and `SHA256SUMS`.
- [x] Verify repository visibility, default branch, license, topics, security settings, and release
  presentation from a signed-out browser session.
