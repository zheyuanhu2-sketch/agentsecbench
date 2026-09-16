# AgentSecBench OSS Application Readiness Design

## Goal

Make AgentSecBench ready for a truthful Codex for Open Source application by correcting its
public contribution posture, publishing a bounded roadmap, and exposing real contributor work
without adding hosted-model code or inventing adoption evidence.

## Scope

This change will deliver five connected improvements:

1. Replace the stale private-repository statement in `CONTRIBUTING.md` with a public contribution
   policy and an explicit maintainer decision process.
2. Add `docs/ROADMAP.md` with evidence-backed Now, Next, and Later milestones.
3. Add `.github/PULL_REQUEST_TEMPLATE.md` with reproducibility, synthetic-data, security, and
   documentation checks.
4. Link contribution guidance and the roadmap from `README.md`.
5. Open three public GitHub issues that correspond to roadmap work: two bounded newcomer tasks
   and one larger OpenAI provider integration task.

## Non-goals

- No OpenAI or other hosted-provider adapter implementation.
- No live API calls, API keys, billing setup, or model evaluation.
- No source-code, schema, benchmark-contract, package-version, or release change.
- No GitHub release or Codex for Open Source form submission.
- No invented stars, downloads, users, contributors, or ecosystem adoption claims.
- No issue created solely to make the repository appear active; every issue must describe useful,
  independently reviewable work that remains undone.

## Approaches considered

### Selected: application-readiness documentation plus real contribution entry points

Update the repository-facing documentation and PR workflow, then create three issues backed by the
published roadmap. This is the smallest change that fixes the current contradiction and gives an
application reviewer a credible path from project status to future maintenance work.

### Rejected: documentation-only cleanup

Correcting prose without opening any contribution work would leave the `good first issue` and
`help wanted` paths empty. It would improve consistency but not contributor readiness.

### Deferred: implement an official OpenAI provider adapter

An adapter requires a separately approved protocol design, mocked transport tests, threat-model
updates, credential handling, budget controls, and live-call boundaries. Adding it during an
application cleanup would mix documentation work with a security-sensitive feature.

## Repository documentation

### Contributing guide

`CONTRIBUTING.md` will state that AgentSecBench is a public open-source project and welcomes
changes that preserve its deterministic, synthetic-data-only, and side-effect-free core. It will
explain the expected workflow: choose or open an issue, create a focused branch, include tests for
behavior changes, run the documented gate, and submit a pull request with risks and residual
assumptions.

The guide will identify Zheyuan Hu as the current primary maintainer and state that benchmark
contract, security-boundary, and release decisions are made through reviewable pull requests.
Security reports will continue to use the private route in `SECURITY.md`, not public issues.

### Roadmap

`docs/ROADMAP.md` will separate plans by confidence and dependency:

- **Now:** contributor onboarding, scenario-authoring guidance, validation troubleshooting, and
  maintenance of the deterministic showcase and release gates.
- **Next:** design and implement an opt-in official OpenAI provider adapter only after its request
  schema, response schema, network boundary, retention assumptions, token accounting, redaction,
  and mocked tests are reviewed.
- **Later:** broaden independently reviewed scenario catalogs and repeated provider experiments
  while preserving exact catalog fingerprints and content-free artifacts.

The roadmap will distinguish intent from commitment and will not promise dates, funding, or model
support that has not been delivered.

### README entry points

The README project-status section will link directly to `CONTRIBUTING.md`, `docs/ROADMAP.md`, and
the public issue tracker. The first-screen benchmark claims and the stable v1.0 contract remain
unchanged.

## Pull-request workflow

`.github/PULL_REQUEST_TEMPLATE.md` will request:

- a concise change summary and linked issue;
- exact verification commands and outcomes;
- confirmation that new benchmark data is synthetic;
- confirmation that core behavior remains offline and side-effect free, or an explicit review of
  any changed network or tool boundary;
- documentation of security assumptions and residual risks;
- confirmation that generated artifacts and release contracts were refreshed when applicable.

The template is a review aid, not a substitute for CI or maintainer judgment.

## Public contribution issues

After repository files are ready, create these issues through the GitHub CLI:

1. **`docs: add a paired-scenario contributor walkthrough`** — labeled `documentation`,
   `good first issue`, and `help wanted`; document how to add one normal/attack pair, validate it,
   evaluate it, and report its fingerprint without including real data.
2. **`docs: add a catalog validation troubleshooting guide`** — labeled `documentation`,
   `good first issue`, and `help wanted`; map representative validation failures to safe fixes and
   reproduction commands without weakening fail-closed behavior.
3. **`feat: add an opt-in OpenAI Responses API adapter`** — labeled `enhancement` and
   `help wanted`; require a separate design, exact official endpoint, environment-only project
   key, bounded budgets, no retries or redirects, redaction tests, mocked transport coverage,
   explicit network approval, and threat-model documentation.

Each issue will include acceptance criteria, relevant file links, scope exclusions, and the full
safety boundary needed for an external contributor to assess the work without guessing.

## Delivery and external state

All repository-file changes will be made on `docs/oss-application-readiness` in an isolated
worktree. The branch will be pushed and proposed through a pull request because direct changes to
`main` would bypass the repository's existing review pattern.

Creating the three issues and opening the pull request are authorized repository-maintenance
actions within this change. Merging the pull request, publishing a release, configuring OpenAI
billing, creating API credentials, and submitting the application remain separate actions.

## Verification strategy

1. Check all new relative Markdown links and GitHub template paths.
2. Run formatting, lint, type-check, test coverage, deterministic comparison, dependency audit,
   source-release validation, and showcase byte verification using the existing contribution gate.
3. Inspect `git diff --check` and scan changed files for placeholders, private-repository wording,
   unsupported adoption claims, credentials, and personal data.
4. Verify the branch and pull-request CI before reporting the repository-file work as delivered.
5. Read back the created issues and confirm titles, labels, acceptance criteria, and URLs.

## Acceptance criteria

- No active contributor document describes AgentSecBench as private.
- README exposes clear contribution, roadmap, and issue-tracker entry points.
- The roadmap contains bounded, truthful work and distinguishes future plans from shipped code.
- The pull-request template preserves the benchmark's safety and reproducibility requirements.
- Two useful newcomer issues and one larger provider-integration issue are publicly accessible with
  accurate labels and acceptance criteria.
- The complete local quality gate and pull-request CI pass without changing the benchmark output,
  package version, or stable v1.0 contract.
- No release is published and no OpenAI application is submitted.
