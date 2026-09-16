# AgentSecBench OSS Application Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make AgentSecBench ready for a truthful Codex for Open Source application by fixing its public contribution posture, publishing a bounded roadmap, and exposing real contributor work.

**Architecture:** Keep the benchmark code and stable v1.0 contract unchanged. Improve only repository-facing Markdown and GitHub contribution surfaces, then verify the existing release gates before opening a pull request and three scoped issues.

**Tech Stack:** Markdown, GitHub issue and pull-request templates, PowerShell, GitHub CLI, Python 3.11-3.14 project tooling through `uv`.

## Global Constraints

- Do not implement an OpenAI or other hosted-provider adapter in this change.
- Do not make live API calls, create API keys, configure billing, or run hosted-model evaluations.
- Do not change source code, schemas, the frozen benchmark contract, package version, or release artifacts.
- Do not publish a GitHub release, merge the pull request, or submit the Codex for Open Source application.
- Do not invent stars, downloads, users, contributors, or ecosystem adoption claims.
- Every public issue must describe useful, independently reviewable work that remains undone.
- Preserve the deterministic, synthetic-data-only, side-effect-free core and its existing complete quality gate.

---

## File Structure

- Modify `CONTRIBUTING.md`: public contribution policy, workflow, maintainer process, and safety requirements.
- Create `docs/ROADMAP.md`: evidence-backed Now, Next, and Later work with no dates or unsupported promises.
- Create `.github/PULL_REQUEST_TEMPLATE.md`: review checklist for reproducibility, synthetic data, trust boundaries, and release contracts.
- Modify `README.md`: links to contributing, roadmap, and the issue tracker from Project status.
- No source, schema, generated showcase, package, or release file changes.

---

### Task 1: Publish the contributor-facing repository documentation

**Files:**
- Modify: `CONTRIBUTING.md`
- Create: `docs/ROADMAP.md`
- Create: `.github/PULL_REQUEST_TEMPLATE.md`
- Modify: `README.md`
- Test: repository-local Markdown and claim checks

**Interfaces:**
- Consumes: the safety rules in `SECURITY.md`, provider gate in `docs/MODEL_ADAPTERS.md`, and existing command gate in `CONTRIBUTING.md`.
- Produces: stable contributor entry points for the README, GitHub pull requests, and public issue descriptions.

- [ ] **Step 1: Record the pre-change failures**

Run:

```powershell
rg -n "currently private" CONTRIBUTING.md
Test-Path docs/ROADMAP.md
Test-Path .github/PULL_REQUEST_TEMPLATE.md
$readmeLinks = rg -n "CONTRIBUTING.md|docs/ROADMAP.md|/issues" README.md
if ($LASTEXITCODE -eq 1) { 'README contributor entry points incomplete as expected' } else { $readmeLinks }
```

Expected:

- `CONTRIBUTING.md` reports the stale private-repository sentence.
- Both `Test-Path` calls print `False`.
- README has no complete set of contributor, roadmap, and issue-tracker links.

- [ ] **Step 2: Replace `CONTRIBUTING.md` with the public contribution contract**

Use `apply_patch` to replace the file with this complete content:

```markdown
# Contributing

AgentSecBench is a public open-source project. Contributions are welcome when they preserve the
benchmark's deterministic, synthetic-data-only, and side-effect-free core.

## Before you start

- Use the issue tracker to check for related work or open a proposal.
- Use the private vulnerability-reporting route in `SECURITY.md` for suspected vulnerabilities.
- Never add credentials, real personal data, confidential repository content, malware, or actions
  that cause real external side effects.
- Read `docs/SCENARIO_CATALOGS.md` before changing benchmark data and
  `docs/MODEL_ADAPTERS.md` before proposing a provider integration.

## Contribution requirements

Contributions must:

1. use synthetic data only;
2. include tests for security-relevant behavior;
3. distinguish benchmark ground truth from controls visible to the policy under test;
4. avoid network, subprocess, and host-filesystem side effects in the core runtime;
5. document new assumptions and residual risks.

## Development workflow

1. Create a focused branch linked to an issue.
2. Add or update tests for every behavior or security-boundary change.
3. Document changed assumptions and residual risks.
4. Run the complete local gate below.
5. Open a pull request using the repository template.

## Complete local gate

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy src scripts
uv run pytest --cov=agentsecbench --cov-report=term-missing
uv run agentsecbench compare
uv run agentsecbench catalog-validate examples/coding-agent-scenarios-v1.json
uv audit --locked
uv run python scripts/release_gate.py source
uv run python scripts/showcase.py check
```

## Review and maintenance

Zheyuan Hu is the current primary maintainer. Benchmark-contract, security-boundary, and release
decisions are made through reviewable pull requests. A maintainer may request a smaller scope,
additional adversarial tests, or explicit threat-model changes before accepting security-sensitive
work.

GitHub CI additionally tests Python 3.11 through 3.14, scans the complete Git history with a
checksum-pinned Gitleaks binary, builds the wheel and source distribution twice from one source
epoch, and verifies a clean wheel install.
```

- [ ] **Step 3: Create `docs/ROADMAP.md`**

Use `apply_patch` to create a roadmap containing these exact sections and boundaries:

```markdown
# Roadmap

This roadmap describes intended maintenance work, not promised dates or shipped functionality.
Items move only after design review, tests, and the repository's quality and security gates pass.

## Now

- Improve contributor onboarding with a paired normal/attack scenario walkthrough.
- Document representative catalog-validation failures and safe fixes without weakening fail-closed behavior.
- Maintain the deterministic coding-agent showcase, supported Python matrix, dependency audit,
  full-history secret scan, and reproducible release checks.

## Next

- Design an opt-in adapter for the official OpenAI Responses API.
- Freeze request and response contracts in mocked tests before any live request.
- Require an exact official endpoint, environment-only project credential, explicit network approval,
  bounded tokens/turns/timeouts/response bytes, no redirects or retries, and redacted errors.
- Document provider retention and data-handling assumptions in the threat model.

## Later

- Add independently reviewed synthetic scenario catalogs for additional coding-agent workflows.
- Run repeated, identified provider experiments whose results retain exact catalog fingerprints.
- Keep result artifacts content-free: no prompts, tool arguments, tool outputs, endpoints, or secrets.

## Out of scope

- Claims that deterministic reference-policy results establish production-model security.
- Real credentials, personal data, confidential repositories, malware, or real external side effects.
- A generic arbitrary-URL client or an automatically enabled hosted-provider integration.
```

- [ ] **Step 4: Create `.github/PULL_REQUEST_TEMPLATE.md`**

Use `apply_patch` to create this review surface:

```markdown
## Summary

Describe the problem and the smallest change that solves it.

Closes #

## Verification

List the exact commands run and their outcomes.

## Safety and reproducibility checklist

- [ ] New or changed benchmark data is synthetic and contains no credentials or personal data.
- [ ] Behavior changes include tests, including adversarial coverage where security-relevant.
- [ ] The deterministic core remains offline and side-effect free, or changed boundaries are documented.
- [ ] Security assumptions and residual risks are documented.
- [ ] Generated artifacts, fingerprints, and release contracts were refreshed when applicable.
- [ ] The complete local gate in `CONTRIBUTING.md` passes.

## Residual risks

Describe remaining risks or write `None identified` with a brief reason.
```

- [ ] **Step 5: Add README contributor entry points**

Use `apply_patch` to add this paragraph at the end of `## Project status`, before `## Safety`:

```markdown
Contributions are welcome through the [contribution guide](CONTRIBUTING.md). Planned work is kept
in the [public roadmap](docs/ROADMAP.md), and bounded proposals can be discussed in the
[issue tracker](https://github.com/zheyuanhu2-sketch/agentsecbench/issues).
```

- [ ] **Step 6: Verify the documentation change**

Run:

```powershell
$required = @(
  'CONTRIBUTING.md',
  'docs/ROADMAP.md',
  '.github/PULL_REQUEST_TEMPLATE.md',
  'README.md'
)
$required | ForEach-Object {
  if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Missing file: $_" }
}
if (rg -n "currently private" CONTRIBUTING.md README.md docs/ROADMAP.md .github/PULL_REQUEST_TEMPLATE.md) {
  throw 'Active documentation still describes the repository as currently private'
}
rg -n "CONTRIBUTING.md|docs/ROADMAP.md|agentsecbench/issues" README.md
rg -n "synthetic|side-effect|SECURITY.md|MODEL_ADAPTERS.md" CONTRIBUTING.md
rg -n "## Now|## Next|## Later|## Out of scope" docs/ROADMAP.md
rg -n "## Verification|Safety and reproducibility checklist|Residual risks" .github/PULL_REQUEST_TEMPLATE.md
git diff --check
```

Expected: all required files exist; no stale private wording is found; each required section is
reported; `git diff --check` exits 0.

- [ ] **Step 7: Commit the repository documentation**

Run:

```powershell
git add CONTRIBUTING.md README.md docs/ROADMAP.md .github/PULL_REQUEST_TEMPLATE.md
git commit -m "docs: prepare public contribution workflow"
```

Expected: one commit containing only the four intended repository-facing files.

---

### Task 2: Run the complete repository quality gate

**Files:**
- Test: all changed documentation plus the unchanged package and generated evidence

**Interfaces:**
- Consumes: the exact complete gate published by `CONTRIBUTING.md`.
- Produces: fresh local evidence that documentation changes did not alter benchmark or release behavior.

- [ ] **Step 1: Run static and type checks**

Run:

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy src scripts
```

Expected: every command exits 0 with no formatting, lint, or type errors.

- [ ] **Step 2: Run tests and deterministic benchmark checks**

Run:

```powershell
uv run pytest --cov=agentsecbench --cov-report=term-missing
uv run agentsecbench compare
uv run agentsecbench catalog-validate examples/coding-agent-scenarios-v1.json
```

Expected: 163 tests pass, total coverage is at least 90%, deterministic secure/unsafe metrics match
the checked-in contract, and the coding-agent catalog validates.

- [ ] **Step 3: Run supply-chain and release checks**

Run:

```powershell
uv audit --locked
uv run python scripts/release_gate.py source
uv run python scripts/showcase.py check
```

Expected: no known dependency vulnerability is reported; source and showcase gates exit 0 without
changing generated files.

- [ ] **Step 4: Inspect the final local diff and commit state**

Run:

```powershell
git status --short
git diff --check origin/main...HEAD
git diff --stat origin/main...HEAD
git diff --name-only origin/main...HEAD
$unexpected = rg -n "TB[D]|TO[D]O|FIXM[E]|currently private" CONTRIBUTING.md README.md docs/ROADMAP.md .github/PULL_REQUEST_TEMPLATE.md
if ($LASTEXITCODE -eq 0) { $unexpected; throw 'Unexpected placeholder or stale wording found' }
if ($LASTEXITCODE -ne 1) { throw 'Placeholder scan failed to run' }
```

Expected: the worktree is clean; diff check exits 0; the changed-file list contains only the design,
plan, and four approved repository-facing files; the placeholder/stale-wording scan has no matches.

---

### Task 3: Push the branch and open a pull request

**Files:**
- External state: branch `docs/oss-application-readiness`
- External state: one GitHub pull request against `main`

**Interfaces:**
- Consumes: verified commits from Tasks 1 and 2.
- Produces: a reviewable public diff and GitHub Actions evidence without merging it.

- [ ] **Step 1: Push the verified branch**

Run:

```powershell
git push -u origin docs/oss-application-readiness
```

Expected: the remote branch is created and the local branch tracks it.

- [ ] **Step 2: Open the pull request**

Run:

```powershell
$body = @'
## Summary

- correct the stale private-repository contribution posture
- publish a bounded public roadmap
- add a pull-request safety and reproducibility checklist
- expose contributor and issue-tracker entry points from the README

## Verification

- `uv run ruff format --check .`
- `uv run ruff check .`
- `uv run mypy src scripts`
- `uv run pytest --cov=agentsecbench --cov-report=term-missing`
- `uv run agentsecbench compare`
- `uv run agentsecbench catalog-validate examples/coding-agent-scenarios-v1.json`
- `uv audit --locked`
- `uv run python scripts/release_gate.py source`
- `uv run python scripts/showcase.py check`

## Boundaries

No source, schema, benchmark-contract, package-version, release, hosted-model, credential, or API
billing change is included. This pull request does not submit the Codex for Open Source application.
'@
gh pr create --repo zheyuanhu2-sketch/agentsecbench `
  --base main `
  --head docs/oss-application-readiness `
  --title "docs: prepare OSS application contribution workflow" `
  --body $body
```

Expected: GitHub returns one new pull-request URL. Do not merge it.

- [ ] **Step 3: Wait for pull-request checks**

Run:

```powershell
$pr = gh pr view --repo zheyuanhu2-sketch/agentsecbench --json number --jq .number
gh pr checks $pr --repo zheyuanhu2-sketch/agentsecbench --watch
```

Expected: all required GitHub Actions checks complete successfully. If any check fails, inspect the
exact failed log, make the smallest correction on the same branch, rerun the full relevant local
gate, commit, push, and wait again.

---

### Task 4: Open and verify the public contribution issues

**Files:**
- External state: two `good first issue` documentation issues
- External state: one `help wanted` provider-integration issue

**Interfaces:**
- Consumes: the approved roadmap and public repository paths from Task 1.
- Produces: three honest, independently actionable contributor entry points.

- [ ] **Step 1: Create the paired-scenario walkthrough issue**

Run:

```powershell
$body = @'
## Problem

The catalog contract is documented, but a first-time contributor does not yet have a concise,
end-to-end walkthrough for adding a matched normal/attack scenario pair.

Relevant files:

- https://github.com/zheyuanhu2-sketch/agentsecbench/blob/main/docs/SCENARIO_CATALOGS.md
- https://github.com/zheyuanhu2-sketch/agentsecbench/blob/main/schemas/scenario-catalog-v1.schema.json
- https://github.com/zheyuanhu2-sketch/agentsecbench/blob/main/examples/coding-agent-scenarios-v1.json

## Acceptance criteria

- Add a contributor walkthrough that authors one small normal/attack pair using synthetic data only.
- Explain task IDs, evaluator-only actions, policy-visible controls, provenance, approvals, forbidden
  actions, and synthetic sensitive canaries.
- Include exact `catalog-validate` and secure/unsafe `catalog-evaluate` commands.
- Show how to report the resulting exact catalog fingerprint and why different fingerprints are not
  directly comparable without analysis.
- Keep the built-in v0.1 catalog, schema, network behavior, and provider behavior unchanged.
- Run the complete local gate in `CONTRIBUTING.md`.

## Safety boundary

Do not include real credentials, personal data, confidential repository content, malware, or real
external side effects. Do not weaken validator checks to make an example pass.
'@
gh issue create --repo zheyuanhu2-sketch/agentsecbench `
  --title "docs: add a paired-scenario contributor walkthrough" `
  --label documentation `
  --label "good first issue" `
  --label "help wanted" `
  --body $body
```

Expected: GitHub returns one new issue URL.

- [ ] **Step 2: Create the validation troubleshooting issue**

Run:

```powershell
$body = @'
## Problem

Catalog validation fails closed with precise errors, but contributors do not yet have a compact
troubleshooting guide that maps common failures to safe corrections.

Relevant files:

- https://github.com/zheyuanhu2-sketch/agentsecbench/blob/main/docs/SCENARIO_CATALOGS.md
- https://github.com/zheyuanhu2-sketch/agentsecbench/blob/main/src/agentsecbench/scenario_io.py
- https://github.com/zheyuanhu2-sketch/agentsecbench/blob/main/schemas/scenario-catalog-v1.schema.json

## Acceptance criteria

- Document representative failures for duplicate IDs, unknown tools, invalid or traversing paths,
  conflicting labels, missing attack canaries, and non-synthetic classification.
- For every failure, include a minimal synthetic example, the exact validation command, the expected
  error class or message fragment, and a safe correction.
- Keep examples free of credentials, personal data, confidential content, malware, and external
  side effects.
- Do not weaken, bypass, catch-and-ignore, or normalize away validator failures.
- Run the complete local gate in `CONTRIBUTING.md`.

## Scope

Documentation and synthetic examples only. Changes to schema semantics or loader behavior require a
separate proposal and tests.
'@
gh issue create --repo zheyuanhu2-sketch/agentsecbench `
  --title "docs: add a catalog validation troubleshooting guide" `
  --label documentation `
  --label "good first issue" `
  --label "help wanted" `
  --body $body
```

Expected: GitHub returns one new issue URL.

- [ ] **Step 3: Create the OpenAI Responses API adapter issue**

Run:

```powershell
$body = @'
## Problem

AgentSecBench has provider-neutral model contracts and strict hosted-provider boundaries, but it does
not yet have an adapter for the official OpenAI Responses API. This issue is intentionally larger
than a newcomer task and requires a separately reviewed design before implementation.

Relevant files:

- https://github.com/zheyuanhu2-sketch/agentsecbench/blob/main/docs/MODEL_ADAPTERS.md
- https://github.com/zheyuanhu2-sketch/agentsecbench/blob/main/agentsecbench-threat-model.md
- https://github.com/zheyuanhu2-sketch/agentsecbench/tree/main/src/agentsecbench/adapters

## Required design and acceptance criteria

- Freeze the exact official endpoint plus request and response schemas in mocked tests.
- Load a project-scoped credential from a named environment variable at request time; never store or
  print it.
- Require explicit network approval for every live CLI path.
- Bound requests, turns, input/output tokens, timeout, and response bytes before transport work.
- Reject redirects, retries, arbitrary base URLs, URL credentials, environment proxies, and
  non-JSON responses.
- Redact errors and add credential canaries plus mocked transport tests.
- Define token accounting, retention assumptions, supported model identifiers, and update the threat
  model before any live pilot.
- Use synthetic inputs only. Ordinary CI must not require credentials or a live API call.
- Run the complete local gate in `CONTRIBUTING.md`.

## Out of scope

No generic OpenAI-compatible URL client, production security claim, real repository data, or
automatic hosted-model execution.
'@
gh issue create --repo zheyuanhu2-sketch/agentsecbench `
  --title "feat: add an opt-in OpenAI Responses API adapter" `
  --label enhancement `
  --label "help wanted" `
  --body $body
```

Expected: GitHub returns one new issue URL.

- [ ] **Step 4: Read back and verify all three issues**

Run:

```powershell
gh issue list --repo zheyuanhu2-sketch/agentsecbench --state open --limit 20 `
  --json number,title,labels,url `
  --jq '.[] | [.number,.title,([.labels[].name] | join(",")),.url] | @tsv'
```

Expected: exactly the three new non-PR issues appear with their intended labels and public URLs.
Open each issue through `gh issue view` and verify that its acceptance criteria and scope exclusions
match this plan.

---

### Task 5: Final acceptance and handoff

**Files:**
- Inspect: local branch, pull request, checks, and three GitHub issues

**Interfaces:**
- Consumes: all local and remote evidence from Tasks 1-4.
- Produces: a precise implemented/verified/pushed/PR-open report for user review.

- [ ] **Step 1: Verify local and remote identity**

Run:

```powershell
git status --short --branch
git rev-parse HEAD
git rev-parse origin/docs/oss-application-readiness
gh pr view --repo zheyuanhu2-sketch/agentsecbench `
  --json number,title,state,isDraft,url,headRefName,baseRefName,statusCheckRollup
```

Expected: the worktree is clean; local and remote branch SHAs match; the pull request is open,
targets `main`, and has successful checks.

- [ ] **Step 2: Check the acceptance criteria line by line**

Confirm and report:

- active contributor documentation no longer calls the repository private;
- README links contributing, roadmap, and issue tracker;
- roadmap future work is bounded and truthful;
- PR template contains the safety and reproducibility checklist;
- two newcomer issues and one provider issue are publicly accessible;
- full local gate and pull-request CI passed;
- benchmark outputs, package version, and stable v1.0 contract did not change;
- no release was published, no PR was merged, and no OpenAI application was submitted.

- [ ] **Step 3: Stop for user review**

Provide the pull-request URL, issue URLs, commit SHA, local verification counts, and CI status. Do not
merge the pull request or submit the OpenAI application without a new explicit user request.
