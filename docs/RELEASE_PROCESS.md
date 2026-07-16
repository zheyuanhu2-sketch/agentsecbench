# Release process

AgentSecBench releases are built from exact semantic-version tags. The tag workflow publishes one
wheel, one source distribution, and `SHA256SUMS`; it does not publish to PyPI or change repository
visibility.

## Source gate

From a clean checkout:

```powershell
uv sync --locked --dev
uv run ruff format --check .
uv run ruff check .
uv run mypy src scripts
uv run pytest --cov=agentsecbench --cov-report=term-missing
uv run agentsecbench compare
uv audit --locked
uv run python scripts/release_gate.py source
```

The source gate requires one version across `pyproject.toml`, the package, and the first Changelog
entry. It verifies local Markdown links, README command names, required review files, and synthetic
fixture conventions. CI repeats tests on Python 3.11, 3.12, 3.13, and 3.14.

## Reproducible package gate

CI derives `SOURCE_DATE_EPOCH` from the release commit and performs two independent `uv build`
runs into separate runner-temporary directories outside the source tree. Keeping outputs outside
the source tree is mandatory: an in-tree first build would change the file set seen by the second
source-distribution build. `scripts/release_gate.py artifacts` validates archive paths, exact
package metadata, license, console entry point, runtime/source contents, and stale output
exclusion. The `compare` subcommand then requires both wheels and both source distributions to be
byte-identical. Finally, CI installs the wheel into an isolated environment and runs the
deterministic comparison.

## Security gate

The locked dependency graph must have no known OSV advisory. Gitleaks 8.30.1 is downloaded from
the official release, its Linux archive is checked against the pinned
`551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` SHA-256, and the complete Git
history is scanned with redacted output. Changing the scanner version requires reviewing and
updating both the version and checksum in CI and the release workflow.

Actionlint 1.7.12 is likewise downloaded from its official release, verified against its pinned
Linux archive SHA-256, and used to validate workflow syntax, expressions, action inputs, and shell
steps before source or release publication.

## Tag and publish

Only after every applicable pre-tag item in `PUBLICATION_CHECKLIST.md` is complete:

1. Set the intended version in `pyproject.toml` and `src/agentsecbench/__init__.py`.
2. Add the dated Changelog entry and run the complete source gate.
3. Merge the exact commit after all required GitHub checks pass.
4. Create and push the exact tag, for example `v1.0.0`.
5. The tag workflow reruns all gates, builds twice, writes canonical SHA-256 checksums, verifies an
   isolated install, and creates the GitHub release.
6. Download the three release assets and verify `SHA256SUMS` before announcing the release.

The workflow refuses a tag that differs from the package version. A failed workflow must be fixed
with a new commit and version/tag; published release assets are not silently replaced.

## GitHub publication transition

The current GitHub Free private repository cannot configure branch protection or private
vulnerability reporting. Immediately before public v1.0 publication:

1. confirm the previously exposed development provider key has been rotated;
2. make the repository public only when all repository-local gates are green;
3. enable private vulnerability reporting and verify the link in `SECURITY.md`;
4. enable a ruleset requiring the complete CI workflow on `main`, blocked force pushes, and blocked
   branch deletion;
5. recheck visibility, security settings, default branch, release assets, and checksum verification.

Repository visibility is an external state change and is deliberately not performed by CI.
