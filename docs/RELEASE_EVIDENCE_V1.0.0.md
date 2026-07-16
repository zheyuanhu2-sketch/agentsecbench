# AgentSecBench v1.0.0 release evidence

This record captures the independently checked evidence for the first public AgentSecBench
release. Times are from GitHub or Sigstore; hashes are lowercase SHA-256.

## Immutable source

- Release tag: [`v1.0.0`](https://github.com/zheyuanhu2-sketch/agentsecbench/releases/tag/v1.0.0)
- Annotated tag object: `1f00b78cae1a25dedfe486114f8cf6d667737d43`
- Dereferenced release commit: `a125aa446854a12d2741d1c7625bc91887d82955`
- Candidate CI:
  [`29504851600`](https://github.com/zheyuanhu2-sketch/agentsecbench/actions/runs/29504851600)
- Catalog fingerprint:
  `77b6e5ad903fc10f2b521e1951427c10bb061c9775c60878e6f7ecf642613311`

The tag was not moved during release recovery. The public release page identifies short commit
`a125aa4`, and the release source gate required the package, Changelog, citation, showcase, and tag
version to agree on `1.0.0`.

## Release execution

The initial tag run
[`29506196674`](https://github.com/zheyuanhu2-sketch/agentsecbench/actions/runs/29506196674)
passed the source, static, test, dependency, and complete-history secret gates, then correctly
rejected the sdist because release-only scanner files had been downloaded into the source tree.
No Release, asset, workflow artifact, or attestation was published by that run.

Recovery was implemented through protected
[PR #6](https://github.com/zheyuanhu2-sketch/agentsecbench/pull/6), merged as
`ff0c0edae8d4faa48375d3fc9248df7d1b51dfc7`. Main CI
[`29506686901`](https://github.com/zheyuanhu2-sketch/agentsecbench/actions/runs/29506686901)
passed all seven required jobs. The corrected workflow then checked out the unchanged `v1.0.0`
tag, required a clean source tree, rebuilt twice, verified both distributions and a clean wheel
install, published provenance, and created the Release in successful run
[`29506737737`](https://github.com/zheyuanhu2-sketch/agentsecbench/actions/runs/29506737737).

## Published assets

| Asset | Bytes | SHA-256 |
|---|---:|---|
| `agentsecbench-1.0.0-py3-none-any.whl` | 49,064 | `42261cb80c56931ced6e127676c96ccce9f98c7ba209895d6b1629f9ea8476a4` |
| `agentsecbench-1.0.0.tar.gz` | 129,466 | `dc62be3b002a46efb0a831dbe658ec4ae580e10f05d211d54d737b68df0c4454` |
| `SHA256SUMS` | 196 | `5d9b78644b55a26efc6f0f407e7e817ed00b128562473f950c7a39e0bb2e2ae0` |

All three uploaded assets were downloaded twice: once with GitHub CLI authentication and once
through direct anonymous HTTPS URLs. Both package hashes matched `SHA256SUMS` and the GitHub
Release API digests. The downloaded wheel and sdist passed `scripts/release_gate.py artifacts`;
the wheel installed alone under Python 3.11, exposed `py.typed`, and reproduced the reviewed
deterministic comparison.

## Provenance

`gh attestation verify` succeeded independently for both packages with:

```powershell
--repo zheyuanhu2-sketch/agentsecbench `
--signer-workflow zheyuanhu2-sketch/agentsecbench/.github/workflows/release.yml `
--deny-self-hosted-runners
```

The verified statement uses predicate `https://slsa.dev/provenance/v1`, names both package hashes
above as subjects, identifies a GitHub-hosted runner, and carries a Sigstore transparency-log
timestamp of `2026-07-16T22:28:48+08:00`.

Because this was an unpublished-tag recovery, the signed builder identity is the corrected
default-branch workflow at `ff0c0edae8d4faa48375d3fc9248df7d1b51dfc7`. The artifact source tag
is bound separately by the workflow's immutable-target preflight, explicit tag checkout, exact-tag
source gate, release page, and annotated-tag dereference to `a125aa4`. This distinction is retained
here instead of presenting the builder commit as the package source commit.

## Public repository controls

- Visibility: public.
- Default branch: `main`.
- License: MIT.
- Topics: `agent-security`, `ai-agents`, `llm-security`, `prompt-injection`, `python`,
  `security-benchmark`.
- Private vulnerability reporting: enabled.
- Dependency graph, Dependabot alerts, and automated security fixes: enabled; open alerts: zero.
- Ruleset: `main protection`, ID `19052039`, active with no bypass actors.
- Ruleset behavior: blocks branch deletion and non-fast-forward pushes, requires strict latest-main
  status, and requires the static gate, four Python test jobs, complete-history security scan, and
  reproducible package job.

The repository and release pages were fetched without authentication. They displayed the public
repository, README, MIT license, security policy, topics, `v1.0.0` as the latest release, and the
release commit `a125aa4`. The private-report URL redirected a signed-out session to GitHub login,
which is the expected access boundary for submitting a confidential report.

## Credential boundary

The repository owner confirmed that the development Alibaba Cloud Model Studio key previously
referenced in a private task conversation was replaced in DayFlow and revoked before repository
publication. No provider key is present in the repository, release assets, current environment, or
complete-history secret-scan findings.
