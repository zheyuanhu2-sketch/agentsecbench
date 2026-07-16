# Synthetic data review

## Decision

All benchmark fixtures checked into AgentSecBench are synthetic. They contain no production
credentials, personal records, real mailbox contents, or live tool targets. This decision covers
the frozen built-in catalog, the shipped external-catalog example, tests, and documentation
examples at version 0.8.0.

Repository authorship and Git commit metadata identify the maintainer and are not benchmark data.
Official documentation URLs identify their publishers and are not tool targets.

## Reviewed fixture inventory

| Surface | Inventory | Synthetic controls |
|---|---:|---|
| Built-in catalog | 30 scenarios | Generated names and identifiers; in-memory resources only |
| Normal mail | 10 scenarios | `example.local` recipient and sender domain |
| Attack mail | 5 scenarios | `evil.test` attacker domain and `SYNTHETIC-SECRET-*` canaries |
| Normal files | 10 scenarios | Relative paths under synthetic `notes/` and `reports/` stores |
| Attack files | 5 scenarios | Relative paths under synthetic `uploads/` and `public/` stores |
| External example | 2 scenarios | Same reserved domains, relative paths, and synthetic canaries |

No model-generated action can contact any domain or host path. Mail and file operations terminate
in a per-scenario in-memory environment.

## Automated evidence

`scripts/release_gate.py source` loads and validates both catalogs, scans every scenario string for
email addresses, permits only the reviewed synthetic domains, and requires every protected value
to use the `SYNTHETIC-` prefix. Existing catalog validation separately enforces tool schemas,
resource references, path safety, approvals, provenance order, and label consistency.

The CI security job also:

- audits the exact dependency graph in `uv.lock` against OSV;
- downloads Gitleaks 8.30.1 from its official release and verifies the pinned archive SHA-256;
- checks the complete Git history (`fetch-depth: 0`), not only the current tree;
- redacts any candidate secret from logs.

A local complete-history scan over all nine commits through `2d67b3c` on 2026-07-16 examined
approximately 429 KB and reported no leaks. The same scan is a required CI and tag-release gate,
so later history cannot rely on this one-time result.

## Review boundary

Automated matching cannot prove that arbitrary prose is synthetic. The inventory above therefore
combines fixture-level manual review, reserved identifiers, parser invariants, canary conventions,
and full-history secret detection. Any new fixture changes this review scope and must update this
record before release.
