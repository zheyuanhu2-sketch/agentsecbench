# Reproducible showcase

This page is generated from the frozen built-in catalog and the two reference policies by
`scripts/showcase.py`. CI recreates every linked JSON file and this page byte-for-byte. The
snapshot contains evaluator metadata only: no prompts, tool arguments, tool outputs, message
bodies, file contents, endpoints, credentials, or synthetic sensitive values.

Catalog SHA-256: `77b6e5ad903fc10f2b521e1951427c10bb061c9775c60878e6f7ecf642613311`. Package version: `1.0.0`.

## Deterministic reference result

| Policy | Utility success | Attack success | False blocks | Leakage |
|---|---:|---:|---:|---:|
| Unsafe | 100% | 100% | 0% | 100% |
| Secure | 100% | 0% | 0% | 0% |

The secure-minus-unsafe delta is +0% utility,
-100% attack success,
+0% false blocks, and
-100% leakage. Both artifacts use the same catalog and ordered task
selection.

## Checked-in evidence

| File | Canonical artifact SHA-256 | File SHA-256 |
|---|---|---|
| [`unsafe.result.json`](../examples/showcase/unsafe.result.json) | `5eed7047ae925717a84c0086a7750678e89659379f3fddfad0e2371b55efb90b` | `ba9336248fcb1e09beabfc7ee74e65838a4942d43c1330ee24ed02f25f28beac` |
| [`secure.result.json`](../examples/showcase/secure.result.json) | `409211bbc6779550e23b8af355bf8ab863a0b8ad4c396cb24f2b2d7b2c31e28f` | `a7c776aea33f058b161a03966fb311ce5fe867e8134fed09ac8a871b9c7b2915` |
| [`manifest.json`](../examples/showcase/manifest.json) | n/a | `501ca3a214f26734e4ab75ea0671b393d378d68d3f0bfdcabebb95c5fa895f72` |

The artifact digest follows the public artifact contract and excludes the trailing newline. The
file digest covers the exact checked-in bytes.

## Reproduce

```powershell
uv sync --locked --dev
uv run python scripts/showcase.py check
uv run agentsecbench artifact-verify examples/showcase/unsafe.result.json
uv run agentsecbench artifact-verify examples/showcase/secure.result.json
uv run agentsecbench artifact-compare examples/showcase/unsafe.result.json `
  examples/showcase/secure.result.json --json
```

To intentionally regenerate the snapshot after an approved version or benchmark-contract change:

```powershell
uv run python scripts/showcase.py generate
```

Review every resulting diff. A changed catalog fingerprint, task selection, metric, action record,
or digest is a benchmark-contract change, not formatting noise.

## Interpretation boundary

These values demonstrate the harness and the intentionally contrasting reference policies. They
do not establish that a language model, provider, or production agent is secure. Model claims
require identified repeated trials, retained redacted artifacts, confidence intervals, and the
limitations described in [`EXPERIMENTS.md`](EXPERIMENTS.md).
