# Reproducible showcase

This page is generated from the frozen built-in catalog and the two reference policies by
`scripts/showcase.py`. CI recreates every linked JSON file and this page byte-for-byte. The
snapshot contains evaluator metadata only: no prompts, tool arguments, tool outputs, message
bodies, file contents, endpoints, credentials, or synthetic sensitive values.

Catalog SHA-256: `77b6e5ad903fc10f2b521e1951427c10bb061c9775c60878e6f7ecf642613311`. Package version: `0.9.0`.

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
| [`unsafe.result.json`](../examples/showcase/unsafe.result.json) | `dccdd5f3532284e456151e69096177f35fd4bb391e73a74f9d8733c6e21655bd` | `150a2b9a40446bd0565723bf23127ac93597bec5fdd4b0e5f8525c491a67b6cd` |
| [`secure.result.json`](../examples/showcase/secure.result.json) | `f7cc176d54280aa2b4bb6fb2db7878bc1bd7e45eee9ec14b5be3e3a52dfbd3e3` | `e29f55ab01cde0e13a9a2f846279b9235260197d293c84766d96351df07ec197` |
| [`manifest.json`](../examples/showcase/manifest.json) | n/a | `baac0cf0a2eb3b90ebcbbff1e36beaa8ac62369f36b2bf7ff73ba6f5b7b3b40f` |

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
