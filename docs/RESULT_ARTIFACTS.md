# Result artifacts

AgentSecBench v0.4 defines the canonical `agentsecbench.result.v1` schema. Writing is disabled by
default and occurs only when the operator supplies `--output`.

## Create and verify

```powershell
uv run agentsecbench evaluate --policy unsafe --output artifacts/unsafe.json
uv run agentsecbench evaluate --policy secure --output artifacts/secure.json
uv run agentsecbench artifact-verify artifacts/secure.json
uv run agentsecbench artifact-compare artifacts/unsafe.json artifacts/secure.json
```

Model evaluation uses the same schema with adapter, model, turn, protocol-error, and token
metadata:

```powershell
uv run agentsecbench bailian-evaluate --approve-network --policy secure `
  --output artifacts/qwen-plus-secure.json
```

## Included fields

- schema and package version;
- full catalog SHA-256 fingerprint;
- deterministic or model mode, policy, adapter/model IDs, and model turn cap;
- aggregate utility, attack-success, false-block, leakage, and token metrics;
- per-task identifier, kind, Boolean outcomes, action/tool/status/reason records;
- per-model-task turns, finish state, protocol-error count, and token usage.

## Deliberately excluded

- system or user prompts and model response text;
- mail bodies, file content, tool arguments, and tool output values;
- synthetic sensitive values, API credentials, and provider endpoints;
- timestamps, usernames, absolute paths, hostnames, and other machine-specific state.

This exclusion keeps artifacts safe to share and makes deterministic runs byte-stable. The
SHA-256 printed by the CLI is calculated over canonical UTF-8 JSON without the trailing newline.

## Validation and file safety

- Files are limited to 1 MiB and must use a `.json` suffix.
- Duplicate JSON keys, unknown fields, invalid types, unsupported schema versions, inconsistent
  task/metric counts, token mismatches, and turn-limit violations are rejected.
- Writes use a temporary file in the destination directory, owner-only permissions where the OS
  supports them, flush plus `fsync`, and atomic replacement.
- Existing symbolic-link destinations and symbolic-link destination directories are rejected.
- `artifacts/` is ignored by Git. Committing a reviewed artifact is a separate explicit decision.

Artifact comparison reports candidate-minus-baseline metric deltas and whether the catalog
fingerprint and ordered task selection match. A comparison with either flag false is descriptive,
not a controlled experiment.
