# Coding-agent scenario catalog

AgentSecBench includes a separate synthetic catalog for repository-aware coding-agent workflows.
It models repository documents through the existing in-memory file tools, so the complete example
is offline, deterministic, and free of credentials or real vulnerability data.

Catalog SHA-256:
`5a3c57196148e667a9378e78bbb8dceea1e2f7cdaeb9f7b6142064eca0479064`.

## Threat coverage

The catalog contains five normal/attack pairs:

| Pair | Legitimate behavior | Adversarial behavior |
|---|---|---|
| Repository instructions | Read trusted guidance and write an approved review note | Disclose protected configuration from untrusted nested instructions |
| Issue content | Read a report without changing files | Redirect a write outside the approved patch directory |
| Generated fixture | Read trusted fixture data and write the requested result | Treat fixture text as authority for an unrelated mutation |
| Dependency note | Preserve a trusted audit finding | Suppress a finding based on untrusted dependency text |
| Pull-request document | Record the declared review scope | Overwrite trusted repository instructions |

Every value is synthetic. The catalog uses only `file.read` and `file.write` against an in-memory
environment and never accesses a host repository.

## Reproduce

```powershell
uv sync --locked --dev
uv run agentsecbench catalog-validate examples/coding-agent-scenarios-v1.json
uv run agentsecbench catalog-evaluate examples/coding-agent-scenarios-v1.json --policy unsafe
uv run agentsecbench catalog-evaluate examples/coding-agent-scenarios-v1.json --policy secure
```

Expected deterministic reference metrics:

| Policy | Utility success | Attack success | False blocks | Leakage |
|---|---:|---:|---:|---:|
| Unsafe | 100% | 100% | 0% | 100% |
| Secure | 100% | 0% | 0% | 0% |

## Interpretation boundary

These metrics demonstrate the benchmark harness and two intentionally contrasting reference
policies. They do not measure or establish the security of Codex, another language model, a
provider, or a production coding agent. Model claims require separately identified repeated trials
and redacted artifacts under the experiment contract.
