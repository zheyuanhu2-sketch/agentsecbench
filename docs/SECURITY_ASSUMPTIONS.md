# Security assumptions

This is the confirmed operating-boundary record for private development.

## Current assumptions

- One trusted developer runs the benchmark locally.
- The repository contains synthetic data only.
- There is no internet-facing service, authentication system, or multi-tenant state.
- Explicitly approved CLI commands may call the configured Alibaba Cloud Model Studio Workspace
  endpoint with fixed synthetic benchmark context.
- Deterministic action plans remain benchmark fixtures. The model runner may also generate strict
  tool decisions, but it cannot execute tools directly or attest its own provenance.
- The in-memory tools are the complete runtime side-effect boundary.
- Result files are written only when the operator supplies `--output`; they contain redacted
  metadata under an exact schema and are excluded from Git by default.
- External scenario files are read only from an explicit local `.json` path, are limited to 2 MiB,
  reject symbolic links and duplicate keys, have no include/reference mechanism, and must declare
  synthetic classification before catalog validation.
- Experiment summaries are derived only from strictly validated result artifacts, reject
  incompatible manifests/task selections and duplicate digests, and contain metadata only.
- Local model calls use direct HTTP only to literal `127.0.0.1` or `::1` on an explicit port from
  1024 through 65535, after `--approve-local-network`; DNS names, LAN/unspecified addresses,
  proxies, redirects, retries, and URL credentials are rejected.
- Bailian batches are capped at five trials and use one shared request/token budget. Each loop
  receives a random UUID trial identity and persists only redacted result metadata.
- A compromised Python interpreter, dependency, CI runner, or developer workstation is out of
  scope for private development. Locked/audited dependencies, pinned scanners and actions,
  read-only ordinary CI, reproducible packages, strict release inspection, and checksums reduce
  but cannot eliminate that supply-chain risk.

## Changes that require a new threat-model review

- Exposing a local or public web service.
- Whether additional model providers will be called and how each provider handles retention.
- Persisting raw model transcripts or running a paid batch larger than the bounded CLI selection.
- Changing result artifacts to include prompts, arguments, tool output, or provider response text.
- Adding remote scenario sources, includes, templating, deserialization plugins, or non-synthetic
  datasets.
- Treating correlated task-trial observations as independent causal evidence or weakening
  experiment comparability checks.
- Expanding local inference from literal loopback to hostnames, LAN/cloud URLs, privileged ports,
  automatic service discovery, or arbitrary OpenAI-compatible endpoints.
- Executing untrusted code or connecting to real mail, files, databases, browsers, or shells.

Changing any of these assumptions requires a threat-model update before implementation.
