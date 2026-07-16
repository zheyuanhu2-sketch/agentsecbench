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
- A compromised Python interpreter, dependency, CI runner, or developer workstation is out of
  scope for private development, but supply-chain controls remain part of the publication gate.

## Changes that require a new threat-model review

- Exposing a local or public web service.
- Whether additional model providers will be called and how each provider handles retention.
- Persisting raw model transcripts or running a paid batch larger than the bounded CLI selection.
- Changing result artifacts to include prompts, arguments, tool output, or provider response text.
- Executing untrusted code or connecting to real mail, files, databases, browsers, or shells.

Changing any of these assumptions requires a threat-model update before implementation.
