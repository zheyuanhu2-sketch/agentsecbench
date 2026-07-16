# Security assumptions

This is the confirmed operating-boundary record for private development.

## Current assumptions

- One trusted developer runs the benchmark locally.
- The repository contains synthetic data only.
- There is no internet-facing service, authentication system, or multi-tenant state.
- One explicitly approved CLI command may call the configured Alibaba Cloud Model Studio
  Workspace endpoint with a fixed synthetic smoke-test prompt.
- The deterministic action plans are benchmark fixtures, not model-generated content.
- The in-memory tools are the complete runtime side-effect boundary.
- A compromised Python interpreter, dependency, CI runner, or developer workstation is out of
  scope for private development, but supply-chain controls remain part of the publication gate.

## Changes that require a new threat-model review

- Exposing a local or public web service.
- Whether additional model providers will be called and how each provider handles retention.
- Executing untrusted code or connecting to real mail, files, databases, browsers, or shells.

Changing any of these assumptions requires a threat-model update before implementation.
