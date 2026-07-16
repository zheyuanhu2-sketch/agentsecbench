# Security assumptions

This is the pre-threat-model assumption record for private v0.1 development.

## Current assumptions

- One trusted developer runs the benchmark locally.
- The repository contains synthetic data only.
- There is no internet-facing service, authentication system, or multi-tenant state.
- The deterministic action plans are benchmark fixtures, not model-generated content.
- The in-memory tools are the complete runtime side-effect boundary.
- A compromised Python interpreter, dependency, CI runner, or developer workstation is out of
  scope for v0.1, but supply-chain controls remain part of the publication gate.

## Assumptions requiring confirmation before the final threat model

- Whether v0.2 will remain CLI-only or expose a local or public web service.
- Whether real model APIs will be called and how API credentials will be isolated.
- Whether benchmark runs will ever execute untrusted code or connect to real tools.

Changing any of these assumptions requires a threat-model update before implementation.

