# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Use GitHub's
[private vulnerability report](https://github.com/zheyuanhu2-sketch/agentsecbench/security/advisories/new).
Do not put security details in a public issue.

Until private vulnerability reporting is enabled, invited collaborators should create a draft
repository security advisory and notify maintainer
[`@zheyuanhu2-sketch`](https://github.com/zheyuanhu2-sketch). Include:

- the affected commit;
- a minimal reproduction using synthetic data;
- the expected and observed security boundary;
- potential impact and suggested mitigation.

Never include credentials, personal data, live exploit targets, or destructive payloads.

The maintainer aims to acknowledge a report within three business days, complete initial triage
within seven business days, and provide a status update at least every fourteen days until it is
resolved. Publication and credit are coordinated with the reporter; there is no promise of a bug
bounty.

## Current safety boundary

The tool runtime is an in-memory simulation. Deterministic runs do not access the network. Opt-in
model commands may send synthetic prompts to an exact allowlisted Model Studio HTTPS endpoint only
after explicit operator approval, or to a literal loopback HTTP address after separate local-network
approval. Model-generated actions cannot spawn processes or read and write host files. Any adapter
or tool that broadens those capabilities requires a new threat-model review and explicit operator
approval before merge.
