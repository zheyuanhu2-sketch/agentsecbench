# Security policy

## Supported versions

Only the latest commit on the default branch is supported during private development.

## Reporting a vulnerability

Do not open a public issue for a vulnerability before the repository publication gate is
complete. Contact the repository owner privately with:

- the affected commit;
- a minimal reproduction using synthetic data;
- the expected and observed security boundary;
- potential impact and suggested mitigation.

Never include credentials, personal data, live exploit targets, or destructive payloads.

## Current safety boundary

The v0.1 runtime is an in-memory simulation. A benchmark run must not access the network, spawn
processes, or read and write host files. Any adapter that adds those capabilities requires a new
threat-model review and explicit operator approval before merge.

