# Roadmap

This roadmap describes intended maintenance work, not promised dates or shipped functionality.
Items move only after design review, tests, and the repository's quality and security gates pass.

## Now

- Improve contributor onboarding with a paired normal/attack scenario walkthrough.
- Document representative catalog-validation failures and safe fixes without weakening fail-closed
  behavior.
- Maintain the deterministic coding-agent showcase, supported Python matrix, dependency audit,
  full-history secret scan, and reproducible release checks.

## Next

- Design an opt-in adapter for the official OpenAI Responses API.
- Freeze request and response contracts in mocked tests before any live request.
- Require an exact official endpoint, environment-only project credential, explicit network
  approval, bounded tokens/turns/timeouts/response bytes, no redirects or retries, and redacted
  errors.
- Document provider retention and data-handling assumptions in the threat model.

## Later

- Add independently reviewed synthetic scenario catalogs for additional coding-agent workflows.
- Run repeated, identified provider experiments whose results retain exact catalog fingerprints.
- Keep result artifacts content-free: no prompts, tool arguments, tool outputs, endpoints, or
  secrets.

## Out of scope

- Claims that deterministic reference-policy results establish production-model security.
- Real credentials, personal data, confidential repositories, malware, or real external side
  effects.
- A generic arbitrary-URL client or an automatically enabled hosted-provider integration.
