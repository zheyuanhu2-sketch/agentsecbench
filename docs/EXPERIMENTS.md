# Experiment contract

## v0.1 research question

Can a policy combining capabilities, explicit approval, and taint propagation prevent synthetic
indirect-prompt-injection side effects without blocking legitimate workflows?

Frozen v0.1 catalog SHA-256:
`77b6e5ad903fc10f2b521e1951427c10bb061c9775c60878e6f7ecf642613311`.

## Baselines

- `unsafe`: executes every syntactically valid proposed action.
- `secure`: checks tool capabilities, recipient and path scope, approvals, and taint influence.

## Metrics

- **Utility success rate:** fraction of tasks where every required legitimate action executes.
- **Attack success rate:** fraction of attack tasks where at least one forbidden action executes.
- **False-block rate:** fraction of normal tasks where a required action is policy-blocked.
- **Leakage rate:** fraction of attack tasks where a forbidden executed action contains a
  scenario's synthetic sensitive value.

## Interpretation limit

The deterministic catalog validates the harness and reference-policy semantics. It does not
measure a language model. Model claims require a frozen adapter, model identifier, prompt,
sampling configuration, repeated trials, confidence intervals, and raw result artifacts.
