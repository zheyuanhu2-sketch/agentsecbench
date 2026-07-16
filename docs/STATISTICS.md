# Repeated-trial statistics

AgentSecBench v0.6 aggregates two to 100 validated result artifacts with:

```powershell
uv run agentsecbench experiment-aggregate `
  artifacts/trial-1.json artifacts/trial-2.json `
  --confidence 0.95 --output artifacts/experiment.json
```

The default is a two-sided 95% Wilson score interval. Confidence may range from 0.80 to 0.999.
The canonical output schema identifier is `agentsecbench.experiment.v1`.

## Comparability gate

Every source must have the same:

- AgentSecBench package version and catalog fingerprint;
- deterministic/model mode and policy;
- adapter ID, model ID, and maximum turns for model runs;
- ordered task IDs and task kinds.

The summary records every source artifact SHA-256. Duplicate digests fail closed because two
byte-identical files cannot prove that two independent runs occurred; a copied artifact must never
shrink a confidence interval. A future batch-run schema will carry explicit trial identities for
providers that produce byte-identical deterministic outputs.

## Metrics and intervals

For a proportion with positive count `x`, observations `n`, and normal quantile `z`, the Wilson
center and half-width are:

```text
center = (x/n + z²/(2n)) / (1 + z²/n)
margin = z * sqrt((x/n)(1-x/n)/n + z²/(4n²)) / (1 + z²/n)
```

The implementation clamps the final bounds to `[0, 1]` and reports four decimal places. It does
not use the misleading zero-width normal approximation at 0% or 100%.

Observation denominators are:

- utility: every task in every trial;
- attack success and leakage: attack tasks only;
- false blocks: normal tasks only;
- completion: model tasks only;
- protocol errors: model turns, with each turn allowing at most one protocol error.

The summary includes these global estimates plus one estimate per task, making brittle scenarios
visible instead of hiding them in an average. Input and output tokens are summed, not estimated.

## Interpretation limits

Task-trial observations are not guaranteed independent: the same task appears across trials and
tasks can share templates. Wilson intervals therefore describe observed benchmark variability;
they are not causal confidence intervals, hypothesis tests, or proof of real-world security.
Report trial count, task count, fingerprint, model configuration, sampling settings, and all
intervals. Do not claim a defense effect when the model never attempted the malicious action under
the unsafe policy.

Deterministic-policy artifacts normally should not be repeated because identical outputs add no
evidence. Their aggregation is useful only for testing the statistics pipeline or comparing
genuinely distinct validated outcomes under an otherwise identical manifest.
