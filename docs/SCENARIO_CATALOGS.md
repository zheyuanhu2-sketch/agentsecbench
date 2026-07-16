# External scenario catalogs

AgentSecBench v0.5 defines `agentsecbench.scenario.v1` for reviewed synthetic datasets. The built-in
v0.1 catalog remains frozen and retains its original fingerprint; loading an external catalog does
not change or impersonate it.

## Try the shipped example

```powershell
uv run agentsecbench catalog-validate examples/scenario-catalog-v1.json
uv run agentsecbench catalog-evaluate examples/scenario-catalog-v1.json --policy unsafe
uv run agentsecbench catalog-evaluate examples/scenario-catalog-v1.json --policy secure `
  --output artifacts/example-secure.json
```

The example contains one legitimate mail workflow and one indirect-injection file workflow. Its
current fingerprint is
`d7e7931bf233235f7003c888d36e8646643d2e735001e19042e00edf0c1f972c`.

## Top-level contract

```json
{
  "schema_version": "agentsecbench.scenario.v1",
  "data_classification": "synthetic",
  "scenarios": []
}
```

Each scenario contains an ID, `normal` or `attack` kind, goal, synthetic messages/files, an ordered
evaluator action plan, task policy, and synthetic sensitive canaries. See
[`schemas/scenario-catalog-v1.schema.json`](../schemas/scenario-catalog-v1.schema.json) and
[`examples/scenario-catalog-v1.json`](../examples/scenario-catalog-v1.json).

The JSON Schema supports editor tooling and structural review. The Python loader is authoritative
because it also verifies semantic invariants across records:

- globally unique task IDs and per-task resource/action IDs;
- exact argument names for each of the four supported tools;
- reads reference existing messages/files and all paths reject traversal or absolute forms;
- provenance points only to prior actions and contains no duplicates;
- approvals reference known actions and policy tools/scopes are valid;
- required and forbidden labels cannot conflict;
- normal tasks cannot contain forbidden actions or sensitive labels;
- attack tasks require a forbidden action and `SYNTHETIC-SECRET-...` canary used by that action.

## Input boundary

- The file must be a regular, non-symbolic-link `.json` file no larger than 2 MiB.
- UTF-8, duplicate keys, unknown fields, unknown tools, excessive collections/strings, and invalid
  types fail closed.
- There are no URLs, `$ref` resolution, includes, templates, environment expansion, dynamic
  imports, YAML tags, pickle, or executable hooks.
- `data_classification: synthetic` is mandatory but is still an author assertion. Reviewers must
  independently confirm that messages and files contain no real personal or confidential data.

## Research use

Always report the exact external catalog fingerprint with results. Changing any goal, content,
label, action, or policy changes the digest. Results from different fingerprints are not directly
comparable unless the differences are explicitly analyzed.
