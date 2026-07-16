# Model adapter foundation

AgentSecBench provides provider-neutral model contracts, a bounded model/tool loop, an opt-in
Alibaba Cloud Model Studio adapter, and a loopback-only local adapter. No live request runs by
default.

1. `ModelAdapter` accepts an immutable `ModelRequest` and returns a validated `ModelResponse`.
2. `BudgetLedger` reserves request, input, output, response-size, token, and timeout budgets before
   an adapter can perform work.
3. `SecureJsonTransport` performs the exact-host HTTPS POST used by the Bailian adapter.
4. `model_runner.py` parses one strict JSON decision per turn, binds provenance in the runtime,
   mediates every tool call through a policy, and executes only in-memory tools.

## Default network posture

- Deterministic commands perform no network requests. Live Bailian commands require the explicit
  `--approve-network` flag.
- `FakeModelAdapter` is the only complete adapter and is fully offline.
- The JSON transport requires an exact HTTPS endpoint and an explicit hostname allowlist.
- Only port 443 is accepted; URL credentials, query strings, fragments, traversal, wildcards,
  redirects, retries, environment proxies, and non-JSON responses are rejected.
- The API key is loaded from a named environment variable at request time. It is not stored in the
  config object, command line, repository, or exception text.
- Responses have a strict byte ceiling and errors never include request or response bodies.

## Offline example

```python
from agentsecbench.adapters import BudgetLedger, BudgetLimits, FakeModelAdapter, ModelRequest

request = ModelRequest(
    request_id="example-0001",
    system_prompt="Use synthetic data only.",
    user_prompt="Return a deterministic result.",
    max_output_tokens=64,
)
adapter = FakeModelAdapter({request.request_id: '{"action":"finish"}'})
response = adapter.complete(request, BudgetLedger(BudgetLimits()))
print(response.content)
```

## Model decision protocol

The model may return exactly one of these JSON objects, with no Markdown or extra keys:

```json
{"type":"tool_call","tool":"mail.read","arguments":{"message_id":"trusted-01"}}
```

```json
{"type":"finish","summary":"Task complete."}
```

The model cannot provide action identifiers, ground-truth labels, trust flags, or `derived_from`.
The runtime conservatively binds every previously executed tool output as provenance for the next
action. Policy-visible action and approval identifiers are opaque and never expose fixture names
such as `attack` or `exfiltrate`.

Each scenario has a turn cap, repeated identical calls are rejected, malformed decisions are not
logged, and every accepted action crosses the policy boundary exactly once. Target matching maps
dynamic model calls back to evaluator-only canonical actions for scoring.

## Provider integration gate

Before adding another live provider adapter:

- freeze its request and response schema in tests;
- select one exact provider hostname and endpoint;
- define model identifier, token accounting, retention policy, and supported timeouts;
- load credentials only from the environment or OS key store;
- add redaction canaries and mocked transport tests;
- add a manual `--approve-network` boundary for any future CLI command;
- update `agentsecbench-threat-model.md` with provider-specific data handling.

Real email, file, database, subprocess, browser, or shell tools remain out of scope.

## Alibaba Cloud Model Studio

`BailianChatAdapter` implements the OpenAI-compatible Chat Completions request and response schema
for Alibaba Cloud Model Studio. The adapter accepts only official Alibaba Cloud Model Studio hosts
and the exact `/compatible-mode/v1` base path. The configured model defaults to `qwen-plus`.

Configure these values in the process environment; never pass the key on the command line:

```text
AGENTSECBENCH_BAILIAN_BASE_URL=https://your-workspace.cn-beijing.maas.aliyuncs.com/compatible-mode/v1
AGENTSECBENCH_BAILIAN_API_KEY=<stored outside Git>
AGENTSECBENCH_BAILIAN_MODEL=qwen-plus
```

The fixed connectivity check requires an explicit boundary:

```powershell
uv run agentsecbench bailian-smoke --approve-network
```

It prints only adapter/model identifiers, token counts, and whether the fixed marker matched. It
does not print the prompt, response body, endpoint, or credential.

A bounded synthetic evaluation is also opt-in:

```powershell
uv run agentsecbench bailian-evaluate --approve-network --policy secure
```

It defaults to `normal-mail-01` and `attack-mail-01`, permits at most four selected tasks and six
turns per task, performs no retries, and prints only model identifiers, metrics, turn/protocol
counts, and token usage. Use repeated `--task` options to select other frozen scenarios.

The private development environment completed a live `qwen-plus` smoke test on 2026-07-16. The
fixed marker matched; reported usage was 41 input tokens and 8 output tokens. No response body or
credential was stored as an artifact. Because the development key originally appeared in a prior
private task conversation, rotate it before making the repository public or running larger jobs.

The private environment also completed a two-task `qwen-plus` pilot under both `unsafe` and
`secure` policies on 2026-07-16. Both runs achieved utility 100%, attack success 0%, leakage 0%,
and zero protocol errors, using 1,621 input and 142 output tokens per policy. This is a connectivity
and plumbing check with one attack task, not evidence that the model or policy is generally secure.

## Local OpenAI-compatible inference

The local adapter targets servers such as Ollama, LM Studio, or vLLM without becoming a generic
URL client. Configure the model that is already installed on the local server:

```text
AGENTSECBENCH_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
AGENTSECBENCH_LOCAL_MODEL=<installed-model-id>
AGENTSECBENCH_LOCAL_API_KEY=<optional-local-only-value>
```

```powershell
uv run agentsecbench local-smoke --approve-local-network
uv run agentsecbench local-evaluate --approve-local-network --policy secure
```

Controls:

- only literal `127.0.0.1` and `::1` are accepted; `localhost`, LAN, wildcard, and public addresses
  are rejected to avoid DNS and SSRF ambiguity;
- the URL must be HTTP with an explicit port from 1024 to 65535 and exact `/v1` base path;
- no URL credentials, query, fragment, traversal, proxy, redirect, retry, or service discovery;
- the same strict request/response schema, token accounting, response cap, and model loop apply;
- the current development workstation had no local compatible server installed or listening when
  v0.7 was validated, so transport and adapter coverage is mocked rather than claimed as a live
  local-model result.

Ollama documents its OpenAI-compatible `/v1/chat/completions` endpoint in the
[official compatibility guide](https://docs.ollama.com/api/openai-compatibility).

## Identified Bailian batches

```powershell
uv run agentsecbench bailian-batch --approve-network --trials 2 `
  --policy secure --output artifacts/qwen-plus-secure.json
```

The command writes `<stem>.trial-01.result.json` through the selected trial count, then writes the
aggregate experiment summary at `--output`. Trial count is two to five, every trial has a UUID,
and one ledger enforces the total batch budget. Existing files at those explicit paths are replaced
atomically.

Official references:

- [OpenAI-compatible Chat Completions](https://help.aliyun.com/zh/model-studio/qwen-api-via-openai-chat-completions)
- [Base URL overview](https://help.aliyun.com/en/model-studio/base-url)
- [API key safety](https://help.aliyun.com/zh/model-studio/get-api-key/)
