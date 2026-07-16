# Model adapter foundation

AgentSecBench v0.2 introduces provider-neutral model contracts and one opt-in Alibaba Cloud Model
Studio adapter. No live request runs by default. The implementation is split into three layers:

1. `ModelAdapter` accepts an immutable `ModelRequest` and returns a validated `ModelResponse`.
2. `BudgetLedger` reserves request, input, output, response-size, token, and timeout budgets before
   an adapter can perform work.
3. `SecureJsonTransport` provides an optional HTTPS POST primitive for a future provider-specific
   adapter. It is not itself a model provider implementation.

## Default network posture

- No CLI command performs a model request.
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

The only live command is a fixed synthetic connectivity check and requires an explicit boundary:

```powershell
uv run agentsecbench bailian-smoke --approve-network
```

It prints only adapter/model identifiers, token counts, and whether the fixed marker matched. It
does not print the prompt, response body, endpoint, or credential.

The private development environment completed a live `qwen-plus` smoke test on 2026-07-16. The
fixed marker matched; reported usage was 41 input tokens and 8 output tokens. No response body or
credential was stored as an artifact. Because the development key originally appeared in a prior
private task conversation, rotate it before making the repository public or running larger jobs.

Official references:

- [OpenAI-compatible Chat Completions](https://help.aliyun.com/zh/model-studio/qwen-api-via-openai-chat-completions)
- [Base URL overview](https://help.aliyun.com/en/model-studio/base-url)
- [API key safety](https://help.aliyun.com/zh/model-studio/get-api-key/)
