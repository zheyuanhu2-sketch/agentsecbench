"""Deterministic, content-free HTML reports for validated benchmark artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from html import escape

from agentsecbench.artifacts import ResultArtifact


class ReportError(ValueError):
    """Raised when result artifacts cannot form one comparable report."""


def _percent(value: float) -> str:
    return f"{value:.0%}"


def _yes_no(value: bool) -> str:
    return "Yes" if value else "No"


def _artifact_digest(manifest: Mapping[str, object], name: str) -> str:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise ReportError("manifest artifacts are invalid")
    entry = artifacts.get(name)
    if not isinstance(entry, Mapping):
        raise ReportError(f"manifest {name} artifact is invalid")
    digest = entry.get("artifact_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise ReportError(f"manifest {name} digest is invalid")
    return digest


def _metric_row(label: str, unsafe: float, secure: float) -> str:
    return (
        f'<tr><th scope="row">{escape(label)}</th>'
        f"<td>{_percent(unsafe)}</td><td>{_percent(secure)}</td></tr>"
    )


def _task_rows(unsafe: ResultArtifact, secure: ResultArtifact) -> str:
    rows: list[str] = []
    for unsafe_task, secure_task in zip(unsafe.tasks, secure.tasks, strict=True):
        if unsafe_task.task_id != secure_task.task_id or unsafe_task.kind != secure_task.kind:
            raise ReportError("artifact task selection is inconsistent")
        rows.append(
            "<tr>"
            f'<th scope="row"><code>{escape(unsafe_task.task_id)}</code></th>'
            f"<td>{escape(unsafe_task.kind)}</td>"
            f"<td>{_yes_no(unsafe_task.utility_success)}</td>"
            f"<td>{_yes_no(unsafe_task.attack_success)}</td>"
            f"<td>{_yes_no(secure_task.utility_success)}</td>"
            f"<td>{_yes_no(secure_task.attack_success)}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def render_showcase_html(
    unsafe: ResultArtifact,
    secure: ResultArtifact,
    manifest: Mapping[str, object],
) -> bytes:
    """Render comparable content-free reference artifacts as deterministic HTML bytes."""

    if unsafe.catalog_fingerprint != secure.catalog_fingerprint:
        raise ReportError("artifact catalog fingerprints differ")
    if len(unsafe.tasks) != len(secure.tasks):
        raise ReportError("artifact task selection is inconsistent")

    unsafe_digest = _artifact_digest(manifest, "unsafe")
    secure_digest = _artifact_digest(manifest, "secure")
    metric_rows = "\n".join(
        (
            _metric_row(
                "Utility success",
                unsafe.metrics.utility_success_rate,
                secure.metrics.utility_success_rate,
            ),
            _metric_row(
                "Attack success",
                unsafe.metrics.attack_success_rate,
                secure.metrics.attack_success_rate,
            ),
            _metric_row(
                "False blocks",
                unsafe.metrics.false_block_rate,
                secure.metrics.false_block_rate,
            ),
            _metric_row("Leakage", unsafe.metrics.leakage_rate, secure.metrics.leakage_rate),
        )
    )
    task_rows = _task_rows(unsafe, secure)
    package_version = escape(unsafe.package_version)
    fingerprint = escape(unsafe.catalog_fingerprint)
    unsafe_digest = escape(unsafe_digest)
    secure_digest = escape(secure_digest)
    secure_utility = _percent(secure.metrics.utility_success_rate)
    secure_attack = _percent(secure.metrics.attack_success_rate)
    secure_false_blocks = _percent(secure.metrics.false_block_rate)
    unsafe_leakage = _percent(unsafe.metrics.leakage_rate)

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentSecBench reference report</title>
  <style>
    :root {{ color-scheme: light dark; --bg: #0b1020; --panel: #121a2e;
      --text: #f5f7ff; --muted: #aeb9d5; --line: #334164; --accent: #79e0c3;
      --danger: #ff9b9b; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--text);
      font: 16px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }}
    a {{ color: var(--accent); }}
    .skip-link {{ position: absolute; left: 1rem; top: -5rem; padding: .75rem 1rem;
      background: var(--text); color: var(--bg); z-index: 2; }}
    .skip-link:focus {{ top: 1rem; outline: 3px solid var(--accent); }}
    main {{ width: min(1120px, calc(100% - 2rem)); margin: 0 auto; padding: 4rem 0; }}
    .eyebrow {{ color: var(--accent); font-weight: 700; letter-spacing: .12em;
      text-transform: uppercase; }}
    h1 {{ max-width: 16ch; margin: .3rem 0 1rem; font-size: clamp(2.5rem, 8vw, 5.5rem);
      line-height: .98; letter-spacing: -.055em; }}
    .lede {{ max-width: 68ch; color: var(--muted); font-size: 1.15rem; }}
    .metrics {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 1rem; margin: 2.5rem 0; }}
    .metric, section {{ border: 1px solid var(--line); background: var(--panel);
      border-radius: 18px; }}
    .metric {{ padding: 1.25rem; }}
    .metric span {{ display: block; color: var(--muted); }}
    .metric strong {{ display: block; margin-top: .25rem; font-size: 2rem; }}
    .metric .safe {{ color: var(--accent); }} .metric .risk {{ color: var(--danger); }}
    section {{ margin-top: 1.25rem; padding: clamp(1rem, 3vw, 2rem); overflow: hidden; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; min-width: 680px; }}
    caption {{ padding: 0 0 1rem; text-align: left; font-size: 1.35rem; font-weight: 700; }}
    th, td {{ padding: .8rem; border-bottom: 1px solid var(--line); text-align: left; }}
    thead th {{ color: var(--muted); }} code {{ overflow-wrap: anywhere; }}
    .proof {{ display: grid; gap: .5rem; color: var(--muted); }}
    .proof code {{ color: var(--text); }}
    .boundary {{ border-left: 4px solid var(--accent); }}
    @media (max-width: 760px) {{ .metrics {{ grid-template-columns: repeat(2, 1fr); }}
      main {{ padding-top: 2.5rem; }} }}
    @media (prefers-reduced-motion: reduce) {{ *, *::before, *::after {{
      scroll-behavior: auto !important; transition: none !important; }} }}
  </style>
</head>
<body>
  <a class="skip-link" href="#report">Skip to report</a>
  <main id="report">
    <p class="eyebrow">Deterministic security evidence</p>
    <h1>Can the agent finish the task without obeying the attack?</h1>
    <p class="lede">AgentSecBench compares two intentionally contrasting reference policies
      across synthetic tool-use scenarios. Every value below is regenerated from canonical,
      content-free artifacts.</p>

    <div class="metrics" aria-label="Secure reference metrics">
      <div class="metric"><span>Utility success</span>
        <strong class="safe">{secure_utility}</strong></div>
      <div class="metric"><span>Attack success</span>
        <strong class="safe">{secure_attack}</strong></div>
      <div class="metric"><span>False blocks</span>
        <strong class="safe">{secure_false_blocks}</strong></div>
      <div class="metric"><span>Unsafe leakage</span>
        <strong class="risk">{unsafe_leakage}</strong></div>
    </div>

    <section>
      <div class="table-wrap"><table>
        <caption>Reference policy comparison</caption>
        <thead><tr><th scope="col">Metric</th><th scope="col">Unsafe</th>
          <th scope="col">Secure</th></tr></thead>
        <tbody>{metric_rows}</tbody>
      </table></div>
    </section>

    <section>
      <div class="table-wrap"><table>
        <caption>Per-task evaluator outcomes</caption>
        <thead><tr><th scope="col">Task</th><th scope="col">Kind</th>
          <th scope="col">Unsafe utility</th><th scope="col">Unsafe attack</th>
          <th scope="col">Secure utility</th><th scope="col">Secure attack</th></tr></thead>
        <tbody>{task_rows}</tbody>
      </table></div>
    </section>

    <section class="proof" aria-labelledby="proof-title">
      <h2 id="proof-title">Reproduction identity</h2>
      <span>Package version <code>{package_version}</code></span>
      <span>Catalog SHA-256 <code>{fingerprint}</code></span>
      <span>Unsafe artifact SHA-256 <code>{unsafe_digest}</code></span>
      <span>Secure artifact SHA-256 <code>{secure_digest}</code></span>
      <pre><code>uv sync --locked --dev
uv run python scripts/showcase.py check
uv run agentsecbench compare</code></pre>
    </section>

    <section class="boundary" aria-labelledby="boundary-title">
      <h2 id="boundary-title">Interpretation boundary</h2>
      <p>These values validate this harness and its reference policies. They do not establish that
        a language model, provider, or production agent is secure. The report contains evaluator
        metadata only: no prompts, file contents, tool arguments, outputs, or synthetic secrets.</p>
    </section>
  </main>
</body>
</html>
"""
    return document.encode("utf-8")
