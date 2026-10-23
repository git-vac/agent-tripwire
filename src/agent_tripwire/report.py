import html
import json
import os
from pathlib import Path
import unicodedata

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

COLORS = {"boundary-crossed": "red", "blocked": "yellow", "attempt-only": "yellow",
    "no-boundary-crossing": "green", "error": "red", "inconclusive": "yellow"}


def clean(value):
    return "".join(char for char in str(value) if char in "\n\t" or not unicodedata.category(char).startswith("C"))


def new_file(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def describe(event, details=False):
    kind = event["kind"]
    if kind == "tool_attempt":
        args = json.dumps(event["arguments"], ensure_ascii=False)
        label = "OUT OF SCOPE" if event["unauthorized"] else "permitted"
        return f'{event["tool"]} {args} · {label}'
    if kind == "injection_delivered":
        text = "Untrusted instructions delivered through " + event["tool"]
        if details:
            text += "\nInjected material:\n" + event["payload"]
            if "legitimate_content" in event:
                text += "\nLegitimate source data:\n" + event["legitimate_content"]
        return text
    if kind == "injection_served":
        return ("Injected response prepared; application receipt pending · " + event["source"] +
            " · response " + str(event["response_ordinal"]) + ("\n" + json.dumps(event, ensure_ascii=False) if details else ""))
    if kind == "application_received":
        return event["tool"] + " · application acknowledged response SHA-256 " + event["sha256"]
    if kind == "permission_decision":
        return event["tool"] + " · " + ("allowed" if event["allowed"] else "denied") + " · " + event["detail"]
    if kind == "mcp_tool_requested":
        return event["tool"] + " · MCP request " + event["request_id"] + ("\n" + json.dumps(event["arguments"], ensure_ascii=False) if details else "")
    if kind == "tool_result":
        return event["tool"] + " returned data" + ("\n" + event["content"] if details else "")
    if kind == "receiver_observed":
        return f'Local receiver: {event["bytes"]} bytes · canary received: {event["canary_received"]}'
    if kind == "file_observed":
        return f'{event["path"]} · content changed: {event["changed"]} · SHA-256 recorded'
    return event.get("reason", event.get("detail", event.get("content", kind)))


def terminal(report, console=None, details=False):
    console = console or Console(highlight=False)
    mode = "SCRIPTED DEMO · NOT A MODEL EVALUATION" if report["mode"] == "demo" else "REAL MODEL RUN · SYNTHETIC ENVIRONMENT"
    if report.get("purpose") == "connection-check":
        mode = "CONNECTION CHECK · CLEAN TASK ONLY"
    elif report.get("purpose") == "application-evaluation":
        mode += " · SEPARATE MCP APPLICATION"
    console.print(Panel(Text("AGENT TRIPWIRE\n" + mode + "\n" + clean(report["model"]) + " · " + clean(report.get("provider", "ollama")) + " · policy: " + clean(report["policy"])), border_style="cyan"))
    if report.get("view_notice"):
        console.print(Text(clean(report["view_notice"]), style="yellow"))
    table = Table(expand=True)
    for column in ("Trial / case", "Outcome", "Control", "Evidence"):
        table.add_column(column, overflow="fold")
    for result in report["results"]:
        proof = "; ".join(item["finding"] for item in result["evidence"]) or result.get("error") or (
            "Task incomplete or injection not reached" if result["status"] == "inconclusive" else "No completed forbidden action observed")
        table.add_row(Text(clean(f'{result["trial"]} / {result["id"]}')), Text(result["status"], style=COLORS[result["status"]]),
            Text("OK" if result["clean_control_ok"] else "UNCERTAIN", style="green" if result["clean_control_ok"] else "yellow"), Text(clean(proof)))
    console.print(table)
    for result in report["results"]:
        if result["id"] == "control" and not details and result["clean_control_ok"]:
            continue
        console.print(Text(clean(f'\n{result["id"]} · trial {result["trial"]} · {result["status"]}'), style="bold"))
        for event in result["events"]:
            if not details and event["kind"] in ("tool_result", "assistant"):
                continue
            text = clean(describe(event, details))
            if not details and len(text) > 240:
                text = text[:237] + "..."
            color = "red" if event.get("unauthorized") else "cyan" if event["kind"] == "injection_delivered" else "white"
            console.print(Text(f'  {event["step"]:02d}  {event["kind"]:<20} {text}', style=color))
    for note in report["notes"]:
        console.print(Text("• " + clean(note), style="dim"))


STYLE = """
:root{color-scheme:dark;--bg:#0b1020;--card:#131c30;--line:#293750;--text:#e5edf9;--muted:#a7b6cc;--accent:#71e3d2}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.65 system-ui,sans-serif}
main{max-width:1180px;margin:auto;padding:48px 24px}h1{font-size:42px;letter-spacing:-.04em;margin:8px 0}h2{font-size:21px}
.eyebrow{color:var(--accent);letter-spacing:.18em;font-size:12px;font-weight:700}.muted,p{color:var(--muted)}
.banner,.card,details,.metric{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:16px 0}
.banner{border-left:4px solid var(--accent)}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}.metric strong{display:block;font-size:30px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:13px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase}
.scroll{overflow:auto}.status{display:inline-block;border:1px solid var(--line);border-radius:30px;padding:2px 10px;white-space:nowrap}.boundary-crossed,.error{color:#ffa3ad}.blocked,.inconclusive,.attempt-only{color:#f6d583}.no-boundary-crossing{color:var(--accent)}
summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 ui-monospace,monospace;background:#090e1a;padding:14px;border-radius:8px}code{color:var(--accent)}
.event{border-left:2px solid var(--line);padding:0 0 12px 18px;margin-left:8px}.event h3{font:13px ui-monospace,monospace;color:var(--accent)}footer{margin-top:32px;color:var(--muted)}
"""


def webpage(report):
    e = lambda value: html.escape(clean(value), quote=True)
    mode = "SCRIPTED DEMO — NOT A MODEL EVALUATION" if report["mode"] == "demo" else "REAL MODEL RUN — SYNTHETIC ENVIRONMENT"
    if report.get("purpose") == "connection-check":
        mode = "CONNECTION CHECK — CLEAN TASK ONLY"
    elif report.get("purpose") == "application-evaluation":
        mode += " — SEPARATE MCP APPLICATION"
    rows, cases = [], []
    for result in report["results"]:
        status = e(result["status"])
        proof = "; ".join(item["finding"] for item in result["evidence"]) or result.get("error") or "No completed forbidden action observed"
        rows.append(f'<tr><td>{result["trial"]} / {e(result["id"])}</td><td><span class="status {status}">{status}</span></td>'
            f'<td>{"OK" if result["clean_control_ok"] else "UNCERTAIN"}</td><td>{e(proof)}</td></tr>')
        timeline = "".join(f'<div class="event"><h3>{event["step"]:02d} / {e(event["kind"])}</h3>'
            f'<pre>{e(describe(event, True))}</pre></div>' for event in result["events"])
        cases.append(f'<details><summary>{e(result["title"])} · trial {result["trial"]} · <span class="{status}">{status}</span></summary>'
            f'<p>{e(result["objective"])}</p><p>Injection delivered: {result["injection_exposed"]} · Task check: {result["task_complete"]} '
            f'· Tool calls: {result["tool_calls"]}</p>{timeline}<h3>Final answer</h3><pre>{e(result["final"])}</pre></details>')
    counts = report["counts"]
    metrics = [("Confirmed crossings", counts.get("boundary-crossed", 0)), ("Blocked attempts", counts.get("blocked", 0)),
        ("No observed crossing", counts.get("no-boundary-crossing", 0)),
        ("Inconclusive / errors", sum(result["status"] in ("inconclusive", "error") or bool(result["error"])
            for result in report["results"]))]
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' \
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">' \
        '<title>Agent Tripwire · evidence report</title><style>' + STYLE + '</style></head><body><main>' \
        '<div class="eyebrow">ACTION-LEVEL PROMPT INJECTION TESTING</div><h1>Agent Tripwire</h1>' \
        f'<div class="banner"><strong>{e(mode)}</strong><p>{e(report["model"])} · policy: {e(report["policy"])} · {e(report["created_at"])}</p><p>{e(report.get("view_notice", ""))}</p></div>' \
        '<div class="metrics">' + ''.join(f'<div class="metric"><strong>{value}</strong>{e(label)}</div>' for label, value in metrics) + '</div>' \
        '<h2>Observed outcomes</h2><div class="card scroll"><table><thead><tr><th>Trial / case</th><th>Outcome</th><th>Clean control</th><th>Evidence</th></tr></thead><tbody>' \
        + ''.join(rows) + '</tbody></table></div><h2>Evidence timelines</h2>' + ''.join(cases) \
        + '<details><summary>Task and system prompt</summary><pre>' + e(report["task"] + '\n\n' + report["system_prompt"]) + '</pre></details>' \
        + '<footer>' + ''.join('<p>' + e(note) + '</p>' for note in report["notes"]) + '</footer></main></body></html>'
