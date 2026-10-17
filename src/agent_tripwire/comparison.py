"""Compare observed counts without turning small test suites into safety scores."""
from collections import defaultdict
import html
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .report import STYLE, clean

STATUSES = {"boundary-crossed", "blocked", "attempt-only", "no-boundary-crossing", "inconclusive", "error"}


def read_report(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("Comparison input exceeds 16 MiB")
    try:
        report = json.loads(raw)
    except (ValueError, RecursionError):
        raise ValueError("Comparison input must be a valid JSON report") from None
    if not isinstance(report, dict) or report.get("schema_version") != 1 or report.get("mode") not in ("demo", "run"):
        raise ValueError("Expected an Agent Tripwire run report with schema_version 1")
    if not isinstance(report.get("results"), list) or not 1 <= len(report["results"]) <= 2000:
        raise ValueError("Report must contain between 1 and 2,000 case results")
    for field in ("model", "policy", "task", "system_prompt"):
        if not isinstance(report.get(field), str):
            raise ValueError("Report is missing required metadata")
    seen = set()
    for result in report["results"]:
        if (not isinstance(result, dict) or not isinstance(result.get("id"), str) or not result["id"] or
                type(result.get("trial")) is not int or not 1 <= result["trial"] <= 20 or
                not isinstance(result.get("status"), str) or result["status"] not in STATUSES or
                any(type(result.get(field)) is not bool for field in ("task_complete", "clean_control_ok", "limits_reached")) or
                "error" not in result or not isinstance(result.get("attempted"), bool)):
            raise ValueError("Report contains an invalid case result")
        key = (result["id"], result["trial"])
        if key in seen:
            raise ValueError("Report contains duplicate case/trial results")
        seen.add(key)
    fingerprints = report.get("scenario_fingerprints", {})
    if not isinstance(fingerprints, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in fingerprints.items()):
        raise ValueError("Report contains invalid scenario fingerprints")
    return report


def compare(before, after):
    grouped = []
    for report in (before, after):
        groups = defaultdict(list)
        for result in report["results"]:
            if result["id"] != "control":
                groups[result["id"]].append(result)
        grouped.append(groups)
    rows = []
    for identifier in sorted(set(grouped[0]) | set(grouped[1])):
        left, right = (group.get(identifier, []) for group in grouped)
        issues = []
        if not left or not right:
            issues.append("Case missing from one run")
        if {item["trial"] for item in left} != {item["trial"] for item in right}:
            issues.append("Trial sets differ")
        for items, label in ((left, "Before"), (right, "After")):
            if any(not item["clean_control_ok"] or not item["task_complete"] or item["error"] or item["limits_reached"] or
                    item["status"] in ("error", "inconclusive") for item in items):
                issues.append(label + " contains incomplete results or invalid controls")
        for items, source, label in ((left, before, "Before"), (right, after, "After")):
            controls = {item["trial"]: item for item in source["results"] if item["id"] == "control"}
            if any(item["trial"] not in controls or controls[item["trial"]]["status"] != "no-boundary-crossing" or
                    not controls[item["trial"]]["task_complete"] for item in items):
                issues.append(label + " is missing a successful clean control")
        for key in ("mode", "task", "system_prompt", "seed", "limits"):
            if before.get(key) != after.get(key):
                issues.append("Different " + key.replace("_", " "))
        fingerprints = [report.get("scenario_fingerprints", {}).get(identifier) for report in (before, after)]
        if not all(fingerprints):
            issues.append("Scenario fingerprint unavailable")
        elif fingerprints[0] != fingerprints[1]:
            issues.append("Scenario definition changed")
        old = sum(item["status"] == "boundary-crossed" for item in left)
        new = sum(item["status"] == "boundary-crossed" for item in right)
        change = "not-comparable" if issues else "more-crossings" if new > old else "fewer-crossings" if new < old else "same-count"
        rows.append({"id": identifier, "before_crossings": old, "before_trials": len(left),
            "after_crossings": new, "after_trials": len(right), "change": change, "issues": issues})
    return {"type": "comparison", "schema_version": 1,
        "before": {key: before.get(key) for key in ("model", "provider", "policy", "mode")},
        "after": {key: after.get(key) for key in ("model", "provider", "policy", "mode")}, "rows": rows,
        "notes": ["Counts describe observed actions in these runs, not a general model safety ranking.",
            "Different policies compare full setups; enforced tools can block actions even when the model follows an injection.",
            "Rows with missing, changed or incomplete test conditions are not comparable.",
            "Matching counts do not imply identical behavior. Inspect the original evidence timelines."]}


def comparison_exit(report):
    if not report["rows"] or any(row["issues"] for row in report["rows"]):
        return 2
    return 1 if any(row["change"] == "more-crossings" for row in report["rows"]) else 0


def terminal(report, console=None):
    console = console or Console(highlight=False)
    console.print(Text("AGENT TRIPWIRE · RUN COMPARISON", style="bold cyan"))
    console.print(Text(clean(f'Before: {report["before"]["model"]} / {report["before"]["policy"]}')))
    console.print(Text(clean(f'After:  {report["after"]["model"]} / {report["after"]["policy"]}')))
    table = Table(expand=True)
    for name in ("Case", "Before crossings", "After crossings", "Observation"):
        table.add_column(name, overflow="fold")
    for row in report["rows"]:
        table.add_row(Text(clean(row["id"])), Text(f'{row["before_crossings"]}/{row["before_trials"]}'),
            Text(f'{row["after_crossings"]}/{row["after_trials"]}'), Text(clean("; ".join(row["issues"]) or row["change"])))
    console.print(table)
    for note in report["notes"]:
        console.print(Text("• " + note, style="dim"))


def webpage(report):
    e = lambda value: html.escape(clean(value), quote=True)
    rows = ''.join('<tr><td>' + e(row["id"]) + '</td><td>' + f'{row["before_crossings"]}/{row["before_trials"]}' +
        '</td><td>' + f'{row["after_crossings"]}/{row["after_trials"]}' + '</td><td>' +
        e('; '.join(row["issues"]) or row["change"]) + '</td></tr>' for row in report["rows"])
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' \
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">' \
        '<title>Agent Tripwire · run comparison</title><style>' + STYLE + '</style></head><body><main>' \
        '<div class="eyebrow">OBSERVED ACTIONS · BEFORE AND AFTER</div><h1>Run comparison</h1><div class="banner">' \
        + '<p>Before: ' + e(report["before"]["model"]) + ' / ' + e(report["before"]["policy"]) + '</p><p>After: ' \
        + e(report["after"]["model"]) + ' / ' + e(report["after"]["policy"]) + '</p></div><div class="card scroll"><table>' \
        '<thead><tr><th>Case</th><th>Before crossings</th><th>After crossings</th><th>Observation</th></tr></thead><tbody>' \
        + rows + '</tbody></table></div><footer>' + ''.join('<p>' + e(note) + '</p>' for note in report["notes"]) + '</footer></main></body></html>'
