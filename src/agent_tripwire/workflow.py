"""Offline evidence views and CI exports. No model or network operations."""
from collections import Counter
import xml.etree.ElementTree as ET

from .report import clean


def incomplete(result):
    return (result["status"] in ("error", "inconclusive") or bool(result["error"])
        or result["limits_reached"] or not result["task_complete"] or not result["clean_control_ok"])


def select_results(report, scenarios=None, trial=None, only=None):
    available = {result["id"] for result in report["results"]}
    if scenarios and set(scenarios) - available:
        raise ValueError("Unknown case ID in saved report")
    if trial and trial not in {result["trial"] for result in report["results"]}:
        raise ValueError("Trial is not present in saved report")
    if not (scenarios or trial or only):
        return report
    matches = []
    for result in report["results"]:
        if trial and result["trial"] != trial or scenarios and result["id"] not in scenarios:
            continue
        if only == "findings" and result["status"] != "boundary-crossed":
            continue
        if only == "attention" and not (result["status"] == "boundary-crossed" or result["attempted"] or incomplete(result)):
            continue
        matches.append(result)
    trials = {item["trial"] for item in matches}
    # Keep the attribution context even when the requested view has no findings.
    controls = [item for item in report["results"] if item["id"] == "control"
        and (item["trial"] in trials if trials else not trial or item["trial"] == trial)]
    keys = {(item["id"], item["trial"]) for item in matches + controls}
    results = [item for item in report["results"] if (item["id"], item["trial"]) in keys]
    return {**report, "results": results,
        "counts": dict(Counter(item["status"] for item in results if item["id"] != "control")),
        "view_notice": f"Filtered view: {len(matches)} matching results; relevant clean controls retained. "
            "Exit status and JSON/JUnit exports always describe the complete input run.",
        "notes": [*report["notes"], "No results match the requested filters." if not matches else
            "This view omits other results. Use the original JSON for the complete run."]}


def xml_text(value):
    # XML 1.0 disallows U+FFFE/U+FFFF, even though they are not control characters.
    return "".join(char for char in clean(value) if ord(char) not in (0xFFFE, 0xFFFF))


def junit(report):
    """One test per case/trial, including controls; invalid runs cannot look green."""
    root = ET.Element("testsuites")
    results = report["results"]
    errors = sum(incomplete(item) for item in results)
    failures = sum(not incomplete(item) and item["status"] == "boundary-crossed" for item in results)
    elapsed = sum(item["elapsed_ms"] for item in results) / 1000
    attrs = {"tests": str(len(results)), "failures": str(failures), "errors": str(errors),
        "skipped": "0", "time": f"{elapsed:.3f}"}
    root.attrib.update(attrs)
    suite = ET.SubElement(root, "testsuite", {"name": "Agent Tripwire", **attrs})
    properties = ET.SubElement(suite, "properties")
    for key in ("mode", "model", "provider", "policy", "purpose"):
        if key in report:
            ET.SubElement(properties, "property", {"name": key, "value": xml_text(report[key])})
    for item in results:
        case = ET.SubElement(suite, "testcase", {"classname": "agent_tripwire." + report["mode"],
            "name": xml_text(f'{item["id"]} / trial {item["trial"]}'), "time": f'{item["elapsed_ms"] / 1000:.3f}'})
        summary = ["Outcome: " + item["status"],
            "Task complete: " + str(item["task_complete"]), "Clean control OK: " + str(item["clean_control_ok"])]
        summary.extend(f'Step {proof["step"]}: {proof["finding"]}' for proof in item["evidence"])
        if item["error"]:
            summary.append("Error: " + item["error"])
        if item["limits_reached"]:
            summary.append("Execution budget reached")
        if incomplete(item):
            element = ET.SubElement(case, "error", {"type": "incomplete-evaluation",
                "message": "Incomplete evaluation or invalid clean control; inspect evidence"})
            element.text = xml_text("\n".join(summary))
        elif item["status"] == "boundary-crossed":
            element = ET.SubElement(case, "failure", {"type": "boundary-crossed", "message": "Forbidden action verified"})
            element.text = xml_text("\n".join(summary))
        ET.SubElement(case, "system-out").text = xml_text("\n".join(summary))
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
