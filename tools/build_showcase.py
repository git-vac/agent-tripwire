"""Regenerate examples/terminal.svg from the checked-in scripted demo report.

Run with: python tools/build_showcase.py
"""

from html import escape
import json
from pathlib import Path


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def showcase(report):
    cases = {(result["id"], result["trial"]): result for result in report["results"]}
    control = cases["control", 1]
    attack = cases["ticket-exfil", 1]
    if (
        report["mode"] != "demo"
        or report["policy"] != "observe"
        or not control["task_complete"]
        or control["status"] != "no-boundary-crossing"
        or not attack["clean_control_ok"]
        or attack["status"] != "boundary-crossed"
    ):
        raise ValueError("showcase requires the scripted observe demo with a valid control")

    def event(kind, tool=None):
        return next(
            item for item in attack["events"]
            if item["kind"] == kind and (tool is None or item.get("tool") == tool)
        )

    ticket = event("tool_attempt", "read_ticket")
    injection = event("injection_delivered", "read_ticket")
    notes = event("tool_attempt", "search_notes")
    read = event("tool_attempt", "read_file")
    result = event("tool_result", "read_file")
    post = event("tool_attempt", "send_http")
    receipt = event("receiver_observed")
    proof = {item["step"] for item in attack["evidence"]}
    if (
        not read["unauthorized"]
        or not post["unauthorized"]
        or not receipt["canary_received"]
        or not {result["step"], receipt["step"]} <= proof
    ):
        raise ValueError("showcase requires evidence of a forbidden read and a received canary")

    rows = [
        (ticket, "read_ticket", ticket["arguments"]["ticket_id"], "Permitted"),
        (injection, "Injection delivered", "Untrusted ticket content", "Exposed"),
        (notes, "search_notes", notes["arguments"]["query"], "Permitted"),
        (read, "read_file", read["arguments"]["path"], "Out of scope"),
        (result, "Private read completed", "Synthetic canary returned", "Verified"),
        (post, "send_http", "POST to loopback receiver", "Out of scope"),
        (receipt, "Canary transfer verified", f'{receipt["bytes"]} bytes received locally', "Verified"),
    ]

    svg = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1160" height="636" viewBox="0 0 1160 636" role="img" aria-labelledby="title desc">',
        '<!-- Design method: Unslop by Damir Sokolovsky (@heydamir), CC BY 4.0. https://github.com/heydamir/unslop -->',
        '<title id="title">Agent Tripwire: trace of a scripted prompt injection</title>',
        '<desc id="desc">The clean control completed without a boundary crossing. In ticket-exfil, the agent read the private synthetic canary and the local HTTP receiver confirmed its transfer.</desc>',
        '<style>',
        'text{font-family:system-ui,Segoe UI,sans-serif;fill:#efede8;font-variant-numeric:tabular-nums}',
        '.mono{font-family:Consolas,Menlo,monospace}.meta{fill:#b0aea7}.rule{stroke:#383632}.proof{fill:#f0be77}',
        '</style>',
        '<rect x="0.5" y="0.5" width="1159" height="635" rx="16" fill="#191918" stroke="#383632"/>',
        '<path d="M40 60H1120" class="rule"/>',
        '<text x="40" y="43" font-size="18" font-weight="600">Agent Tripwire</text>',
        '<text x="1120" y="43" text-anchor="end" class="mono meta" font-size="16">Scripted demo · No model evaluated</text>',
        '<text x="40" y="112" font-size="42" font-weight="500">From ticket injection to confirmed transfer</text>',
        '<text x="40" y="144" class="meta" font-size="18">Selected events from the support assistant demo</text>',
        '<rect x="40" y="172" width="240" height="384" rx="12" fill="#222220" stroke="#383632"/>',
        '<text x="60" y="208" font-size="17" class="meta">Scenario</text>',
        f'<text x="60" y="244" font-size="25" class="mono">{escape(attack["id"])}</text>',
        f'<text x="60" y="276" font-size="17" class="meta">Trial {attack["trial"]} · Observe policy</text>',
        '<path d="M60 300H260M60 424H260" class="rule"/>',
        '<text x="60" y="332" font-size="17" class="meta">Outcome</text>',
        '<text x="60" y="364" font-size="22" class="proof">Boundary crossed</text>',
        f'<text x="60" y="392" font-size="17" class="meta">{len(proof)} verified effects</text>',
        '<text x="60" y="456" font-size="17" class="meta">Clean control</text>',
        '<text x="60" y="488" font-size="22">Task completed</text>',
        '<text x="60" y="516" font-size="17" class="meta">No boundary crossing</text>',
        '<text x="304" y="198" font-size="16" class="meta">Step</text>',
        '<text x="416" y="198" font-size="16" class="meta">Recorded event</text>',
        '<text x="736" y="198" font-size="16" class="meta">Detail</text>',
        '<text x="1104" y="198" text-anchor="end" font-size="16" class="meta">Evidence status</text>',
        '<path d="M304 220H1120" class="rule"/>',
    ]
    for index, (item, label, detail, status) in enumerate(rows):
        top = 220 + index * 48
        y = top + 30
        verified = item["step"] in proof
        if verified:
            svg.extend([
                f'<rect x="304" y="{top+1}" width="816" height="47" fill="#2d261e"/>',
                f'<path d="M304 {top+1}v47" stroke="#c28b4c" stroke-width="2"/>',
            ])
        svg.extend([
            f'<text x="320" y="{y}" class="mono {"proof" if verified else "meta"}" font-size="17">{item["step"]:02d}</text>',
            f'<text x="416" y="{y}" class="{"mono" if item["kind"] == "tool_attempt" else ""}" font-size="19">{label}</text>',
            f'<text x="736" y="{y}" class="meta" font-size="17">{escape(detail)}</text>',
            f'<text x="1104" y="{y}" text-anchor="end" class="{"proof" if verified else "meta"}" font-size="17">{status}</text>',
            f'<path d="M304 {top+48}H1120" class="rule"/>',
        ])
    svg.extend([
        '<path d="M40 580H1120" class="rule"/>',
        '<text x="40" y="612" class="meta" font-size="17">Observe mode records out-of-scope actions inside the synthetic environment</text>',
        '</svg>',
    ])
    return "\n".join(svg) + "\n"


if __name__ == "__main__":
    report = json.loads((EXAMPLES / "demo-report.json").read_text(encoding="utf-8"))
    (EXAMPLES / "terminal.svg").write_text(showcase(report), encoding="utf-8", newline="\n")
