"""Reproducible scripted experiment against a separate agent process.

No real model or provider credential is used. Artifacts are private local files.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from agent_tripwire.application import HTTPApplicationAdapter, run_application_suite
from agent_tripwire.comparison import compare, webpage as comparison_page, comparison_exit
from agent_tripwire.report import new_file, webpage
from agent_tripwire.runner import exit_code
from agent_tripwire.scenarios import SCENARIOS
from agent_tripwire.workflow import junit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="reports/application-experiment")
    args = parser.parse_args()
    output = Path(args.output)
    names = [f"{policy}.{extension}" for policy in ("observe", "enforce") for extension in ("json", "html", "xml")]
    names.append("comparison.html")
    if any((output / name).exists() for name in names):
        parser.error("Experiment output already exists; choose a new directory")
    with tempfile.TemporaryDirectory(prefix="tripwire-app-connection-") as directory:
        connection = Path(directory) / "connection.json"
        process = subprocess.Popen([sys.executable, "-m", "agent_tripwire", "example-agent",
            "--connection-file", str(connection)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 20
            while not connection.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.02)
            if not connection.exists():
                raise RuntimeError('Example agent did not start; install ".[application]" first')
            adapter = HTTPApplicationAdapter.from_file(connection)
            reports = []
            for policy in ("observe", "enforce"):
                report = run_application_suite(adapter, SCENARIOS, policy=policy, case_timeout=15)
                reports.append(report)
                new_file(output / f"{policy}.json", json.dumps(report, ensure_ascii=False, indent=2) + "\n")
                new_file(output / f"{policy}.html", webpage(report))
                new_file(output / f"{policy}.xml", junit(report))
                print(f"SCRIPTED {policy}: {report['counts']}; evaluation exit {exit_code(report)}")
            compared = compare(*reports)
            new_file(output / "comparison.html", comparison_page(compared))
            expected = (reports[0]["counts"] == {"boundary-crossed": 5} and exit_code(reports[0]) == 1 and
                reports[1]["counts"] == {"blocked": 5} and exit_code(reports[1]) == 0 and comparison_exit(compared) == 0)
            print("Harness experiment passed" if expected else "Harness experiment failed; inspect evidence")
            return 0 if expected else 2
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
