import argparse
import json
import os
from pathlib import Path
import sys

from rich.console import Console
from rich.text import Text

from .agents import Ollama, Scripted
from .report import new_file, terminal, webpage
from .runner import exit_code, run_suite
from .scenarios import BY_ID, SCENARIOS


def bounded(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"Must be between {low} and {high}")
        return number
    return parse


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Test prompt injections by observing tool actions in a synthetic environment.")
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="List bundled injection scenarios")
    listing.add_argument("--no-color", action="store_true")
    for name in ("demo", "run"):
        sub = commands.add_parser(name, help="Scripted instrumentation demo" if name == "demo" else "Test a real Ollama model")
        sub.add_argument("--scenario", action="append", choices=list(BY_ID), help="Repeat to select cases; default: all")
        sub.add_argument("--policy", choices=("observe", "enforce"), default="observe")
        sub.add_argument("--trials", type=bounded(1, 20), default=1)
        sub.add_argument("--html", metavar="FILE")
        sub.add_argument("--json", metavar="FILE")
        sub.add_argument("--details", action="store_true", help="Include full tool results and injection text in terminal output")
        sub.add_argument("--no-color", action="store_true")
        if name == "demo":
            sub.add_argument("--behavior", choices=("vulnerable", "guarded"), default="vulnerable")
        else:
            sub.add_argument("--model", required=True, help="Installed Ollama model with tool-calling support")
            sub.add_argument("--base-url", default="http://127.0.0.1:11434", help="Ollama server origin")
            sub.add_argument("--timeout", type=bounded(1, 120), default=60, help="Per-request timeout in seconds")
            sub.add_argument("--case-timeout", type=bounded(1, 1800), default=180)
            sub.add_argument("--max-turns", type=bounded(1, 30), default=8)
            sub.add_argument("--max-calls", type=bounded(1, 100), default=24)
            sub.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    console = Console(no_color=args.no_color or bool(os.getenv("NO_COLOR")), highlight=False)
    if args.command == "list":
        for scenario in SCENARIOS:
            console.print(Text(scenario.id, style="cyan"))
            console.print(Text("  " + scenario.title + "\n  " + scenario.objective))
        return 0
    try:
        outputs = [Path(path) for path in (args.html, args.json) if path]
        if len({path.resolve() for path in outputs}) != len(outputs):
            raise ValueError("HTML and JSON need different output paths")
        for path in outputs:
            if path.exists():
                raise ValueError("Output already exists; choose a new filename")
        scenarios = [BY_ID[name] for name in dict.fromkeys(args.scenario or BY_ID)]
        limits = {}
        if args.command == "demo":
            factory = lambda environment: Scripted(environment, args.behavior)
            model = "scripted-" + args.behavior
        else:
            factory = lambda environment: Ollama(args.model, args.base_url, args.timeout, args.seed)
            # Validate endpoint and model before creating environments.
            factory(None)
            model = args.model
            limits = {"max_turns": args.max_turns, "max_calls": args.max_calls, "case_timeout": args.case_timeout}
        def progress(trial, scenario):
            console.print(Text(f'Running trial {trial}: {scenario.id if scenario else "clean control"}…', style="dim"))
        report = run_suite(factory, scenarios, mode=args.command, model=model, policy=args.policy,
            trials=args.trials, seed=getattr(args, "seed", 0), progress=progress, **limits)
        terminal(report, console, args.details)
        if args.html:
            new_file(args.html, webpage(report))
            console.print(Text("HTML saved: " + args.html, style="cyan"))
        if args.json:
            new_file(args.json, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
            console.print(Text("JSON saved: " + args.json, style="cyan"))
        return exit_code(report)
    except (ValueError, OSError) as exc:
        Console(stderr=True, no_color=True).print(Text("Error: " + str(exc)))
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
