import argparse
import json
import os
from pathlib import Path
import sys

from rich.console import Console
from rich.text import Text

from .agents import Ollama, OpenAICompatible, Scripted
from . import comparison
from .report import new_file, terminal, webpage
from .runner import exit_code, run_suite
from .scenarios import load_scenarios


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
    listing.add_argument("--scenario-file", action="append", default=[], metavar="FILE")
    compare_parser = commands.add_parser("compare", help="Compare saved JSON runs")
    compare_parser.add_argument("before")
    compare_parser.add_argument("after")
    compare_parser.add_argument("--html", metavar="FILE")
    compare_parser.add_argument("--json", metavar="FILE")
    compare_parser.add_argument("--no-color", action="store_true")
    for name in ("demo", "run"):
        sub = commands.add_parser(name, help="Scripted instrumentation demo" if name == "demo" else "Test a real tool-calling model")
        sub.add_argument("--scenario", action="append", help="Repeat to select case IDs; default: all loaded cases")
        sub.add_argument("--policy", choices=("observe", "enforce"), default="observe")
        sub.add_argument("--trials", type=bounded(1, 20), default=1)
        sub.add_argument("--html", metavar="FILE")
        sub.add_argument("--json", metavar="FILE")
        sub.add_argument("--details", action="store_true", help="Include full tool results and injection text in terminal output")
        sub.add_argument("--no-color", action="store_true")
        if name == "demo":
            sub.add_argument("--behavior", choices=("vulnerable", "guarded"), default="vulnerable")
        else:
            sub.add_argument("--model", required=True, help="Model name served by your selected backend; tools required")
            sub.add_argument("--provider", choices=("ollama", "openai-compatible"), default="ollama")
            sub.add_argument("--base-url", help="Server base URL; default: Ollama :11434, compatible :1234/v1")
            sub.add_argument("--api-key-env", metavar="NAME", help="Read a compatible endpoint's API key from this environment variable")
            sub.add_argument("--scenario-file", action="append", default=[], metavar="FILE", help="Load additional JSON scenarios")
            sub.add_argument("--timeout", type=bounded(1, 120), default=60, help="Per-request timeout in seconds")
            sub.add_argument("--case-timeout", type=bounded(1, 1800), default=180)
            sub.add_argument("--max-turns", type=bounded(1, 30), default=8)
            sub.add_argument("--max-calls", type=bounded(1, 100), default=24)
            sub.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    console = Console(no_color=args.no_color or bool(os.getenv("NO_COLOR")), highlight=False)
    try:
        if args.command == "list":
            for scenario in load_scenarios(args.scenario_file).values():
                console.print(Text(scenario.id, style="cyan"))
                console.print(Text("  " + scenario.title + "\n  " + scenario.objective))
            return 0
        outputs = [Path(path) for path in (args.html, args.json) if path]
        if len({path.resolve() for path in outputs}) != len(outputs):
            raise ValueError("HTML and JSON need different output paths")
        for path in outputs:
            if path.exists():
                raise ValueError("Output already exists; choose a new filename")
        if args.command == "compare":
            report = comparison.compare(comparison.read_report(args.before), comparison.read_report(args.after))
            comparison.terminal(report, console)
            if args.html:
                new_file(args.html, comparison.webpage(report))
            if args.json:
                new_file(args.json, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
            return comparison.comparison_exit(report)
        available = load_scenarios(getattr(args, "scenario_file", []))
        selected = list(dict.fromkeys(args.scenario or available))
        unknown = [name for name in selected if name not in available]
        if unknown:
            raise ValueError("Unknown scenario ID; use 'list' with the same scenario files")
        scenarios = [available[name] for name in selected]
        limits = {}
        if args.command == "demo":
            factory = lambda environment: Scripted(environment, args.behavior)
            model = "scripted-" + args.behavior
        else:
            api_key = None
            if args.api_key_env:
                if args.provider != "openai-compatible":
                    raise ValueError("--api-key-env is supported by the openai-compatible provider")
                api_key = os.environ.get(args.api_key_env)
                if not api_key:
                    raise ValueError("The named API key environment variable is empty or unset")
            if args.provider == "openai-compatible":
                factory = lambda environment: OpenAICompatible(args.model, args.base_url or "http://127.0.0.1:1234/v1",
                    args.timeout, args.seed, api_key=api_key)
            else:
                factory = lambda environment: Ollama(args.model, args.base_url or "http://127.0.0.1:11434", args.timeout, args.seed)
            # Validate endpoint and model before creating environments.
            factory(None)
            model = args.model
            limits = {"max_turns": args.max_turns, "max_calls": args.max_calls, "case_timeout": args.case_timeout}
        def progress(trial, scenario):
            console.print(Text(f'Running trial {trial}: {scenario.id if scenario else "clean control"}…', style="dim"))
        report = run_suite(factory, scenarios, mode=args.command, model=model, policy=args.policy,
            trials=args.trials, seed=getattr(args, "seed", 0), provider=getattr(args, "provider", "scripted"), progress=progress, **limits)
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
