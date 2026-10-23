import argparse
import json
import os
from pathlib import Path
import sys

from rich.console import Console
from rich.text import Text

from . import __version__
from .agents import Ollama, OpenAICompatible, Scripted
from . import comparison
from .report import new_file, terminal, webpage
from .workflow import junit, select_results
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
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
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
    report_parser = commands.add_parser("report", help="Inspect saved evidence offline; no model requests")
    report_parser.add_argument("input", metavar="FILE")
    report_parser.add_argument("--scenario", action="append", help="Show selected case IDs with their clean controls")
    report_parser.add_argument("--trial", type=bounded(1, 20), help="Show one trial")
    report_parser.add_argument("--only", choices=("findings", "attention"), help="Findings: confirmed crossings; attention: crossings, attempts or incomplete results")
    example = commands.add_parser("example-agent", help="Serve a separate MCP agent application on loopback")
    example.add_argument("--connection-file", required=True, metavar="FILE", help="New private file for generated lab credentials")
    example.add_argument("--engine", choices=("scripted-vulnerable", "scripted-guarded", "ollama", "openai-compatible"), default="scripted-vulnerable")
    example.add_argument("--model")
    example.add_argument("--base-url")
    example.add_argument("--api-key-env", metavar="NAME")
    example.add_argument("--timeout", type=bounded(1, 120), default=60)
    example.add_argument("--no-color", action="store_true")
    for name in ("demo", "run", "check", "report", "app"):
        sub = report_parser if name == "report" else commands.add_parser(name, help={
            "demo": "Scripted instrumentation demo", "run": "Test a real tool-calling model",
            "check": "Verify connection and tool round trip with one clean task",
            "app": "Evaluate a separately running application through the HTTP/MCP adapter"}[name])
        if name in ("run", "demo", "app"):
            sub.add_argument("--scenario", action="append", help="Repeat to select case IDs; default: all loaded cases")
        if name != "report":
            sub.add_argument("--policy", choices=("observe", "enforce"), default="observe")
            if name == "check":
                sub.set_defaults(trials=1)
            else:
                sub.add_argument("--trials", type=bounded(1, 20), default=1)
        sub.add_argument("--html", metavar="FILE")
        sub.add_argument("--json", metavar="FILE", help="Export complete run as JSON (not filtered)")
        sub.add_argument("--junit", metavar="FILE", help="Export complete run as JUnit XML (not filtered)")
        sub.add_argument("--details", action="store_true", help="Include full tool results and injection text in terminal output")
        sub.add_argument("--no-color", action="store_true")
        if name == "demo":
            sub.add_argument("--behavior", choices=("vulnerable", "guarded"), default="vulnerable")
        elif name in ("run", "check", "app"):
            if name == "app":
                sub.add_argument("--connection-file", required=True, metavar="FILE")
                sub.add_argument("--injection-call", type=bounded(1, 100), default=1, help="Inject only this matching source response ordinal")
            else:
                sub.add_argument("--model", required=True, help="Model name served by your selected backend; tools required")
                sub.add_argument("--provider", choices=("ollama", "openai-compatible"), default="ollama")
                sub.add_argument("--base-url", help="Server base URL; default: Ollama :11434, compatible :1234/v1")
                sub.add_argument("--api-key-env", metavar="NAME", help="Read a compatible endpoint's API key from this environment variable")
            if name in ("run", "app"):
                sub.add_argument("--scenario-file", action="append", default=[], metavar="FILE", help="Load additional JSON scenarios")
            if name != "app":
                sub.add_argument("--timeout", type=bounded(1, 120), default=60, help="Per-request timeout in seconds")
            sub.add_argument("--case-timeout", type=bounded(1, 1800), default=180)
            sub.add_argument("--max-turns", type=bounded(1, 30), default=8)
            sub.add_argument("--max-calls", type=bounded(1, 100), default=24)
            sub.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)
    console = Console(no_color=args.no_color or bool(os.getenv("NO_COLOR")), highlight=False)
    try:
        if args.command == "example-agent":
            try:
                import mcp  # noqa: F401
            except ImportError:
                raise ValueError('The example application needs: python -m pip install ".[application]"') from None
            from .example_agent import ExampleApplication
            api_key = os.environ.get(args.api_key_env) if args.api_key_env else None
            if args.api_key_env and not api_key:
                raise ValueError("The named API key environment variable is empty or unset")
            if Path(args.connection_file).exists():
                raise ValueError("Connection file already exists; choose a new private filename")
            with ExampleApplication(args.engine, args.model, args.base_url, api_key, args.timeout) as app:
                app.connection_file(args.connection_file)
                console.print(Text("Separate MCP example application ready. Private connection file created; keep this process running."))
                console.print(Text("Mode: " + app.info["mode"] + " · " + app.info["model"]))
                app.thread.join()
            return 0
        if args.command == "list":
            for scenario in load_scenarios(args.scenario_file).values():
                console.print(Text(scenario.id, style="cyan"))
                console.print(Text("  " + scenario.title + "\n  " + scenario.objective))
            return 0
        outputs = [Path(path) for path in (args.html, args.json, getattr(args, "junit", None)) if path]
        if len({path.resolve() for path in outputs}) != len(outputs):
            raise ValueError("Each output needs a different path")
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
        if args.command == "report":
            source = comparison.read_report(args.input)
            report = select_results(source, args.scenario, args.trial, args.only)
            terminal(report, console, args.details)
            if args.html:
                new_file(args.html, webpage(report))
            if args.json:
                new_file(args.json, json.dumps(source, ensure_ascii=False, indent=2) + "\n")
            if args.junit:
                new_file(args.junit, junit(source))
            # Filtering must never hide a failure from automation.
            return exit_code(source)
        available = load_scenarios(getattr(args, "scenario_file", []))
        selected = [] if args.command == "check" else list(dict.fromkeys(args.scenario or available))
        unknown = [name for name in selected if name not in available]
        if unknown:
            raise ValueError("Unknown scenario ID; use 'list' with the same scenario files")
        scenarios = [available[name] for name in selected]
        limits = {}
        def progress(trial, scenario):
            console.print(Text(f'Running trial {trial}: {scenario.id if scenario else "clean control"}…', style="dim"))
        if args.command == "app":
            from .application import HTTPApplicationAdapter, run_application_suite
            adapter = HTTPApplicationAdapter.from_file(args.connection_file)
            report = run_application_suite(adapter, scenarios, policy=args.policy, trials=args.trials,
                seed=args.seed, injection_call=args.injection_call, max_turns=args.max_turns,
                max_calls=args.max_calls, case_timeout=args.case_timeout, progress=progress)
        elif args.command == "demo":
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
        if args.command != "app":
            report = run_suite(factory, scenarios, mode="run" if args.command == "check" else args.command, model=model, policy=args.policy,
                trials=args.trials, seed=getattr(args, "seed", 0), provider=getattr(args, "provider", "scripted"), progress=progress, **limits)
        if args.command == "check":
            report["purpose"] = "connection-check"
            report["notes"].insert(0, "Connection check only: clean task and tool round trip; no injection scenarios were run.")
            if exit_code(report) == 0:
                console.print(Text("Connection check passed: ticket and notes tools returned data, and the task check passed.", style="green"))
            else:
                console.print(Text("Connection check failed. Inspect the control timeline and endpoint/model settings.", style="yellow"))
        terminal(report, console, args.details)
        if args.html:
            new_file(args.html, webpage(report))
            console.print(Text("HTML saved: " + args.html, style="cyan"))
        if args.json:
            new_file(args.json, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
            console.print(Text("JSON saved: " + args.json, style="cyan"))
        if args.junit:
            new_file(args.junit, junit(report))
            console.print(Text("JUnit saved: " + args.junit, style="cyan"))
        return exit_code(report)
    except (ValueError, OSError) as exc:
        Console(stderr=True, no_color=True).print(Text("Error: " + str(exc)))
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
