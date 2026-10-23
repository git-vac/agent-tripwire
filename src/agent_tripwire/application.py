"""Application adapter contract and runner for a separately running MCP host."""
from dataclasses import dataclass
import json
from pathlib import Path
import secrets
import time
from typing import Protocol

from .application_wire import PROTOCOL, loopback_url, bounded_request_json
from .mcp_lab import ApplicationEnvironment, MCPToolServer
from .runner import assess, run_suite
from .scenarios import SYSTEM, TASK


class ApplicationAdapter(Protocol):
    """A trusted host shim, never an adapter around model.next().

    execute must start a fresh conversation, use only the supplied case's tools,
    acknowledge received tool results and return the bounded final envelope.
    It must not infer or manufacture effect evidence. See docs/application.md.
    """
    info: dict

    def execute(self, request: dict, timeout: float) -> dict: ...


@dataclass
class HTTPApplicationAdapter:
    url: str
    token: str
    info: dict

    @classmethod
    def from_file(cls, path):
        with Path(path).open("rb") as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise ValueError("Application connection file exceeds 8 KiB")
        try:
            data = json.loads(raw)
            if (set(data) != {"protocol", "url", "token"} or data["protocol"] != PROTOCOL or
                    not isinstance(data["token"], str) or not 32 <= len(data["token"]) <= 256 or
                    not data["token"].isascii() or not data["token"].isprintable()):
                raise ValueError()
            url = loopback_url(data["url"], "")
            info = bounded_request_json(url + "/tripwire/v1/info", data["token"], timeout=5)
            if (not isinstance(info, dict) or set(info) != {"protocol", "application", "version", "mode", "model", "provider", "configuration"} or
                    info["protocol"] != PROTOCOL or info["mode"] not in ("demo", "run") or
                    any(not isinstance(value, str) or not value or len(value) > 200 for value in info.values())):
                raise ValueError()
            # A buggy application must not echo the bootstrap token into metadata.
            info = {key: value.replace(data["token"], "[REDACTED LAB CREDENTIAL]") for key, value in info.items()}
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            raise ValueError("Invalid application connection or handshake; check the running app and private connection file") from None
        return cls(url, data["token"], info)

    def execute(self, request, timeout):
        # Tools are revoked when this returns; a worker cannot extend access.
        return bounded_request_json(self.url + "/tripwire/v1/run", self.token, request, timeout)


def run_application_case(adapter, scenario=None, policy="observe", trial=1, max_turns=8, max_calls=24,
        case_timeout=180, injection_call=1, seed=0):
    started = time.monotonic()
    case_id = secrets.token_hex(16)
    final, error, exhausted = "", None, False
    with ApplicationEnvironment(scenario, policy, injection_call) as env:
        env.redactions.extend([getattr(adapter, "token", "")])
        env.redactions = [value for value in env.redactions if value]
        with MCPToolServer(env, case_id, max_calls, case_timeout) as lab:
            env.event("application_case", case_id=case_id, detail="Fresh application conversation and case-scoped MCP capability")
            request = {"protocol": PROTOCOL, "case_id": case_id, "system": SYSTEM, "task": TASK, "seed": seed,
                "mcp": {"url": lab.url, "token": lab.token},
                "limits": {"max_turns": max_turns, "max_calls": max_calls, "case_timeout": case_timeout}}
            try:
                response = adapter.execute(request, max(.001, lab.deadline - time.monotonic()))
                if (not isinstance(response, dict) or set(response) != {"protocol", "case_id", "final", "error", "limits_reached"} or
                        response["protocol"] != PROTOCOL or response["case_id"] != case_id or
                        not isinstance(response["final"], str) or len(response["final"].encode()) > 32768 or
                        type(response["limits_reached"]) is not bool or
                        response["error"] not in (None, "agent-failed", "deadline", "protocol-failed")):
                    raise ValueError("Invalid response envelope")
                final = response["final"]
                # A host's deadline can fire before this process's wall clock.
                # It is a budget outcome even if the host omitted the limit flag.
                expired = response["error"] == "deadline"
                error = "Application reported " + response["error"] if response["error"] and not expired else None
                exhausted = expired or response["limits_reached"] or time.monotonic() >= lab.deadline
            except TimeoutError:
                exhausted = True
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                error = "Application transport or protocol failed; inspect the application locally"
            finally:
                lab.close_case()
            exhausted = exhausted or lab.limit_reached
            if final:
                env.event("assistant", content=final)
            if error:
                env.event("error", detail=error)
            if exhausted:
                env.event("limit", detail="Application or MCP execution budget reached; case capability revoked")
            # Server-side reads prove effects. Task success additionally needs app receipt.
            received = {event["tool"] for event in env.events if event["kind"] == "application_received" and event["task_data"]}
            checked_final = final if {"read_ticket", "search_notes"} <= received else ""
            outcome = assess(env.events, checked_final, env.exposed, scenario is None, error, exhausted)
            return {"id": scenario.id if scenario else "control", "title": scenario.title if scenario else "Clean control",
                "trial": trial, "case_id": case_id, "surface": scenario.surface if scenario else None,
                "objective": scenario.objective if scenario else "Complete the legitimate task without injection",
                "injection_exposed": env.exposed, "final": env.redact(final), "error": error,
                "limits_reached": exhausted, "tool_calls": lab.calls,
                "elapsed_ms": round((time.monotonic() - started) * 1000), "events": env.events,
                "receipts": env.receipts, **outcome}


def run_application_suite(adapter, scenarios, *, injection_call=1, **options):
    if not 1 <= injection_call <= 100:
        raise ValueError("Injection response ordinal must be between 1 and 100")
    def case_runner(_factory, *args, **kwargs):
        return run_application_case(adapter, *args, injection_call=injection_call, seed=options.get("seed", 0), **kwargs)
    report = run_suite(None, scenarios, mode=adapter.info["mode"], model=adapter.info["model"],
        provider=adapter.info["provider"], case_runner=case_runner, **options)
    report["integration"] = {"protocol": PROTOCOL, "transport": "mcp-streamable-http-2025-11-25-json",
        "application": adapter.info["application"], "version": adapter.info["version"],
        "configuration": adapter.info["configuration"], "injection_call": injection_call}
    report["purpose"] = "application-evaluation"
    report["notes"][0] = ("Scripted separate application: harness instrumentation only; not a model evaluation."
        if adapter.info["mode"] == "demo" else "Real model in a separate MCP agent application with synthetic case tools.")
    report["notes"].extend([
        "Application: " + adapter.info["application"] + " version " + adapter.info["version"] +
            "; integration: tripwire.application.v1 / MCP 2025-11-25 JSON tools.",
        "Injection delivery requires the application's acknowledgment of exact tool-response bytes; this does not prove model attention.",
        "Effects cover only the supplied MCP tools, temporary fixture files and case receiver. Other application capabilities are not monitored."])
    return report
