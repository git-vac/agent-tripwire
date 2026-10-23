"""Shared authenticated HTTP host for independently running applications."""
import asyncio
from contextlib import AbstractContextManager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import secrets
from threading import Lock, Thread

from .agents import AgentError
from .application_wire import PROTOCOL, authorized, loopback_url, read_json, reply
from .host_tools import ExecutionLimit
from .report import new_file


def validate_request(request):
    if (set(request) != {"protocol", "case_id", "system", "task", "mcp", "limits", "seed"} or
            request["protocol"] != PROTOCOL or not isinstance(request["case_id"], str) or
            not re.fullmatch(r"[a-f0-9]{32}", request["case_id"]) or type(request["seed"]) is not int or
            any(not isinstance(request[key], str) or len(request[key].encode()) > 16384 for key in ("system", "task"))):
        raise ValueError("Invalid application request")
    mcp, limits = request["mcp"], request["limits"]
    if (not isinstance(mcp, dict) or set(mcp) != {"url", "token"} or
            not isinstance(mcp["token"], str) or not 32 <= len(mcp["token"]) <= 256):
        raise ValueError("Invalid case capability")
    loopback_url(mcp["url"], "/mcp")
    if not isinstance(limits, dict) or set(limits) != {"max_turns", "max_calls", "case_timeout"}:
        raise ValueError("Invalid limits")
    for key, low, high in (("max_turns", 1, 30), ("max_calls", 1, 100), ("case_timeout", 1, 1800)):
        if type(limits[key]) is not int or not low <= limits[key] <= high:
            raise ValueError("Invalid limits")


async def execute(request, runner):
    final, error, exhausted = "", None, False
    try:
        content, limited = await asyncio.wait_for(runner(request), request["limits"]["case_timeout"])
        if not isinstance(content, str) or type(limited) is not bool or len(content.encode()) > 32768:
            raise ValueError("Invalid application result")
        final, exhausted = content, limited
    except asyncio.TimeoutError:
        error, exhausted = "deadline", True
    except asyncio.CancelledError:
        error = "agent-failed"
    except AgentError:
        error = "agent-failed"
    except Exception as exc:
        # Never serialize SDK/provider exceptions: they may include headers/URLs.
        def limit_error(error):
            return isinstance(error, (ExecutionLimit, TimeoutError, asyncio.TimeoutError)) or any(limit_error(item)
                for item in getattr(error, "exceptions", ()))
        if limit_error(exc):
            exhausted = True
        else:
            error = "protocol-failed"
    return {"protocol": PROTOCOL, "case_id": request["case_id"], "final": final,
        "error": error, "limits_reached": exhausted}


class ApplicationHost(AbstractContextManager):
    """Trusted application process; the harness observes only its case tools."""
    def __init__(self, info, runner, redactions=()):
        self.token = secrets.token_urlsafe(32)
        self.secrets = [self.token, *[item for item in redactions if item]]
        self.info = dict(info)
        if (set(self.info) != {"protocol", "application", "version", "mode", "model", "provider", "configuration"} or
                self.info["protocol"] != PROTOCOL or self.info["mode"] not in ("demo", "run") or
                any(not isinstance(value, str) or not value or len(value) > 200 for value in self.info.values())):
            raise ValueError("Invalid application identity; use non-secret labels of at most 200 characters")
        for secret in self.secrets:
            self.info = {key: value.replace(secret, "[REDACTED CREDENTIAL]") for key, value in self.info.items()}
        self.run_request = runner
        self.lock, self.case_ids = Lock(), set()

    def __enter__(self):
        app = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(3)

            def log_message(self, *args):
                pass

            def do_GET(self):
                if not authorized(self, app.token):
                    reply(self, 403)
                else:
                    reply(self, 200 if self.path == "/tripwire/v1/info" else 404,
                        app.info if self.path == "/tripwire/v1/info" else None)

            def do_POST(self):
                if not authorized(self, app.token):
                    reply(self, 403)
                    return
                if self.path != "/tripwire/v1/run":
                    reply(self, 404)
                    return
                try:
                    request = read_json(self)
                    validate_request(request)
                except (OSError, ValueError, TypeError, KeyError, RecursionError):
                    reply(self, 400)
                    return
                if not app.lock.acquire(blocking=False):
                    reply(self, 409)
                    return
                try:
                    if request["case_id"] in app.case_ids or len(app.case_ids) >= 2000:
                        reply(self, 409)
                        return
                    app.case_ids.add(request["case_id"])
                    response = asyncio.run(execute(request, app.run_request))
                    # Runtime capabilities are private even if a provider echoes them.
                    for secret in [*app.secrets, request["mcp"]["token"]]:
                        response["final"] = response["final"].replace(secret, "[REDACTED CREDENTIAL]")
                    reply(self, 200, response)
                finally:
                    app.lock.release()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()
        return self

    def connection_file(self, path):
        new_file(path, json.dumps({"protocol": PROTOCOL, "url": self.url, "token": self.token}) + "\n")

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
