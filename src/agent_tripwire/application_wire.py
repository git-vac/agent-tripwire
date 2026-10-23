"""Bounded, loopback-only application adapter transport (not a general HTTP tool)."""
import json
import secrets
from queue import Queue, Empty
from threading import Thread
import urllib.parse
import urllib.error
import urllib.request

from .environment import NoRedirect

PROTOCOL = "tripwire.application.v1"
MAX_BODY = 128 * 1024


def loopback_url(value, path=None):
    if not isinstance(value, str):
        raise ValueError("Expected a loopback URL string")
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port or
            parsed.username or parsed.password or parsed.query or parsed.fragment or
            (path is not None and parsed.path != path)):
        raise ValueError("Application integration requires an explicit http://127.0.0.1:PORT endpoint")
    return value.rstrip("/")


def request_json(url, token, payload=None, timeout=10):
    data = json.dumps(payload).encode() if payload is not None else None
    if data is not None and len(data) > MAX_BODY:
        raise ValueError("Application request exceeds 128 KiB")
    request = urllib.request.Request(url, data=data, headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        raw = response.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY:
        raise ValueError("Application response exceeds 128 KiB")
    return json.loads(raw)


def bounded_request_json(url, token, payload=None, timeout=10):
    """Bound wall time even if a peer continuously trickles response bytes."""
    result = Queue(maxsize=1)

    def work():
        try:
            result.put((True, request_json(url, token, payload, timeout)))
        except Exception as exc:
            timed_out = isinstance(exc, TimeoutError) or (
                isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, TimeoutError))
            result.put((False, "deadline" if timed_out else None))

    Thread(target=work, daemon=True).start()
    try:
        ok, response = result.get(timeout=timeout)
    except Empty:
        raise TimeoutError("Application deadline reached") from None
    if not ok:
        if response == "deadline":
            raise TimeoutError("Application deadline reached") from None
        raise ValueError("Application transport or protocol failed")
    return response


def authorized(handler, token):
    # Reject browser origins and Host rebinding even when a token is present.
    return (handler.headers.get("Origin") is None and
        handler.headers.get("Host") == f"127.0.0.1:{handler.server.server_port}" and
        secrets.compare_digest(handler.headers.get("Authorization", "").encode(), ("Bearer " + token).encode()))


def read_json(handler):
    if handler.headers.get("Transfer-Encoding") or handler.headers.get_content_type() != "application/json":
        raise ValueError("Expected a bounded JSON body")
    length = int(handler.headers.get("Content-Length", "-1"))
    if not 0 < length <= MAX_BODY:
        raise ValueError("Invalid JSON body length")
    raw = handler.rfile.read(length)
    if len(raw) != length:
        raise ValueError("Truncated JSON body")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def reply(handler, status, value=None):
    raw = json.dumps(value).encode() if value is not None else b""
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    try:
        handler.wfile.write(raw)
    except OSError:
        pass  # A timed-out caller may already have closed the connection.
