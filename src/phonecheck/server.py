"""`phonecheck serve`: the same checkup as a local web page.

A web page that can uninstall apps from a phone is a juicy target: any website
you visit could try to send requests to localhost. The defences, each of which
has a test:

* listens on 127.0.0.1 only, never on the network
* every request's Host header must be exactly 127.0.0.1:PORT or localhost:PORT
  (blocks DNS-rebinding, where a hostile site points its own name at 127.0.0.1)
* every /api call needs a random per-run token that only the page we served
  knows (blocks cross-site request forgery)
* POST bodies must be application/json, which browsers will not send
  cross-origin without a preflight we never approve
* no CORS headers at all, a strict Content-Security-Policy, no inline script
* removal also needs an explicit {"confirm": "remove"} and goes through the
  same guarded remove_packages() as the command line
"""

from __future__ import annotations

import hmac
import json
import secrets
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .adb import AdbError, list_devices
from .collector import collect
from .removal import RemovalRefused, remove_packages
from .report import to_dict
from .rules import Context, analyze
from .source import DeviceSource

WEB_ROOT = Path(__file__).resolve().parent / "web"
MAX_BODY = 64 * 1024
TOKEN_HEADER = "X-Phonecheck-Token"
STATIC_FILES = {
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
}


class AppState:
    def __init__(self, source: DeviceSource, context: Context, port: int):
        self.source = source
        self.context = context
        self.token = secrets.token_urlsafe(32)
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        self.lock = threading.Lock()  # one phone operation at a time


class _HttpError(Exception):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Handler(BaseHTTPRequestHandler):
    server_version = "phonecheck"
    sys_version = ""  # do not advertise the Python version

    def version_string(self) -> str:
        return self.server_version  # the default appends a space and the Python version

    @property
    def state(self) -> AppState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format, *args):  # keep the terminal quiet; errors are reported explicitly
        pass

    # ---- plumbing -------------------------------------------------------

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: HTTPStatus, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

    def _check_host(self) -> None:
        if self.headers.get("Host") not in self.state.allowed_hosts:
            raise _HttpError(HTTPStatus.FORBIDDEN, "Unexpected Host header.")

    def _check_token(self) -> None:
        supplied = self.headers.get(TOKEN_HEADER, "")
        if not hmac.compare_digest(supplied.encode("utf-8"), self.state.token.encode("utf-8")):
            raise _HttpError(HTTPStatus.FORBIDDEN, "Missing or wrong token. Reload the page.")

    def _read_json(self) -> dict:
        content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise _HttpError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Send application/json.")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise _HttpError(HTTPStatus.LENGTH_REQUIRED, "Content-Length is required.") from None
        if length < 0 or length > MAX_BODY:
            raise _HttpError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request body too large.")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            raise _HttpError(HTTPStatus.BAD_REQUEST, "Body is not valid JSON.") from None
        if not isinstance(data, dict):
            raise _HttpError(HTTPStatus.BAD_REQUEST, "Body must be a JSON object.")
        return data

    def _dispatch(self, method: str) -> None:
        try:
            self._check_host()
            path = self.path.split("?", 1)[0]
            if method == "GET" and path == "/":
                page = (WEB_ROOT / "index.html").read_text(encoding="utf-8").replace("__TOKEN__", self.state.token)
                self._send(HTTPStatus.OK, page.encode("utf-8"), "text/html; charset=utf-8")
            elif method == "GET" and path in STATIC_FILES:
                name, content_type = STATIC_FILES[path]
                self._send(HTTPStatus.OK, (WEB_ROOT / name).read_bytes(), content_type)
            elif method == "GET" and path == "/api/status":
                self._check_token()
                self._json(HTTPStatus.OK, self._status())
            elif method == "POST" and path == "/api/scan":
                self._check_token()
                self._read_json()
                self._json(HTTPStatus.OK, self._scan())
            elif method == "POST" and path == "/api/remove":
                self._check_token()
                self._json(HTTPStatus.OK, self._remove(self._read_json()))
            else:
                raise _HttpError(HTTPStatus.NOT_FOUND, "Not found.")
        except _HttpError as exc:
            self._json(exc.status, {"error": exc.message})
        except RemovalRefused as exc:
            self._json(HTTPStatus.CONFLICT, {"error": str(exc)})
        except AdbError as exc:
            self._json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to the browser
            print(f"phonecheck: unexpected error: {exc!r}", file=sys.stderr)
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Something went wrong. See the terminal."})

    def do_GET(self) -> None:  # noqa: N802 - http.server's naming
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    # ---- actions --------------------------------------------------------

    def _status(self) -> dict:
        source = self.state.source
        phones: list[dict] = []
        note = None
        if source.is_real:
            try:
                phones = [
                    {"serial": e.serial, "state": e.state, "description": e.description}
                    for e in list_devices(source.adb_path)
                ]
            except AdbError as exc:
                note = str(exc)
        return {"source": source.label, "simulated": not source.is_real, "phones": phones, "note": note}

    def _scan(self) -> dict:
        with self.state.lock:
            snapshot = collect(self.state.source.open())
            return to_dict(analyze(snapshot, self.state.context))

    def _remove(self, body: dict) -> dict:
        packages = body.get("packages")
        if not isinstance(packages, list) or not all(isinstance(p, str) for p in packages):
            raise _HttpError(HTTPStatus.BAD_REQUEST, "'packages' must be a list of package names.")
        if body.get("confirm") != "remove":
            raise _HttpError(HTTPStatus.BAD_REQUEST, "Removal needs an explicit confirmation.")
        with self.state.lock:
            device = self.state.source.open()
            results = remove_packages(device, packages)
            report = analyze(collect(device), self.state.context)
        return {
            "results": [
                {"package": r.package, "ok": r.ok, "message": r.message, "hint": r.hint} for r in results
            ],
            "report": to_dict(report),
        }


def make_server(source: DeviceSource, context: Context, port: int = 8765) -> tuple[ThreadingHTTPServer, AppState]:
    """Bind to localhost (port 0 picks a free one) without starting to serve."""
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as exc:
        raise ValueError(f"Could not listen on port {port}: {exc.strerror or exc}. Try --port with another number.") from exc
    state = AppState(source, context, server.server_address[1])
    server.state = state  # type: ignore[attr-defined]
    return server, state


def serve(source: DeviceSource, context: Context, *, port: int, open_browser: bool, io) -> int:
    server, _ = make_server(source, context, port)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    io.say(f"phonecheck is running at {url}   (press Ctrl+C to stop)")
    io.say(f"Using: {source.label}. Only this computer can reach this page.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        io.say("\nStopped.")
    finally:
        server.server_close()
    return 0
