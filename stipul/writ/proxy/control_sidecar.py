"""Loopback-only in-process HTTP control sidecar for the proxy."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from stipul.writ.proxy.operator_state import OperatorStateError

if TYPE_CHECKING:
    from stipul.writ.proxy.server import ProxyServer

_HOST = "127.0.0.1"
_CONTROL_PANEL_PATH = Path(__file__).with_name("control_panel.html")


def _operator_status_payload(proxy: ProxyServer) -> dict[str, object]:
    proxy._refresh_operator_state()
    payload = proxy.health.payload()
    return {
        "kill_switch_active": payload["kill_switch_active"],
        "operator_updated_at": payload["operator_updated_at"],
        "operator_updated_by": payload["operator_updated_by"],
        "operator_reason": payload["operator_reason"],
    }


def _health_payload(proxy: ProxyServer) -> dict[str, object]:
    proxy._refresh_operator_state()
    return proxy.health.payload()


class _ControlHTTPServer(HTTPServer):
    proxy: ProxyServer


class _ControlHandler(BaseHTTPRequestHandler):
    server: _ControlHTTPServer

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        try:
            if path == "/":
                self._send_html(200, _CONTROL_PANEL_PATH.read_text(encoding="utf-8"))
                return
            if path == "/health":
                self._send_json(200, _health_payload(self.server.proxy))
                return
            if path == "/operator/status":
                self._send_json(200, _operator_status_payload(self.server.proxy))
                return
            self._send_json(404, {"error": "not_found"})
        except OperatorStateError as exc:
            self.server.proxy.health.set_degraded(True)
            self._send_json(503, {"error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in {
            "/operator/kill-switch/enable",
            "/operator/kill-switch/disable",
        }:
            self._send_json(404, {"error": "not_found"})
            return

        try:
            payload = self._read_json_object()
            by = payload.get("by")
            reason = payload.get("reason")
            if not isinstance(by, str) or not by:
                self._send_json(400, {"error": "field `by` must be a non-empty string"})
                return
            if not isinstance(reason, str) or not reason:
                self._send_json(400, {"error": "field `reason` must be a non-empty string"})
                return

            self.server.proxy.set_kill_switch(
                path.endswith("/enable"),
                updated_by=by,
                reason=reason,
            )
            self._send_json(200, _operator_status_payload(self.server.proxy))
        except json.JSONDecodeError:
            self._send_json(400, {"error": "request body must be valid JSON"})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except OperatorStateError as exc:
            self.server.proxy.health.set_degraded(True)
            self._send_json(503, {"error": str(exc)})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def _read_json_object(self) -> dict[str, object]:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length) if content_length > 0 else b"{}"
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")
        return payload

    def _send_json(self, status_code: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status_code: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@dataclass
class ControlSidecar:
    """Own a loopback-only HTTP server bound to a proxy instance."""

    proxy: ProxyServer
    host: str = _HOST
    _server: _ControlHTTPServer | None = field(default=None, init=False, repr=False)
    _thread: Thread | None = field(default=None, init=False, repr=False)
    _base_url: str | None = field(default=None, init=False)

    def start(self, *, port: int = 0) -> str:
        if self._server is not None and self._base_url is not None:
            return self._base_url

        server = _ControlHTTPServer((self.host, port), _ControlHandler)
        server.proxy = self.proxy
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()

        server_address = server.server_address
        bound_host_value = server_address[0]
        bound_host = (
            bound_host_value.decode("utf-8", errors="replace")
            if isinstance(bound_host_value, bytes)
            else str(bound_host_value)
        )
        bound_port = int(server_address[1])
        self._server = server
        self._thread = thread
        self._base_url = f"http://{bound_host}:{bound_port}"
        print(f"Control sidecar listening on {self._base_url}")
        return self._base_url

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        if server is None:
            return

        try:
            server.shutdown()
            server.server_close()
        finally:
            if thread is not None:
                thread.join(timeout=2.0)
            self._server = None
            self._thread = None
            self._base_url = None
