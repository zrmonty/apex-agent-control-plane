"""Deterministic read-only upstream fixture for the managed proxy gate."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json


class Handler(BaseHTTPRequestHandler):
    server_version = "ApexProxyFixture/1.0"

    def do_GET(self) -> None:  # noqa: N802
        self._write({"status": "ready", "tools": ["portfolio.read"]})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        self._write({"jsonrpc": "2.0", "id": 1, "result": {"echoBytes": len(body)}})

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _write(self, value: dict[str, object]) -> None:
        data = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
