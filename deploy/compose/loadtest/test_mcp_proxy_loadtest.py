import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from mcp_proxy_loadtest import build_json_rpc_request, decode_payload, parse_json_rpc_response, run


def test_builds_json_rpc_requests_for_initialize_and_tool_calls():
    initialize = build_json_rpc_request(
        "initialize",
        1,
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
    )
    call = build_json_rpc_request("tools/call", 2, {"name": "portfolio.read", "arguments": {"portfolioId": "fixture"}})

    assert initialize == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    }
    assert call["method"] == "tools/call"
    assert call["params"]["name"] == "portfolio.read"


def test_parses_protocol_errors_without_returning_response_bodies():
    result = parse_json_rpc_response({"jsonrpc": "2.0", "id": 3, "error": {"code": -32000, "message": "private detail"}}, 3)

    assert result == {"ok": False, "error": "json-rpc error"}


def test_decodes_sse_json_rpc_messages_with_event_metadata():
    payload = decode_payload(b'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n')

    assert payload == {"jsonrpc": "2.0", "id": 1, "result": {}}


def test_run_reuses_mcp_sessions_for_warm_calls():
    methods: list[str] = []
    origins: list[str | None] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            origins.append(self.headers.get("origin"))
            if self.headers.get("origin") != "https://console.example.test":
                self.send_response(403)
                self.end_headers()
                return
            length = int(self.headers["content-length"] or "0")
            request = json.loads(self.rfile.read(length))
            methods.append(request["method"])
            if request["method"] == "initialize":
                body = {"jsonrpc": "2.0", "id": request["id"], "result": {"protocolVersion": "2025-06-18"}}
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("mcp-session-id", "fixture-session")
            elif request["method"] == "notifications/initialized":
                body = None
                self.send_response(202)
            else:
                body = {"jsonrpc": "2.0", "id": request["id"], "result": {}}
                self.send_response(200)
                self.send_header("content-type", "application/json")
            if body is not None:
                encoded = json.dumps(body).encode()
                self.send_header("content-length", str(len(encoded)))
            else:
                encoded = b""
                self.send_header("content-length", "0")
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        result = run(
            f"http://127.0.0.1:{server.server_port}/mcp",
            1,
            1,
            2,
            2.0,
            "fixture-token",
            origin="https://console.example.test",
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert result["successes"] == 2
    assert result["failures"] == 0
    assert methods == ["initialize", "notifications/initialized", "tools/list", "tools/call", "tools/call"]
    assert origins == ["https://console.example.test"] * 5
