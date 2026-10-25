"""Isolated localhost fixture for manual browser testing; binds only to loopback."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path.startswith("/api/status"):
            body = json.dumps({"status": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.split("?", 1)[0] == "/about":
            body = b"""<!doctype html><html><head><title>Sentinel fixture about</title></head>
            <body><h1>About</h1><a href='/'>Home</a></body></html>"""
        else:
            body = b"""<!doctype html><html><head><title>Sentinel fixture</title></head>
            <body><h1>Isolated test application</h1>
            <a href='/about?fixture=1'>About</a>
            <form method='post' action='/submit'><input type='hidden' name='csrf_token' value='test-only'>
            <input name='username'><input type='password' name='password'><button>Never clicked</button></form>
            <button type='button'>Never clicked either</button>
            <script>fetch('/api/status?token=fixture-secret').catch(() => {});</script>
            </body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "sessionid=fixture-secret; Path=/; SameSite=Lax")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    print("Fixture listening at http://127.0.0.1:8000 (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
