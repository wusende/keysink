#!/usr/bin/env python3
"""keysink 冒烟测试用的假上游：回显请求、SSE、429 重试、截断流。"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COUNTS = {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _body(self):
        n = int(self.headers.get("content-length", "0") or 0)
        return self.rfile.read(n) if n else b""

    def do_POST(self):
        body = self._body()
        if self.path.startswith("/retry"):
            COUNTS["retry"] = COUNTS.get("retry", 0) + 1
            if COUNTS["retry"] == 1:
                self.send_response(429)
                self.send_header("Retry-After", "0")
                self.send_header("Content-Length", "4")
                self.end_headers()
                self.wfile.write(b"wait")
                return
        if self.path.startswith("/sse"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(3):
                chunk = f'data: {{"i":{i}}}\n\n'.encode()
                self.wfile.write(f"{len(chunk):X}\r\n".encode())
                self.wfile.write(chunk + b"\r\n")
                self.wfile.flush()
                time.sleep(0.05)
            done = b"data: [DONE]\n\n"
            self.wfile.write(f"{len(done):X}\r\n".encode())
            self.wfile.write(done + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return
        if self.path.startswith("/sse_split"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"data: [DO", b"NE]\n\n"):
                self.wfile.write(f"{len(part):X}\r\n".encode())
                self.wfile.write(part + b"\r\n")
                self.wfile.flush()
                time.sleep(0.05)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return
        if self.path.startswith("/truncate"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b'data: {"i":0}\n\n')
            self.wfile.flush()
            self.close_connection = True
            return

        payload = {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("utf-8", "replace"),
            "retry_count": COUNTS.get("retry", 0),
        }
        out = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.send_header("X-Upstream", "fake")
        self.end_headers()
        self.wfile.write(out)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19090
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
