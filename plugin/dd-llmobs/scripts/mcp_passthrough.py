"""Minimal MCP server that responds to initialize/tools/list/ping and blocks on stdin."""
import json
import sys


def read_msg():
    header = b""
    while True:
        b = sys.stdin.buffer.read(1)
        if b == b"":
            raise EOFError()
        header += b
        if header.endswith(b"\r\n\r\n"):
            break
    length = int(header.decode().split(":")[1].strip())
    return json.loads(sys.stdin.buffer.read(length))


def write_msg(msg):
    body = json.dumps(msg).encode()
    frame = ("Content-Length: %d\r\n\r\n" % len(body)).encode() + body
    sys.stdout.buffer.write(frame)
    sys.stdout.buffer.flush()


SERVER_INFO = {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "serverInfo": {"name": "dd-llmobs-agent", "version": "1.0"},
}

while True:
    try:
        msg = read_msg()
    except EOFError:
        break
    method = msg.get("method", "")
    mid = msg.get("id")
    if method == "initialize":
        write_msg({"jsonrpc": "2.0", "id": mid, "result": SERVER_INFO})
    elif method == "tools/list":
        write_msg({"jsonrpc": "2.0", "id": mid, "result": {"tools": []}})
    elif method == "ping":
        write_msg({"jsonrpc": "2.0", "id": mid, "result": {}})
