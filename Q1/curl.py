#!/usr/bin/env python3
"""
CS3103 Assignment 3, Q1: retrieve yourip.php over HTTPS using raw sockets.
 
Requirements: Python 3.6+ (standard library only: socket, ssl, re).
Run on Linux:
    python3 q1.py
No compilation needed.
 
The HTTP/1.1 request is built by hand (RFC 9110 / RFC 9112) and sent over a
TCP socket wrapped in TLS. The response is parsed manually (status line,
headers, chunked or Content-Length body) and the IPv4 address is extracted.

"""

import re
import socket
import ssl

HOST = "varlabs.comp.nus.edu.sg"  # The server's hostname
PATH = "/tools/yourip.php"  # The path to the resource
PORT = 443  # HTTPS port

def build_request() -> bytes:
    """Construct a minimal, RFC-compliant HTTP/1.1 GET request.
    Lines end in CRLF and the header block ends with an empty line."""
    lines = [
        f"GET {PATH} HTTP/1.1",
        f"Host: {HOST}",
        "User-Agent: CS3103-Assignment3-Q1/1.0",
        "Accept: */*",
        "Connection: close",  # Close the connection after the response (HTTP/1.1 default is keep-alive)
        "",
        "",  # End of headers
    ]
    return "\r\n".join(lines).encode("ascii")

def recv_all(sock) -> bytes:
    """Receive all data from the socket until the connection is closed."""
    chunk = []
    while True:
        try:
            data = sock.recv(4096)
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            break
        if not data:
            break # data stream ends
        chunk.append(data)

    return b"".join(chunk)

def decode_chunks(body: bytes) -> bytes:
    """Decode a Transfer-Encoding: chunked body (RFC 9112 section 7.1).
    Format: <hex size>[;ext]\r\n<data>\r\n ... 0\r\n\r\n"""
    out = b""

    while body:
        line_end = body.find(b"\r\n")
        size = int(body[:line_end].split(b";")[0].strip(), 16)
        if size == 0:
            break

        start =  line_end + 2
        out += body[start:start + size]
        body = body[start + size + 2:]  # Skip the data and the trailing CRLF

    return out

def parse_response(raw: bytes):
    """Split raw bytes into status code, headers dict and decoded body."""
    head, _, body = raw.partition(b"\r\n\r\n")
    head_lines = head.decode("iso-8859-1").split("\r\n")
    
    status_code = int(head_lines[0].split(" ", 2)[1])

    headers = {}

    for line in head_lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = decode_chunks(body)
    elif "content-length" in headers:
        content_length = int(headers["content-length"])
        body = body[:content_length]

    return status_code, headers, body

def extract_ipv4(text: str):
    """Return the first valid dotted-quad IPv4 address in text."""
    for m in re.finditer(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", text):
        if all(0 <= int(o) <= 255 for o in m.groups()):
            return m.group(0)
    return None



def main():
    # 1. TCP connection, then wrap in TLS (SNI + certificate verification)
    context = ssl.create_default_context()
    
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            # 2. Send the hand-built HTTP request
            ssock.sendall(build_request())
            # 3. Read the full response
            raw = recv_all(ssock)

    # 4. Parse the HTTP response
    status, headers, body = parse_response(raw)

    if status != 200:
        print(f"Error: HTTP {status}")
        return

    ip = extract_ipv4(body.decode("utf-8", errors="replace"))
    if ip:
        print(f"Your IPv4 address is: {ip}")
    else:
        print("Error: No valid IPv4 address found in the response.")


if __name__ == "__main__":
    main()

