#!/usr/bin/env python3
"""THROWAWAY Leg C stub: stands in for the oauth2-proxy admin tier.

Listens on LEGC_PROXY_LISTEN (default 127.0.0.1:8443), strips any
client-supplied X-Forwarded-User, injects the one spike identity, and forwards
to rdpgw (default https://127.0.0.1:9443) from source address LEGC_EGRESS_SRC
(default 127.0.0.2 — the only address in rdpgw's Header.TrustedProxies).
NOT an authenticator — it unconditionally asserts one identity for the spike."""
import http.client
import http.server
import os
import ssl
import sys
import urllib.error
import urllib.request

RDPGW = os.environ.get("LEGC_RDPGW", "https://127.0.0.1:9443")
USER = "kvm-admin@example.test"  # the one allowlisted identity for the spike
_host, _port = os.environ.get("LEGC_PROXY_LISTEN", "127.0.0.1:8443").rsplit(":", 1)
LISTEN = (_host, int(_port))
EGRESS_SRC = os.environ.get("LEGC_EGRESS_SRC", "127.0.0.2")
STATE = os.environ.get("LEGC_STATE", "spikes/legc-rdpgw/state")

# rdpgw uses a self-signed cert on loopback; the spike does not verify it.
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class _SrcHTTPSConnection(http.client.HTTPSConnection):
    """Egress from EGRESS_SRC so rdpgw sees the trusted proxy address."""

    def __init__(self, *args, **kwargs):
        kwargs["source_address"] = (EGRESS_SRC, 0)
        super().__init__(*args, **kwargs)


class _SrcHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_SrcHTTPSConnection, req, context=_CTX)


_OPENER = urllib.request.build_opener(_SrcHTTPSHandler)


class Proxy(http.server.BaseHTTPRequestHandler):
    def _forward(self):
        body_len = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(body_len) if body_len else None
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "x-forwarded-user", "x-forwarded-for", "content-length")}
        headers["X-Forwarded-User"] = USER  # strip-then-inject: client cannot smuggle one
        # As oauth2-proxy / Traefik do. rdpgw ignores it unless the proxy is in
        # Server.TrustedProxies; then it becomes the token's clientIp, which is
        # what lets Security.VerifyClientIp work through a proxy.
        headers["X-Forwarded-For"] = self.client_address[0]
        req = urllib.request.Request(RDPGW + self.path, data=body, headers=headers, method=self.command)
        try:
            with _OPENER.open(req) as r:
                self.send_response(r.status)
                for k, v in r.headers.items():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(r.read())
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read())

    do_GET = _forward
    do_POST = _forward


if __name__ == "__main__":
    httpd = http.server.ThreadingHTTPServer(LISTEN, Proxy)
    # HTTPS so the browser / client trusts the download page (spike cert).
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(f"{STATE}/server.pem", f"{STATE}/key.pem")
    httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
    print(f"header-proxy on https://{LISTEN[0]}:{LISTEN[1]} -> {RDPGW} "
          f"from {EGRESS_SRC} as {USER}", file=sys.stderr, flush=True)
    httpd.serve_forever()
