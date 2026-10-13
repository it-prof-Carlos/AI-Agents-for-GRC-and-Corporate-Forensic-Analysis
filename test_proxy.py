"""Test de integración del proxy DLP con un upstream falso local."""
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aegis.core.audit_chain import ImmutableAuditLog # type: ignore
from aegis.core.samples import FAKE_AWS, FAKE_OPENAI # type: ignore
from aegis.proxy import DLPProxy # type: ignore

visto = {}


class _Eco(BaseHTTPRequestHandler):
    def do_POST(self):
        cuerpo = self.rfile.read(int(self.headers["Content-Length"]))
        visto["body"], visto["auth"] = cuerpo.decode(), self.headers.get("Authorization")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *a):
        pass


def test_proxy_redacta_antes_de_reenviar_y_audita():
    up = HTTPServer(("127.0.0.1", 0), _Eco)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory() as td:
        log = ImmutableAuditLog(os.path.join(td, "a.jsonl"), hmac_key="k")
        px = DLPProxy(("127.0.0.1", 0), f"http://127.0.0.1:{up.server_port}", log)
        threading.Thread(target=px.serve_forever, daemon=True).start()
        payload = {"messages": [{"role": "user", "content": f"mi clave {FAKE_AWS} y host 10.0.0.5"}]}
        req = request.Request(f"http://127.0.0.1:{px.server_port}/v1/chat", method="POST",
                              data=json.dumps(payload).encode(),
                              headers={"Content-Type": "application/json", "Authorization": "Bearer " + FAKE_OPENAI})
        with request.urlopen(req, timeout=10) as r:
            assert r.status == 200 and json.loads(r.read()) == {"ok": True}
        px.shutdown(); up.shutdown()

        assert FAKE_AWS not in visto["body"] and "[REDACTED_AWS_ACCESS_KEY_01]" in visto["body"]
        assert "[REDACTED_PRIVATE_IP_01]" in visto["body"]
        assert visto["auth"] == "Bearer " + FAKE_OPENAI            # cabeceras intactas
        eventos = log.read_all()
        assert log.verify()[0] and eventos[-1]["event"]["hallazgos"]["total"] == 2
        assert FAKE_AWS not in json.dumps(eventos)                  # el log no guarda secretos


def test_proxy_rechaza_upstream_invalido():
    try:
        DLPProxy(("127.0.0.1", 0), "ftp://x")
        assert False
    except ValueError:
        pass
