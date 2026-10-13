"""Proxy DLP loopback — implementación funcional del Informe §3.1.

El agente apunta su "base URL" a http://127.0.0.1:8080; el proxy inspecciona
el cuerpo de cada petición, redacta secretos/PII/IPs privadas con tokens
sintéticos, registra la interacción en la cadena forense y reenvía al
endpoint LLM configurado (HTTPS). Las respuestas se transmiten en streaming.

Uso:
    python -m aegis.proxy --upstream https://api.openai.com --port 8080

Seguridad:
  * Escucha solo en 127.0.0.1 (salvo --allow-remote explícito).
  * El destino es fijo (--upstream): no hay SSRF por cabeceras ni rutas.
  * El log NUNCA guarda valores de secretos, solo tipos y conteos.
  * Las cabeceras (p. ej. Authorization) se reenvían sin modificar: el
    proxy protege el CONTEXTO enviado al LLM, no oculta tu propia API key.
Alcance: es el modo "proxy" del Informe; los hooks eBPF/seccomp quedan en el
roadmap (ver README).
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlsplit

from aegis.core.audit_chain import ImmutableAuditLog # type: ignore
from aegis.core.dlp_scanner import DLPScanner, Finding # type: ignore

MAX_BODY = 10 * 1024 * 1024
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
        "trailers", "transfer-encoding", "upgrade", "host", "content-length", "accept-encoding"}


class DLPProxy(ThreadingHTTPServer):
    def __init__(self, addr: Tuple[str, int], upstream: str,
                 log: Optional[ImmutableAuditLog] = None, timeout: int = 120):
        parts = urlsplit(upstream)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("--upstream debe ser una URL http(s) válida")
        self.upstream = upstream.rstrip("/")
        self.upstream_host = parts.netloc
        self.scanner = DLPScanner()
        self.log = log
        self.timeout = timeout
        super().__init__(addr, _Handler)

    # ------------------------------------------------------ sanitización
    def _walk(self, obj: Any, cont: Dict[str, int], hall: List[Finding]) -> Any:
        if isinstance(obj, str):
            hall.extend(self.scanner.scan(obj))
            return self.scanner.redact(obj, cont)
        if isinstance(obj, list):
            return [self._walk(x, cont, hall) for x in obj]
        if isinstance(obj, dict):
            return {k: self._walk(v, cont, hall) for k, v in obj.items()}
        return obj

    def sanitize(self, body: bytes, content_type: str) -> Tuple[bytes, Dict[str, int]]:
        cont: Dict[str, int] = {}
        hall: List[Finding] = []
        if "json" in content_type.lower():
            try:
                limpio = self._walk(json.loads(body.decode("utf-8")), cont, hall)
                return json.dumps(limpio, ensure_ascii=False).encode("utf-8"), self.scanner.resumen(hall)
            except (ValueError, UnicodeDecodeError):
                cont, hall = {}, []
        texto = body.decode("utf-8", errors="replace")
        hall.extend(self.scanner.scan(texto))
        return self.scanner.redact(texto, cont).encode("utf-8"), self.scanner.resumen(hall)


class _Handler(BaseHTTPRequestHandler):
    server_version = "AEGIS-DLP-Proxy/1.0"
    protocol_version = "HTTP/1.0"       # respuesta delimitada por cierre: streaming simple

    def log_message(self, fmt, *args):  # silencioso: el rastro vive en la cadena forense
        pass

    def _forward(self) -> None:
        srv: DLPProxy = self.server  # type: ignore[assignment]
        try:
            largo = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.send_error(400, "Content-Length inválido")
            return
        if largo > MAX_BODY:
            self.send_error(413, "Cuerpo demasiado grande")
            return
        body = self.rfile.read(largo) if largo else b""
        resumen = {"total": 0}
        if body:
            body, resumen = srv.sanitize(body, self.headers.get("Content-Type", ""))

        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
        req = urlrequest.Request(srv.upstream + self.path, data=body or None,
                                 headers=headers, method=self.command)
        try:
            resp = urlrequest.urlopen(req, timeout=srv.timeout)
        except urlerror.HTTPError as e:         # 4xx/5xx del upstream: se propagan tal cual
            resp = e
        except Exception:
            self._audit(resumen, "upstream_error")
            self.send_error(502, "Error al contactar el endpoint LLM")
            return

        self._audit(resumen, "reenviado")
        self.send_response(getattr(resp, "status", None) or resp.code)
        for k, v in resp.headers.items():
            if k.lower() not in _HOP:
                self.send_header(k, v)
        self.end_headers()
        leer = getattr(resp, "read1", resp.read)
        try:
            while True:
                trozo = leer(8192)
                if not trozo:
                    break
                self.wfile.write(trozo)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            resp.close()

    def _audit(self, resumen: Dict[str, int], estado: str) -> None:
        srv: DLPProxy = self.server  # type: ignore[assignment]
        if srv.log:
            srv.log.append({"modulo": "PROXY_DLP", "metodo": self.command, "ruta": self.path.split("?")[0],
                            "destino": srv.upstream_host, "hallazgos": resumen,
                            "accion": "redaccion_pre_envio", "estado": estado})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _forward


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Proxy DLP loopback de AEGIS (Informe §3.1)")
    ap.add_argument("--upstream", required=True, help="Endpoint LLM, p. ej. https://api.openai.com")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--allow-remote", action="store_true", help="Permitir bind no-loopback (no recomendado)")
    ap.add_argument("--log", default="aegis/data/audit_log.jsonl", help="Ruta de la cadena forense")
    args = ap.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1") and not args.allow_remote:
        print("Rechazado: el proxy solo escucha en loopback (use --allow-remote bajo su responsabilidad).",
              file=sys.stderr)
        return 2
    srv = DLPProxy((args.host, args.port), args.upstream, ImmutableAuditLog(args.log))
    print(f"AEGIS DLP Proxy en http://{args.host}:{args.port}  →  {srv.upstream}  (Ctrl+C para salir)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
