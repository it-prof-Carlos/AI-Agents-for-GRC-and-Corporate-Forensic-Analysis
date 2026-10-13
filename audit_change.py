"""Bitácora forense a prueba de manipulación — cadena HMAC-SHA256.

Implementa el requerimiento del Informe §3.4: cada evento se serializa en
JSON canónico, se encadena con el hash del evento anterior y se firma con
HMAC-SHA256. Cualquier alteración, borrado intermedio o inserción rompe la
verificación (tamper-evident). Aporta trazabilidad e integridad (NIST AU-9,
AU-10; ISO/IEC 27001:2022 A.8.15).

Limitación conocida (documentada en el README): una cadena local detecta
modificaciones y borrados intermedios, pero NO el truncado de los últimos
registros ni el borrado total del archivo. Para eso se debe anclar
`head_hash()` en un sistema externo (WORM, SIEM, repositorio firmado).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

GENESIS_HASH = "0" * 64
DEFAULT_KEY = "AEGIS-DEV-KEY-CAMBIAR-EN-PRODUCCION"
_CAMPOS_FIRMADOS = ("event_id", "timestamp", "event", "previous_hash")
_CAMPOS_REQUERIDOS = _CAMPOS_FIRMADOS + ("hash",)
_LOCK = threading.RLock()


class ImmutableAuditLog:
    """Registro forense append-only con encadenamiento criptográfico."""

    def __init__(self, path: str | Path, hmac_key: Optional[str] = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        clave = hmac_key or os.environ.get("AEGIS_HMAC_KEY") or DEFAULT_KEY
        self.key = clave.encode("utf-8")
        self.usa_clave_por_defecto = clave == DEFAULT_KEY

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _canonical(obj: Dict) -> str:
        return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    def _sign(self, payload: str) -> str:
        return hmac.new(self.key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def _lines(self) -> List[str]:
        if not self.path.exists():
            return []
        return [l for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]

    @staticmethod
    def _parse(line: str) -> Optional[Dict]:
        try:
            rec = json.loads(line)
        except ValueError:
            return None
        if not isinstance(rec, dict) or any(k not in rec for k in _CAMPOS_REQUERIDOS):
            return None
        return rec

    # --------------------------------------------------------------- API
    def head_hash(self) -> str:
        """Hash del último registro válido (ancla externa recomendada)."""
        for line in reversed(self._lines()):
            rec = self._parse(line)
            if rec:
                return str(rec["hash"])
        return GENESIS_HASH

    def append(self, event: Dict) -> Dict:
        """Registra un evento y devuelve el registro completo firmado."""
        # Normaliza a tipos JSON puros para que la re-verificación sea exacta.
        evento = json.loads(json.dumps(event, ensure_ascii=False, default=str))
        with _LOCK:
            record = {
                "event_id": f"evt_{uuid.uuid4().hex[:16]}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": evento,
                "previous_hash": self.head_hash(),
            }
            record["hash"] = self._sign(self._canonical(record))
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    def read_all(self) -> List[Dict]:
        return [r for r in (self._parse(l) for l in self._lines()) if r]

    def verify(self) -> Tuple[bool, List[str]]:
        """Re-verifica la cadena completa. Devuelve (válida, ids alterados)."""
        prev_hash = GENESIS_HASH
        alterados: List[str] = []
        for n, line in enumerate(self._lines(), start=1):
            rec = self._parse(line)
            if rec is None:                      # línea corrupta / malformada
                alterados.append(f"linea_{n}")
                continue
            esperado = self._sign(self._canonical({k: rec[k] for k in _CAMPOS_FIRMADOS}))
            ok_hash = hmac.compare_digest(esperado, str(rec["hash"]))
            ok_cadena = rec["previous_hash"] == prev_hash
            if not (ok_hash and ok_cadena):
                alterados.append(str(rec["event_id"]))
            prev_hash = str(rec["hash"])
        return (len(alterados) == 0, alterados)

    # ------------------------------------------------ utilidades de demo
    def simulate_tamper(self) -> bool:
        """Altera el último registro (solo para demostrar la detección)."""
        with _LOCK:
            lines = self._lines()
            if not lines:
                return False
            rec = self._parse(lines[-1])
            if rec is None:
                return False
            rec["event"]["_manipulado"] = True
            lines[-1] = json.dumps(rec, ensure_ascii=False)
            self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True

    def reset(self) -> None:
        with _LOCK:
            if self.path.exists():
                self.path.unlink()

    def export_text(self) -> str:
        lineas = self._lines()
        return "\n".join(lineas) + ("\n" if lineas else "")
