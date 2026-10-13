"""AEGIS DLP Engine — Sanitización Pre-Envío (Informe §3.1).

Detecta y anonimiza secretos, PII y topología de red ANTES de que un agente
de IA transmita el contexto a un endpoint LLM remoto.
Mitiga OWASP LLM Top 10 (2025): LLM02 Sensitive Information Disclosure.
Controles: ISO/IEC 27001:2022 A.8.12 (DLP) y A.8.11 (enmascaramiento);
NIST SP 800-53 AC-4, SC-7.

Diseño: los hallazgos se resuelven por *spans* (sin solapamientos, gana la
mayor severidad) y el texto se redacta en una sola pasada. El hallazgo guarda
solo una vista enmascarada del valor: nunca se persiste el secreto completo.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

_O = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"   # octeto IPv4 válido

PATTERNS: Dict[str, str] = {
    "PRIVATE_KEY":    r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----",
    "AWS_ACCESS_KEY": r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
    "OPENAI_API_KEY": r"\bsk-[A-Za-z0-9_-]{20,}\b",
    "GITHUB_TOKEN":   r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b",
    "GOOGLE_API_KEY": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "SLACK_TOKEN":    r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    "JWT_TOKEN":      r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    "PASSWORD_HASH":  r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}",
    # Asignaciones tipo  API_KEY="valor"  — el span redactado es solo el valor
    "GENERIC_SECRET": r"(?i)\b[\w-]*(?:api[_-]?key|secret|token|passw(?:or)?d)[\w-]*\s*[:=]\s*['\"](?P<valor>[A-Za-z0-9_\-./+=]{8,})['\"]",
    "PRIVATE_IP":     rf"\b(?:10\.{_O}\.{_O}\.{_O}|172\.(?:1[6-9]|2\d|3[01])\.{_O}\.{_O}|192\.168\.{_O}\.{_O})\b",
    "EMAIL_PII":      r"\b[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b",
}

SEVERITY: Dict[str, str] = {
    "PRIVATE_KEY": "CRÍTICA", "AWS_ACCESS_KEY": "CRÍTICA", "OPENAI_API_KEY": "CRÍTICA",
    "GITHUB_TOKEN": "CRÍTICA", "GOOGLE_API_KEY": "CRÍTICA", "SLACK_TOKEN": "CRÍTICA",
    "GENERIC_SECRET": "ALTA", "JWT_TOKEN": "ALTA", "PASSWORD_HASH": "ALTA",
    "EMAIL_PII": "MEDIA", "PRIVATE_IP": "MEDIA",
}

SEV_ORDER = {"CRÍTICA": 3, "ALTA": 2, "MEDIA": 1, "BAJA": 0}

RECOMENDACIONES: Dict[str, str] = {
    "PRIVATE_KEY": "Clave privada expuesta: revocar el par de claves y reemitir certificados/accesos.",
    "AWS_ACCESS_KEY": "Rotar la clave inmediatamente (AWS IAM). Revocar sesiones activas.",
    "OPENAI_API_KEY": "Revocar y regenerar la clave en el panel del proveedor LLM.",
    "GITHUB_TOKEN": "Revocar el token (GitHub Settings > Developer Settings).",
    "GOOGLE_API_KEY": "Restringir/rotar la clave en Google Cloud Console.",
    "SLACK_TOKEN": "Revocar el token desde la administración de la app de Slack.",
    "GENERIC_SECRET": "Mover el secreto a un gestor (Vault/AWS Secrets Manager) y rotarlo.",
    "JWT_TOKEN": "El token expone identidad/sesión: invalidar en el emisor y rotar el secreto de firma.",
    "PASSWORD_HASH": "El hash permite ataques offline: forzar cambio de contraseña del usuario.",
    "EMAIL_PII": "Dato PII: aplicar enmascaramiento conforme a política de privacidad (ISO/IEC 27701).",
    "PRIVATE_IP": "Topología interna expuesta: anonimizar antes del envío al LLM (LLM02).",
}


def _mask(valor: str) -> str:
    """Vista enmascarada para mostrar/registrar sin exponer el secreto."""
    v = valor.replace("\n", " ")
    return f"{v[:4]}…{v[-4:]}" if len(v) > 12 else f"{v[:2]}***"


@dataclass
class Finding:
    tipo: str
    severidad: str
    coincidencia: str      # valor ENMASCARADO
    inicio: int
    fin: int
    recomendacion: str

    def to_dict(self) -> Dict:
        return asdict(self)


class DLPScanner:
    """Escáner DLP con redacción sintética (tokens no identificables)."""

    def __init__(self) -> None:
        self._compiled = {k: re.compile(v) for k, v in PATTERNS.items()}

    def _candidatos(self, text: str):
        for tipo, rx in self._compiled.items():
            grupo = "valor" if "valor" in rx.groupindex else 0
            for m in rx.finditer(text):
                yield tipo, m.start(grupo), m.end(grupo)

    def scan(self, text: Optional[str]) -> List[Finding]:
        """Hallazgos sin solapamientos, ordenados por posición."""
        text = text or ""
        cands = sorted(self._candidatos(text),
                       key=lambda c: (-SEV_ORDER[SEVERITY[c[0]]], -(c[2] - c[1]), c[1]))
        aceptados = []
        for tipo, a, b in cands:
            if all(b <= x or a >= y for _, x, y in aceptados):
                aceptados.append((tipo, a, b))
        aceptados.sort(key=lambda c: c[1])
        return [Finding(t, SEVERITY[t], _mask(text[a:b]), a, b, RECOMENDACIONES[t])
                for t, a, b in aceptados]

    def redact(self, text: Optional[str], contadores: Optional[Dict[str, int]] = None) -> str:
        """Reemplaza cada hallazgo por [REDACTED_<TIPO>_NN] en una sola pasada.

        `contadores` permite mantener la numeración entre varios fragmentos
        (p. ej. todos los strings de un JSON).
        """
        text = text or ""
        cont = contadores if contadores is not None else {}
        partes, cursor = [], 0
        for h in self.scan(text):
            cont[h.tipo] = cont.get(h.tipo, 0) + 1
            partes.append(text[cursor:h.inicio])
            partes.append(f"[REDACTED_{h.tipo}_{cont[h.tipo]:02d}]")
            cursor = h.fin
        partes.append(text[cursor:])
        return "".join(partes)

    @staticmethod
    def resumen(hallazgos: List[Finding]) -> Dict[str, int]:
        res = {"total": len(hallazgos), "CRÍTICA": 0, "ALTA": 0, "MEDIA": 0, "BAJA": 0}
        for h in hallazgos:
            res[h.severidad] = res.get(h.severidad, 0) + 1
        return res
