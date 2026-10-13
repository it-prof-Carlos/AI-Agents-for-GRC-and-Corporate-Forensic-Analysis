"""Scoring de Riesgo de Agentes de IA (Informe §2.4 y §3.3).

Calcula un índice 0–100 a partir de la postura de despliegue del agente y lo
traduce a hallazgos accionables mapeados a OWASP LLM Top 10 (2025),
ISO/IEC 27001:2022 y NIST SP 800-53 Rev. 5.

Los pesos son una heurística de priorización (suman 100), no una métrica
estadística: documentan el criterio del analista y son ajustables.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

VECTORES: Dict[str, Dict] = {
    "supply_chain_sin_verificar": {
        "peso": 25, "owasp": "LLM03 Supply Chain",
        "titulo": "Salto de Fe en la Cadena de Suministro",
        "detalle": "Instalación vía curl|bash sin verificación SHA-256/PKI (Informe §2.4.1).",
        "mitigacion": "Verificar hashes y firmas antes de ejecutar instaladores; fijar versiones.",
        "iso": ["A.5.21 Seguridad en la cadena de suministro TIC", "A.8.24 Uso de criptografía",
                "A.8.25 Ciclo de vida de desarrollo seguro"],
        "nist": ["SR-3 Controles de cadena de suministro", "SI-7 Integridad de software"],
    },
    "modo_yolo": {
        "peso": 30, "owasp": "LLM06 Excessive Agency",
        "titulo": "Ejecución No Supervisada (Modo Yolo/Auto)",
        "detalle": "Supresión de la intercepción human-in-the-loop (Informe §2.4.2).",
        "mitigacion": "Forzar modo ASK; nunca autonomía total sobre WRITE/EXECUTE-SH.",
        "iso": ["A.8.2 Derechos de acceso privilegiado", "A.8.3 Restricción de acceso a la información",
                "A.8.9 Gestión de la configuración", "A.8.28 Codificación segura"],
        "nist": ["AC-6 Mínimo privilegio", "AC-3 Aplicación del acceso", "CM-7 Funcionalidad mínima"],
    },
    "sin_dlp": {
        "peso": 20, "owasp": "LLM02 Sensitive Information Disclosure",
        "titulo": "Fuga de Secretos y Topología de Red",
        "detalle": "Contexto con claves API, PII e IPs privadas hacia el LLM remoto (Informe §2.4.3).",
        "mitigacion": "Desplegar proxy DLP loopback con redacción sintética.",
        "iso": ["A.8.12 Prevención de fuga de datos", "A.8.11 Enmascaramiento de datos",
                "A.5.23 Servicios en la nube", "A.5.34 Privacidad y protección de PII"],
        "nist": ["AC-4 Control de flujo de información", "SC-7 Protección de límites"],
    },
    "sin_contexto": {
        "peso": 10, "owasp": "LLM10 Unbounded Consumption",
        "titulo": "Bucles de Error y Denial-of-Wallet",
        "detalle": "Agente sin archivos de contexto (agents.md): reintentos recursivos (Informe §2.3/§2.4.4).",
        "mitigacion": "Provisionar guardrails y skills; límites de cuota, presupuesto y timeouts de API.",
        "iso": ["A.8.6 Gestión de la capacidad", "A.8.16 Actividades de seguimiento"],
        "nist": ["SC-5 Protección contra denegación de servicio", "SI-4 Monitoreo del sistema"],
    },
    "egress_abierto": {
        "peso": 15, "owasp": "LLM02 Sensitive Information Disclosure",
        "titulo": "Telemetría / Egress no restringido",
        "detalle": "Conexiones salientes a destinos distintos del endpoint LLM contratado (Informe §3.3).",
        "mitigacion": "Zero Telemetry Enforcement: allowlist de destinos a nivel de socket/proxy.",
        "iso": ["A.8.20 Seguridad de redes", "A.8.22 Segregación de redes", "A.8.23 Filtrado web"],
        "nist": ["SC-7 Protección de límites", "AC-4 Control de flujo de información", "SI-4 Monitoreo del sistema"],
    },
}

NIVELES = [(75, "CRÍTICO"), (50, "ALTO"), (25, "MODERADO"), (0, "BAJO")]

CONTROLES_NIST = ["AC-3 Aplicación del acceso",
                  "AU-2 Registro de eventos (Event Logging)",
                  "AU-9 Protección de la información de auditoría",
                  "SI-4 Monitoreo del sistema"]


@dataclass
class Hallazgo:
    vector: str
    titulo: str
    peso: int
    owasp: str
    detalle: str
    mitigacion: str
    controles_iso: List[str] = field(default_factory=list)
    controles_nist: List[str] = field(default_factory=list)


@dataclass
class RiskReport:
    score: int
    nivel: str
    hallazgos: List[Hallazgo]
    controles_nist: List[str]


def score_agent(config: Dict[str, bool]) -> RiskReport:
    """`config`: True = riesgo presente (mala postura). Claves = vectores."""
    score, hallazgos = 0, []
    for key, vec in VECTORES.items():
        if config.get(key, False):
            score += vec["peso"]
            hallazgos.append(Hallazgo(
                vector=key, titulo=vec["titulo"], peso=vec["peso"], owasp=vec["owasp"],
                detalle=vec["detalle"], mitigacion=vec["mitigacion"],
                controles_iso=list(vec["iso"]), controles_nist=list(vec["nist"])))
    nivel = next(n for umbral, n in NIVELES if score >= umbral)
    hallazgos.sort(key=lambda h: -h.peso)
    return RiskReport(score=score, nivel=nivel, hallazgos=hallazgos,
                      controles_nist=CONTROLES_NIST.copy())
