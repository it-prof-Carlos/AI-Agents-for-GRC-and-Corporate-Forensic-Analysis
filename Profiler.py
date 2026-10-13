"""Threat Actor Profiler — perfilamiento criminal aplicado a ciberamenazas.

Traslada la metodología de perfilamiento e inteligencia criminal (análisis
conductual, modus operandi, firma del sujeto) al ciberespacio: a partir de
TTPs observados (MITRE ATT&CK) infiere hipótesis de actor, motivación y
mitigaciones prioritarias. Modelo EXPLICABLE: cada conclusión se sostiene en
evidencia ponderada.

Aviso metodológico: es una HIPÓTESIS de trabajo basada en solapamiento de
TTPs, no una atribución. La atribución exige corroborar con infraestructura,
malware, victimología e inteligencia adicional.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

_DATA = Path(__file__).resolve().parent.parent / "data" / "threat_profiles.json"


@dataclass
class ProfileMatch:
    perfil: str
    motivacion: str
    score: int                       # 0–100
    ttps_coincidentes: List[str]
    confianza: str                   # ALTA / MEDIA / BAJA
    mitigaciones: List[str]
    indicadores: List[str] = field(default_factory=list)   # indicadores conductuales


def _cargar() -> Dict:
    return json.loads(_DATA.read_text(encoding="utf-8"))


def ttp_catalogo() -> Dict[str, str]:
    """Mapa {ID técnica: nombre} para mostrar en la interfaz."""
    return _cargar()["ttps_catalogo"]


def profile_incident(observed_ttps: List[str]) -> List[ProfileMatch]:
    """Empareja TTPs observados contra perfiles conocidos (ordenados por score)."""
    db = _cargar()
    obs = {t.strip().upper() for t in observed_ttps if t and t.strip()}
    resultados: List[ProfileMatch] = []

    for perfil in db["perfiles"]:
        ttps_perfil = {t.upper() for t in perfil["ttps"]}
        coincidencias = sorted(obs & ttps_perfil)
        if not coincidencias:
            continue
        cobertura = len(coincidencias) / max(len(ttps_perfil), 1)   # % del perfil explicado
        densidad = len(coincidencias) / max(len(obs), 1)            # % de la evidencia explicada
        score = min(round(100 * (0.6 * cobertura + 0.4 * densidad)), 100)
        confianza = "ALTA" if score >= 60 else ("MEDIA" if score >= 35 else "BAJA")
        resultados.append(ProfileMatch(
            perfil=perfil["nombre"], motivacion=perfil["motivacion"], score=score,
            ttps_coincidentes=coincidencias, confianza=confianza,
            mitigaciones=list(perfil["mitigaciones"]),
            indicadores=[i.strip() for i in perfil.get("indicadores_conductuales", [])]))

    resultados.sort(key=lambda r: (-r.score, r.perfil))
    return resultados


def explicacion(match: ProfileMatch) -> str:
    ev = ", ".join(match.ttps_coincidentes[:6])
    return (f"{match.perfil} ({match.motivacion}) — score {match.score}/100, "
            f"confianza {match.confianza}. TTPs coincidentes: {ev}.")
