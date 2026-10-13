"""Mapeador de Controles GRC — ISO/IEC 27001:2022, NIST SP 800-53 Rev. 5 y
OWASP Top 10 for LLM Applications (edición 2025)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

_DATA = Path(__file__).resolve().parent.parent / "data" / "controls_db.json"


def load_controls() -> Dict:
    return json.loads(_DATA.read_text(encoding="utf-8"))


def riesgos_owasp() -> List[str]:
    """Etiquetas 'LLM02 Sensitive Information Disclosure' para selectores."""
    return [f'{o["id"]} {o["nombre"]}' for o in load_controls()["owasp_llm"]]


def controles_por_riesgo(riesgo_owasp: str) -> Dict:
    """Controles ISO/NIST/OWASP para un riesgo tipo 'LLM02 ...' (edición 2025)."""
    db = load_controls()
    code = riesgo_owasp.split()[0].split(":")[0].upper()
    owasp = next((o for o in db["owasp_llm"] if o["id"] == code), None)
    return {
        "riesgo": riesgo_owasp,
        "descripcion_owasp": owasp["descripcion"] if owasp else "N/D",
        "id_2023": owasp.get("id_2023", "—") if owasp else "—",
        "iso_27001": [c["control"] for c in db["iso_27001"] if code in c.get("cubre", [])],
        "nist_800_53": [c["control"] for c in db["nist_800_53"] if code in c.get("cubre", [])],
        "mitigaciones": owasp["mitigaciones"] if owasp else [],
    }
