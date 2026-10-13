"""Motor de Políticas con Human-in-the-Loop (Informe §2.2 y §3.5).

Clasifica acciones propuestas por un agente de IA en ALLOW / REQUIRE_HITL /
BLOCK según modo de ejecución, permiso, ámbito del sandbox y contenido real
del comando. Mitiga OWASP LLM06:2025 (Excessive Agency) y LLM03:2025 (Supply
Chain). Controles: ISO/IEC 27001:2022 A.8.2, A.8.3, A.8.9, A.8.28;
NIST SP 800-53 AC-3, AC-6, AU-2.

Principios de diseño (determinista y explicable):
  * El permiso DECLARADO nunca es suficiente: se infiere el permiso efectivo
    a partir del comando y se aplica el mayor (anti-subestimación).
  * La pertenencia al sandbox se evalúa con rutas normalizadas (anti
    `..` y anti prefijos engañosos como /sandbox-evil) e incluye las rutas
    absolutas que aparezcan DENTRO del comando.
  * Sin sandbox declarado, todo se considera fuera del sandbox (fail-closed).
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------- modelo
@dataclass
class AgentAction:
    modo: str                 # "ASK" | "YOLO"
    permiso: str              # "READ" | "WRITE" | "EXECUTE-SH"
    comando: str
    ruta_objetivo: str
    sandbox_path: str


@dataclass
class Decision:
    decision: str             # ALLOW | REQUIRE_HITL | BLOCK
    razon: str
    controles: List[str] = field(default_factory=list)
    permiso_efectivo: str = ""
    notas: List[str] = field(default_factory=list)

    @property
    def es_segura(self) -> bool:
        return self.decision == "ALLOW"


# ------------------------------------------------------------ constantes
_RANK = {"READ": 0, "WRITE": 1, "EXECUTE-SH": 2}

BASE_CONTROLS = ["ISO/IEC 27001:2022 A.8.28", "NIST SP 800-53 AC-3"]
C_LLM06 = "OWASP LLM06:2025 Excessive Agency"
C_LLM03 = "OWASP LLM03:2025 Supply Chain"
C_LLM02 = "OWASP LLM02:2025 Sensitive Information Disclosure"

# Denegación categórica (BLOCK siempre)
DENY_PATTERNS = [
    (r"\brm\s+(?:--?[A-Za-z-]+\s+)+(?:/\*?|~/?|\$HOME/?)(?=\s|$)",
     "Borrado masivo recursivo de raíz o HOME fuera de cualquier sandbox."),
    (r"\b(?:curl|wget)\b[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b",
     "Instalación curl|bash sin verificación de firma (Supply Chain Blindspot, Informe §2.4.1)."),
    (r"\b(?:ba)?sh\s+<\(\s*(?:curl|wget)\b|\beval\s+\$\(\s*(?:curl|wget)\b",
     "Ejecución directa de script remoto sin verificación de integridad."),
    (r"\bmkfs(?:\.\w+)?\b", "Formateo de disco: destrucción total de evidencia y sistema."),
    (r"\bdd\b[^\n]*\b(?:if|of)=", "Escritura de bajo nivel sobre dispositivo: destrucción de evidencia forense."),
    (r"\bchmod\s+(?:-R\s+)?0?777\s+/(?:\s|$)", "Exposición total de permisos sobre la raíz del sistema."),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Fork bomb: denegación de servicio local."),
    (r">\s*/dev/(?:sd|nvme|hd)", "Escritura directa sobre dispositivo de bloques."),
]

# Operaciones destructivas/irreversibles → exigen HITL aunque el permiso declarado sea READ
RISKY_PATTERNS = [
    (r"\bgit\s+push\b[^\n]*(?:--force\b|--force-with-lease|\s-f\b|--delete\b|\s:\S)",
     "Git push forzado/borrado de rama remota (riesgo de pérdida de historial)."),
    (r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f|branch\s+-D)\b",
     "Operación Git destructiva sobre el repositorio local."),
    (r"\bsudo\b|\bsu\s+-", "Escalada de privilegios."),
    (r"\b(?:terraform\s+destroy|kubectl\s+delete|docker\s+system\s+prune|"
     r"aws\s+\S+\s+(?:delete|rm|terminate)\S*|gcloud\s+\S+[^\n]*\bdelete\b)",
     "Operación destructiva sobre infraestructura local/nube."),
    (r"\bcurl\b[^\n]*(?:\s-d\b|\s--data|\s-F\b|\s-T\b|--upload-file)",
     "Subida de datos hacia un destino externo (posible exfiltración)."),
    (r"\bdrop\s+(?:table|database)\b", "Sentencia SQL destructiva."),
]

_EXEC_HINT = re.compile(
    r"&&|\|\||;|\||\$\(|`|\bsudo\b|\b(?:bash|sh|zsh|python3?|node|perl|ruby|pwsh|powershell)\b|"
    r"\b(?:curl|wget|nc|ncat|ssh|scp)\b|\bgit\s+push\b|"
    r"\b(?:docker|kubectl|terraform|aws|gcloud|npm|pip3?|make)\b", re.I)
_WRITE_HINT = re.compile(
    r"\b(?:rm|mv|cp|touch|mkdir|rmdir|tee|truncate|chmod|chown|ln)\b|\bsed\s+-i\b|"
    r"\bgit\s+(?:add|commit|checkout|merge|rebase|reset|clean|branch|stash)\b|>>?")

_SENSITIVE_PATH = re.compile(
    r"(?:^|/)(?:\.ssh|\.aws|\.gnupg|\.kube|\.netrc|id_rsa|id_ed25519|credentials|shadow|passwd|"
    r"\.env(?!\.(?:example|sample|template))(?:\.[\w-]+)?|secrets?\.(?:json|ya?ml))(?:/|$)", re.I)

_RUTAS_EN_COMANDO = re.compile(r"(?<![\w.:/~-])(~?/[^\s;|&'\"<>()]*)")
_RUTAS_PERMITIDAS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin"}


class PolicyEngine:
    """Evaluador determinista de acciones de agentes de IA."""

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _normalizar(path: Optional[str], base: str = "") -> str:
        p = (path or "").strip().replace("\\", "/")
        if not p:
            return ""
        if base and not p.startswith(("/", "~")):
            p = posixpath.join(base, p)
        return posixpath.normpath(p)

    def _fuera(self, ruta: str, sandbox: str) -> bool:
        if ruta in _RUTAS_PERMITIDAS:
            return False
        t = self._normalizar(ruta, base=sandbox)
        if not t:
            return False
        return not (t == sandbox or t.startswith(sandbox + "/"))

    def _fuera_de_sandbox(self, accion: AgentAction) -> bool:
        s = self._normalizar(accion.sandbox_path)
        if not s or s == "/":                 # fail-closed: sandbox inexistente o inútil
            return True
        rutas = [accion.ruta_objetivo] + _RUTAS_EN_COMANDO.findall(accion.comando or "")
        return any(r and self._fuera(r, s) for r in rutas)

    @staticmethod
    def _match(patrones, comando: str) -> Optional[str]:
        for pat, motivo in patrones:
            if re.search(pat, comando or "", re.IGNORECASE):
                return motivo
        return None

    @staticmethod
    def _permiso_efectivo(declarado: str, comando: str) -> str:
        inferido = "READ"
        if _EXEC_HINT.search(comando or ""):
            inferido = "EXECUTE-SH"
        elif _WRITE_HINT.search(comando or ""):
            inferido = "WRITE"
        declarado = declarado if declarado in _RANK else "READ"
        return inferido if _RANK[inferido] > _RANK[declarado] else declarado

    # --------------------------------------------------------- evaluación
    def evaluate(self, accion: AgentAction) -> Decision:
        modo = (accion.modo or "ASK").upper()
        declarado = (accion.permiso or "READ").upper()
        comando = accion.comando or ""
        efectivo = self._permiso_efectivo(declarado, comando)
        notas: List[str] = []
        if efectivo != declarado:
            notas.append(f"Permiso declarado {declarado} elevado a {efectivo} por el contenido del comando.")

        def dec(d, razon, ctrl):
            return Decision(d, razon, ctrl, permiso_efectivo=efectivo, notas=notas)

        # 1) Patrones de denegación categórica
        motivo = self._match(DENY_PATTERNS, comando)
        if motivo:
            return dec("BLOCK", f"[DENEGADO POR PATRÓN] {motivo}",
                       BASE_CONTROLS + [C_LLM03 if "Supply" in motivo or "remoto" in motivo else C_LLM06])

        fuera = self._fuera_de_sandbox(accion)

        # 2) Operaciones destructivas conocidas
        riesgo = self._match(RISKY_PATTERNS, comando)
        if riesgo:
            if modo == "YOLO":
                return dec("BLOCK", f"[LLM06 EXCESSIVE AGENCY] {riesgo} En modo YOLO no hay intercepción humana.",
                           BASE_CONTROLS + [C_LLM06])
            return dec("REQUIRE_HITL", f"{riesgo} Suspender hilo hasta aprobación humana firmada.",
                       BASE_CONTROLS + [C_LLM06, "NIST SP 800-53 AU-2"])

        # 3) Modo YOLO = autonomía ilimitada → Excessive Agency
        if modo == "YOLO" and (efectivo in ("WRITE", "EXECUTE-SH") or fuera):
            return dec("BLOCK",
                       "[LLM06 EXCESSIVE AGENCY] Modo sin intercepción humana sobre acción de alteración "
                       "de estado o fuera del sandbox. Exige modo ASK y supervisión HITL.",
                       BASE_CONTROLS + [C_LLM06])

        # 4) Ejecución de shell siempre requiere aprobación humana
        if efectivo == "EXECUTE-SH":
            return dec("REQUIRE_HITL",
                       "Comando de ejecución arbitraria: suspender hilo hasta aprobación humana firmada (HITL).",
                       BASE_CONTROLS + ["NIST SP 800-53 AU-2", "ISO/IEC 27001:2022 A.8.2"])

        # 5) Escritura fuera del sandbox requiere aprobación
        if efectivo == "WRITE" and fuera:
            return dec("REQUIRE_HITL",
                       f"Escritura fuera del sandbox asignado ({accion.ruta_objetivo or comando} ⊄ "
                       f"{accion.sandbox_path or 'sin sandbox'}). Aprobación humana obligatoria.",
                       BASE_CONTROLS + ["ISO/IEC 27001:2022 A.8.9"])

        # 6) Escritura dentro del sandbox: permitida con registro forense
        if efectivo == "WRITE":
            return dec("ALLOW", "Escritura confinada al sandbox. Permitida; registrar en audit trail.",
                       BASE_CONTROLS + ["NIST SP 800-53 AU-2"])

        # 7) Lectura de rutas sensibles (credenciales, claves, .env)
        objetivos = [accion.ruta_objetivo] + _RUTAS_EN_COMANDO.findall(comando)
        if any(o and _SENSITIVE_PATH.search(o.replace("\\", "/")) for o in objetivos):
            if modo == "YOLO":
                return dec("BLOCK", "[LLM02] Lectura de credenciales/claves sin supervisión humana.",
                           BASE_CONTROLS + [C_LLM02, C_LLM06])
            return dec("REQUIRE_HITL", "Lectura de ruta sensible (credenciales, claves, .env): el contenido "
                       "viajaría al LLM remoto. Aprobación humana + DLP obligatorios.",
                       BASE_CONTROLS + [C_LLM02, "ISO/IEC 27001:2022 A.8.3"])

        # 8) Lectura: permitida, con paso obligatorio por DLP antes del envío al LLM
        if fuera:
            notas.append("Lectura fuera del sandbox: queda registrada en el audit trail.")
        return dec("ALLOW", "Lectura permitida. Requiere saneamiento DLP (LLM02) antes de transmitir "
                   "contexto al endpoint remoto.", [C_LLM02, "ISO/IEC 27001:2022 A.8.12"])
