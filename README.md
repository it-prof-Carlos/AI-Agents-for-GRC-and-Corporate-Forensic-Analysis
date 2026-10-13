# 🛡️ AEGIS — AI Governance, Risk, Forensics & Threat Profiling Platform

> **Supervisión GRC y análisis forense para agentes de Inteligencia Artificial en entornos corporativos.**
> DLP pre-envío · Human-in-the-Loop · Audit trail a prueba de manipulación · Scoring OWASP LLM Top 10 (2025) · Perfilamiento criminal aplicado a CTI.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B)
![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-green)
![ISO](https://img.shields.io/badge/ISO%2FIEC-27001%20%C2%B7%2027701%20%C2%B7%2042001-orange)
![CI](https://github.com/<tu-usuario>/aegis-grc-ai/actions/workflows/ci.yml/badge.svg)

---

##  Contexto 

La adopción acelerada de **agentes de IA en la terminal** (*Terminal Coding Agents*) multiplica la productividad,
pero introduce vectores de riesgo estructurales,  que las configuraciones por defecto no mitigan. 
AEGIS implementa, como herramienta funcional, un  **marco de supervisión forense y GRC**, en base a informes  de evaluación operativa
en análisis, efectuado  sobre infraestructuras  en Explotacion de Tierras Raras y  Unidades Operativas  en Zonas de Riesgo
donde operan  Corporaciones  Internacionales : Triple Frontera Norte de Argentina -Bolivia -Paraguay . SIGEN Report AARGENTINA 2026 
MESA REGIONAL DE LITIO Periodos 2025 -2026 

| Vector de riesgo (Informe §2.4) | Respuesta en AEGIS |
|---|---|
| Salto de fe en la cadena de suministro (`curl \| bash`) | Motor de políticas **BLOCK** + scoring + controles SR-3/SI-7 |
| Ejecución no supervisada (modo YOLO/Auto) | Motor de políticas **HITL** con permiso efectivo inferido |
| Fuga de secretos, PII y topología de red | **Motor DLP** + **proxy loopback real** con redacción sintética |
| Bucles de error / Denial-of-Wallet | Scoring de riesgo (LLM10 Unbounded Consumption) y guardrails |
| Trazabilidad forense / no repudio (Informe §3.4) | **Cadena HMAC-SHA256** verificable y exportable |

## Objetivos de Implementación 

| Componente | Estado |
|---|---|
| Motor DLP (regex + resolución de solapamientos + redacción sintética) | ✅ Implementado y testeado |
| Proxy DLP loopback `127.0.0.1` con streaming y auditoría (`python -m aegis.proxy`) | ✅ Implementado y testeado (integración) |
| Motor de políticas ALLOW / REQUIRE_HITL / BLOCK | ✅ Implementado y testeado |
| Cadena forense HMAC-SHA256 (detección de alteración, borrado intermedio y líneas corruptas) | ✅ Implementado y testeado |
| Scoring de riesgo, perfilador MITRE ATT&CK, mapeo ISO/NIST/OWASP | ✅ Implementado y testeado |
| Aprobación HITL interactiva real (hoy el dashboard **clasifica** la acción) | 🔜 Roadmap |
| Hooks eBPF, perfiles Seccomp / AppArmor (Informe §3.2) | 🔜 Roadmap (diseño en el informe) |
| Verificación automática de firmas/hashes de instaladores | 🔜 Roadmap |
| Detección AST (hoy: regex) | 🔜 Roadmap |

## Limitaciones: La cadena local es *tamper-evident*: detecta modificaciones y borrados
intermedios, pero no el truncado de los últimos registros ni el borrado total del archivo; para ello se debe anclar
`head_hash()` en un sistema externo (SIEM/WORM). El DLP por regex puede tener falsos negativos/positivos; no
sustituye a una revisión humana. El perfilador produce **hipótesis**, no atribución.

## Instalación y uso

`bash
git clone https://github.com/<tu-usuario>/aegis-grc-ai.git
cd aegis-grc-ai
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
``

### Proxy DLP (protege el contexto que tu agente envía al LLM)

``bash
python -m aegis.proxy --upstream https://api.openai.com --port 8080
# Apunte la "base URL" de su agente a http://127.0.0.1:8080
``

Escucha solo en loopback, el destino es fijo, el log registra únicamente tipos y conteos (nunca el secreto) y las
cabeceras (p. ej. `Authorization`) se reenvían sin modificar.

### Tests

`bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
``

## 🗂️ Estructura

`
aegis-grc-ai/
├── app.py                      # Dashboard Streamlit (tema azul oscuro / texto blanco)
├── aegis/
│   ├── core/
│   │   ├── dlp_scanner.py      # DLP y redacción sintética          (Informe §3.1)
│   │   ├── policy_engine.py    # Políticas ALLOW/HITL/BLOCK         (Informe §2.2, §3.5)
│   │   ├── risk_scorer.py      # Scoring 0–100 de agentes           (Informe §2.4)
│   │   ├── audit_chain.py      # Cadena forense HMAC-SHA256         (Informe §3.4)
│   │   ├── profiler.py         # Perfilador de actores (MITRE ATT&CK)
│   │   ├── controls_mapper.py  # Mapeo ISO 27001 / NIST 800-53 / OWASP LLM
│   │   └── samples.py          # Datos de demostración ficticios
│   ├── proxy.py                # Proxy DLP loopback funcional
│   └── data/                   # controls_db.json · threat_profiles.json
├── tests/                      # test_core.py · test_proxy.py
├── docs/                       # Arquitectura, verificación, texto para LinkedIn/CV
├── .streamlit/config.toml      # Tema
└── .github/workflows/ci.yml    # CI (pytest en Python 3.10 y 3.12)
``

##  Alineación normativa

* **OWASP Top 10 for LLM Applications 2025:** LLM02 Sensitive Information Disclosure, LLM03 Supply Chain,
  LLM06 Excessive Agency, LLM10 Unbounded Consumption (se incluye la equivalencia con la v1.1/2023).
* **ISO/IEC 27001:2022 (Anexo A):** A.8.12 DLP, A.8.11 enmascaramiento, A.8.2/A.8.3 acceso, A.8.9, A.8.15, A.8.28, A.5.21.
* **NIST SP 800-53 Rev. 5:** AC-3, AC-4, AC-6, AU-2, AU-9, AU-10, SC-7, SI-4, SI-7, SR-3.
* **MITRE ATT&CK** para el perfilador. Datos de ejemplo 100 % ficticios.

##  Autor

**Carlos Gallardo** — Cybersecurity Senior in AI · Senior GRC · Criminal Intelligence & Profiling
Lead Auditor ISO/IEC 27001 · 27701 · 42001


