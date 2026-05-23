# SOC Automatizado en Cloud — TFG Ciberseguridad

> Implementación de un Security Operations Center (SOC) funcional y automatizado sobre infraestructura Azure, integrando herramientas open source de nivel enterprise.

Wazuh|
TheHive|
MISP|
Shuffle|
Velociraptor|
Suricata|
MITRE ATT&CK
---

## Descripción

Este proyecto implementa un SOC completo orientado a PYMEs, con capacidades de:

- **Detección** automática de amenazas mediante Wazuh + Suricata
- **Enriquecimiento** multi-fuente (MISP, VirusTotal, AbuseIPDB)
- **Scoring dinámico** ponderado por fuente, criticidad de activo y horario
- **Automatización** de respuesta (SOAR) con Shuffle
- **Gestión de casos** en TheHive con observables forenses
- **DFIR automatizado** con Velociraptor post-incident
- **CTI cerrado** con retroalimentación automática a MISP
- **Validación empírica** con Atomic Red Team sobre técnicas MITRE ATT&CK

---

## Arquitectura

```
                    

Flujo IPs (alertas externas):
Wazuh → Shuffle → [MISP + VT + AbuseIPDB] → Scoring Engine → TheHive → Velociraptor

Flujo Interno (eventos sistema):
Wazuh → Shuffle → TheHive ALERT → TheHive CASE → Velociraptor → Observable
```

---

## Stack Tecnológico

| Componente | Herramienta | Versión | Función |
|---|---|---|---|
| SIEM/EDR | Wazuh | v4.14.5 | Detección, correlación, FIM, SCA |
| IDS | Suricata | 6.0.4 | Detección tráfico red (ET/open 50k reglas) |
| Threat Intel | MISP | Latest | CTI local + feeds públicos |
| Threat Intel | VirusTotal | API v3 | Enriquecimiento IPs y hashes |
| Threat Intel | AbuseIPDB | API v2 | Reputación IPs |
| SOAR | Shuffle | v2.1.3 | Automatización workflows |
| Case Management | TheHive 5 | 5.x | Gestión incidentes y observables |
| DFIR | Velociraptor | 0.76.3 | Forensics automático post-caso |
| Notificaciones | Gmail | SMTP | Alertas al analista |

---

## Scoring Engine

Sistema de puntuación ponderada para priorizar alertas:

| Fuente | Condición | Puntos |
|---|---|---|
| MISP | Hit en feeds locales/públicos | +30 |
| VirusTotal | malicious > 0 | +20 |
| VirusTotal | malicious > 5 | +40 (acumulable) |
| AbuseIPDB | confidence > 50% | +15 |
| AbuseIPDB | confidence > 75% | +30 (acumulable) |
| Wazuh | rule.level > 12 | +10 |
| Asset | Activo crítico (vm1, vm2) | +15 |
| Horario | Fuera UTC 07:00-22:00 | +10 |
| GeoIP | País alto riesgo | +10 |

**Umbral**: Score ≥ 40 → TheHive ALERT + CASE automático

---

## Validación MITRE ATT&CK — Linux (vm5-victim)

Pruebas realizadas con **Atomic Red Team** sobre Ubuntu 22.04 (Norway East).
Pipeline completo validado: Wazuh → Shuffle → TheHive → Velociraptor.

| Técnica | Descripción | Rule ID | Level | MTTR Wazuh | MTTR Shuffle | ALERT | CASE | Velociraptor | Acciones Auto. | Resultado |
|---|---|---|---|---|---|---|---|---|---|---|
| T1110.001 | Brute Force sudo | R100001 | 10 | 0:00:03 | 0:00:17 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1003.008 | /etc/shadow dump | R100300 | 12 | 0:00:06 | 0:00:14 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1059.004 | Sudoers abuse | R100022 | 12 | 0:00:00 | 0:00:16 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1070.003 | FIM archivo crítico | R100100 | 12 | 0:00:00 | 0:00:13 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1036 | Masquerading | R100005 | 8 | 0:00:02 | 0:00:12 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1565 | FIM masivo correlación | R100204 | 13 | 0:00:25 | 0:00:15 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1486 | Ransomware simulado | R100006 | 12 | 0:00:00 | 0:00:19 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1078 | Valid accounts post-BF | R40112 | 12 | 0:00:32 | 0:01:15 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1046 | Port scan Suricata | R100008 | 8 | ~30s | — | ❌* | ❌* | ❌* | — | ✅ |
| T1071.001 | C2 HTTP | R100301 | 11 | — | — | ✅ | ✅ | ✅ | 7 | ⚠️ parcial |
| T1059.004 | Reverse shell | R100030 | 14 | — | — | — | — | — | — | ❌ gap |

> \* T1046: decisión técnica documentada — port scan aislado no genera caso TheHive (política anti-alert-fatigue)

**Tasa de detección Linux: 10/11 = 91%** | **MTTR mínimo: <1s** | **MTTR máximo: 32s**

---

## Validación MITRE ATT&CK — Windows (vm4-windows)

Pruebas realizadas con **Atomic Red Team + Sysmon (SwiftOnSecurity)** sobre Windows Server 2022.

| Técnica | Descripción | Rule ID | Level | MTTR Wazuh | MTTR Shuffle | ALERT | CASE | Velociraptor | Acciones Auto. | Resultado |
|---|---|---|---|---|---|---|---|---|---|---|
| T1136.001 | Usuario local creado | R100504 | 12 | 0:00:01 | 0:00:15 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1543.003 | Nuevo servicio Windows | R100502 | 12 | 0:00:02 | 0:02:05 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1547.001 | Modificación Run key | R100503 | 12 | 0:00:01 | 0:00:09 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1059.001 | PowerShell sospechoso | R100500 | 12 | 0:00:01 | 0:00:13 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1003.001 | Acceso LSASS | R100501 | 14 | 0:00:11 | 0:00:15 | ✅ | ✅ | ✅ | 7 | ✅ |
| T1003 | Mimikatz por nombre | R100505 | 15 | 0:00:01 | 0:00:14 | ✅ | ✅ | ✅ | 7 | ✅ |

**Tasa de detección Windows: 6/6 = 100%** | **MTTR medio: ~3s**

---

## Métricas Globales

| Métrica | Valor |
|---|---|
| Técnicas MITRE validadas (Linux) | 10/11 (91%) |
| Técnicas MITRE validadas (Windows) | 6/6 (100%) |
| MTTR mínimo | < 1 segundo |
| MTTR máximo | 32 segundos |
| MTTR medio (Linux) | ~8 segundos |
| MTTR medio (Windows) | ~3 segundos |
| Acciones automatizadas por evento | 7 (Flujo Interno) |
| Alertas reales procesadas (6 semanas) | 24.679 |
| Países atacantes identificados | 15+ |
| Tácticas MITRE cubiertas | 8 |
| Coste infraestructura estimado | ~200€/mes Azure |
| **MTTR sector (Verizon DBIR 2024)** | **194 días** |

---

## MISP CTI — 3 Capas

```
Capa 1 — Feeds públicos automáticos
  CIRCL OSINT, Feodo IP Blocklist, MalwareBazaar, URLhaus
  → 2364+ eventos importados

Capa 2 — Exportación automática VT→MISP
  Cuando VT malicious > 5, Shuffle hace POST automático a MISP
  → IoC confirmado en evento ID 2389

Capa 3 — Feedback loop TheHive→MISP
  Al cerrar caso: True Positive → añade IoC a MISP
                  False Positive → añade IP a warninglist local
```

---

## Estructura del Repositorio

```
soc-tfg/
├── README.md                    ← Este archivo
├── rules/
│   └── local_rules.xml          ← 31 reglas Wazuh custom (MITRE ATT&CK)
├── docs/
│   └── seguimientos/            ← 18 sesiones de trabajo documentadas
│       ├── Seguimiento_01.md    ← Pipeline inicial Wazuh→TheHive
│       ├── Seguimiento_02.md    ← MISP + VirusTotal integración
│       ├── ...
│       └── Seguimiento_19.md    ← Validación Windows completa + Threat Hunting
└── architecture/
    └── diagrams.md              ← Decisiones de diseño y justificaciones
```

---

## Reglas Wazuh Custom — Resumen

| Rule ID | Técnica MITRE | Descripción |
|---|---|---|
| 100001 | T1110 | Brute Force — múltiples autenticaciones fallidas |
| 100006 | T1486 | Ransomware — extensiones .encrypted/.locked/.crypto |
| 100007 | T1071 | C2 traffic — Suricata ET MALWARE/TROJAN |
| 100008 | T1046 | Port scan — Suricata ET SCAN |
| 100022 | T1548.003 | Modificación /etc/sudoers |
| 100030 | T1059.004 | Reverse shell — nc/bash /dev/tcp |
| 100100 | T1565 | FIM — cambio archivo crítico del sistema |
| 100102 | T1548 | FIM — modificación sudoers |
| 100103 | T1543 | FIM — nuevo servicio systemd |
| 100200 | T1110.003 | Correlación — password spraying (5 usuarios/60s) |
| 100203 | T1548 | Correlación — escalada privilegios repetida (3/300s) |
| 100204 | T1565 | Correlación — FIM masivo (5 archivos/120s) |
| 100300 | T1003 | Auditd — lectura /etc/shadow |
| 100301 | T1048 | Auditd — ejecución herramienta exfiltración |
| 100400 | T1562.001 | Agente Wazuh desconectado |
| 100500 | T1059.001 | Sysmon — PowerShell sospechoso (encodedcommand/IEX) |
| 100501 | T1003.001 | Sysmon — acceso a proceso LSASS |
| 100502 | T1543.003 | Sysmon — nuevo servicio Windows |
| 100503 | T1547.001 | Sysmon — modificación Run key registro |
| 100504 | T1136.001 | Sysmon — usuario local creado |
| 100505 | T1003 | Sysmon — Mimikatz por nombre de proceso |

---

## Decisiones de Diseño Clave

**Enriquecimiento paralelo vs secuencial**: MISP + VT + AbuseIPDB ejecutan simultáneamente en Shuffle, reduciendo latencia de ~15s a ~5s.

**Scoring ponderado vs condition binaria**: el motor de scoring evalúa múltiples fuentes con pesos diferentes, evitando falsos negativos por IPs nuevas sin reputación (day-zero) y falsos positivos por detecciones únicas en VT.

**No bloqueo automático**: riesgo de falso positivo inaceptable en producción. Se implementa como "block-candidate" con aprobación manual del analista.

**Anti-alert-fatigue en port scan**: reconocimiento aislado genera alerta informativa sin caso TheHive. Solo activa pipeline completo si se combina con brute force o login exitoso.

**CTI cerrado**: la retroalimentación del analista al cerrar casos mejora progresivamente la base de conocimiento local, diferenciando un SOC proactivo de uno reactivo.

---

## Autor

TFG — Grado en Ingeniería Informática / Ciberseguridad  
Año académico 2025-2026

---

> **Nota**: Este repositorio documenta el proceso completo de implementación de un SOC académico funcional. Las IPs, credenciales y configuraciones específicas han sido anonimizadas donde corresponde.
