# SOC Automatizado en Cloud — TFG

> Implementación de un Security Operations Center (SOC) funcional y automatizado sobre infraestructura Azure, integrando herramientas open source de nivel enterprise.

Wazuh | TheHive | MISP | Shuffle | Velociraptor | Suricata | MITRE ATT&CK | Dockers

---

## Descripción

Este proyecto implementa un SOC completo orientado a PYMEs, con capacidades de:

- **Detección** automática de amenazas mediante Wazuh + Suricata
- **Enriquecimiento** multi-fuente (MISP, VirusTotal, AbuseIPDB)
- **Scoring dinámico** ponderado por fuente, criticidad de activo, horario, geolocalización y correlación temporal
- **Automatización** de respuesta (SOAR) con Shuffle
- **Gestión de casos** en TheHive con observables forenses
- **DFIR automatizado** con Velociraptor post-incidente (preserve-evidence-before-containment)
- **Respuesta activa**: aislamiento automático de endpoints comprometidos vía Azure NSG ante técnicas críticas (ransomware, C2)
- **CTI cerrado** con retroalimentación automática a MISP (3 capas)
- **Validación empírica** con Atomic Red Team sobre 18 técnicas MITRE ATT&CK (Linux + Windows)

---

## Arquitectura

```
                    

Flujo IPs (alertas externas):
Wazuh → Shuffle → [MISP + VT + AbuseIPDB] → Scoring Engine → TheHive → Velociraptor

Flujo Interno (eventos sistema):
Wazuh → Shuffle → TheHive ALERT → TheHive CASE → Velociraptor → Observable
```
### Containerización

El núcleo operativo del SOC (TheHive, MISP, Shuffle, OpenSearch) se despliega
íntegramente sobre **Docker** en VM2, orquestado mediante Docker Compose:

- Aísla cada servicio en su propia red Docker bridge, evitando conflictos
  de dependencias entre TheHive (Cassandra), MISP (MariaDB/Redis) y Shuffle
  (OpenSearch/Orborus workers)
- Permite recrear el stack completo desde cero en caso de fallo o corrupción
  de estado (situación real documentada tras 2 meses de inactividad por
  agotamiento de créditos Azure, donde el contenedor de TheHive quedó en
  estado `Created` sin arrancar y los alias de OpenSearch de Shuffle
  quedaron duplicados tras el reinicio)
- Los workers efímeros de Shuffle (Docker Swarm) requirieron resolución de
  conectividad interna: comunicación vía red privada Azure (`10.0.0.5`) en
  lugar de la IP pública, y llamadas a TheHive resueltas por el gateway
  Docker bridge (`172.17.0.1`) en lugar de DNS público

**Wazuh Manager y el servidor de Velociraptor (VM1) corren nativos** como
servicios `systemd`, fuera de Docker — separación deliberada para aislar
el componente crítico de detección (SIEM) de la capa de orquestación SOAR,
y porque Wazuh no recomienda oficialmente el despliegue containerizado del
manager en producción por la complejidad de persistencia de reglas y agentes.
---


Infraestructura distribuida en tres entornos de red independientes:
- **Azure France Central**: VM1 (Wazuh Manager + Velociraptor Server + webhook de aislamiento), VM2 (stack Docker: TheHive, MISP, Shuffle)
- **Azure Norway East**: VM5 (endpoint víctima Linux, sin VNet peering con France Central)
- **Local (VirtualBox)**: VM4 (endpoint Windows Server 2022, conectividad NAT hacia IP pública de VM1)

---

## Stack Tecnológico

| Componente | Herramienta | Versión | Función |
|---|---|---|---|
| SIEM/EDR | Wazuh | v4.14.5 | Detección, correlación, FIM, SCA, Vulnerability Detection |
| IDS | Suricata | 8.0.5 | Detección tráfico red (ET/open, 50.049 firmas) |
| Threat Intel | MISP | 2.5.39 | CTI local + feeds públicos, 3 capas de retroalimentación |
| Threat Intel | VirusTotal | API v3 | Enriquecimiento IPs y hashes |
| Threat Intel | AbuseIPDB | API v2 | Reputación IPs |
| SOAR | Shuffle | 2.2.0 | Automatización workflows |
| Case Management | TheHive | 5.7 | Gestión incidentes y observables |
| DFIR | Velociraptor | 0.76.3 | Forensics automático post-caso + threat hunting proactivo |
| Sensor endpoint | Sysmon | 15.20 | Telemetría Windows (config SwiftOnSecurity) |
| Contenedores | Docker + Docker Compose | 29.5.1 | Orquestación TheHive/MISP/Shuffle en VM2 |

> **Nota de diseño**: se evaluó Gmail como canal de notificación al analista y se descartó por tratarse de un canal inseguro para alertas SOC. En un entorno real se recomienda Slack/Teams interno o un canal cifrado equivalente.

---

## Scoring Engine

Sistema de puntuación aditiva ponderada (patrón NCISS/CISA) para priorizar alertas del Flujo IPs:

| Fuente | Condición | Puntos |
|---|---|---|
| MISP | Hit en feeds locales/públicos | +30 |
| VirusTotal | malicious > 0 | +20 |
| VirusTotal | malicious > 5 | +40 (acumulable) |
| AbuseIPDB | confidence > 50% | +15 |
| AbuseIPDB | confidence > 75% | +30 (acumulable) |
| GeoIP | País de origen de alto riesgo | +10 |
| Wazuh | rule.level > 12 | +10 |
| Correlación | Regla de correlación temporal disparada | +20 |
| Asset | Activo crítico (vm1-wazuh, vm2-soc) | +15 |
| Horario | Fuera de ventana laboral UTC 07:00–22:00 | +10 |

**Clasificación** (tope normalizado a 100 puntos sobre un máximo teórico de 165):
- Score < 40 → **Medium**: no genera caso, se añade a watchlist MISP adaptativa
- 40 ≤ Score < 70 → **High**: ALERT + CASE automático en TheHive
- Score ≥ 70 → **Critical**: ALERT + CASE + activa aislamiento automático si la regla es crítica

---

## Validación MITRE ATT&CK — Linux (vm5-victim)

Pruebas con **Atomic Red Team** sobre Ubuntu 22.04 (Norway East). Pipeline validado: Wazuh → Shuffle → TheHive → Velociraptor.

| Técnica | Rule ID | Level | MTTD | MTTR pipeline | TheHive | Resultado |
|---|---|---|---|---|---|---|
| T1110.001 | R100001 | 10 | 3s | 17s | ✅ | ✅ |
| T1003.008 | R100300 | 12 | 6s | 14s | ✅ | ✅ |
| T1548.003 | R100022 | 12 | 0s | 16s | ✅ | ✅ |
| T1070.003 | R100100 | 12 | 0s | 13s | ✅ | ✅ |
| T1046 | R100008 | 10 | 5s | 11s | ✅ | ✅ |
| T1565 | R100204 | 13 | 25s | 15s | ✅ | ✅ |
| T1486 | R100006 | 12 | 0s | 19s | ✅ | ✅ |
| T1572 | R100311 | 10 | 0s | 1m16s | ✅ | ✅ |
| T1021.004 | R100002 | 10 | 23s | 56s | ✅ | ✅ |
| T1071 | R100007 | 10 | 0s | 13s | ✅ | ✅ |
| T1078 | R40112 | 12 | 32s | 1m15s | ✅ | ✅ |

**Tasa de detección Linux: 12/12 = 100%** | MTTD min: 0s | MTTD max: 32s | MTTR medio pipeline: ~8s (excluyendo correlación temporal, ~2s)

---

## Validación MITRE ATT&CK — Windows (vm4-windows)

Pruebas con **Atomic Red Team + Sysmon (SwiftOnSecurity)** sobre Windows Server 2022.

| Técnica | Rule ID | Level | MTTD | MTTR pipeline | TheHive | Resultado |
|---|---|---|---|---|---|---|
| T1136.001 | R100504 | 12 | 1s | 15s | ✅ | ✅ |
| T1543.003 | R100502 | 12 | 2s | 2m5s | ✅ | ✅ |
| T1547.001 | R100503 | 12 | 1s | 9s | ✅ | ✅ |
| T1059.001 | R100500 | 12 | 1s | 13s | ✅ | ✅ |
| T1003.001 | R100501 | 14 | 11s | 15s | ✅ | ✅ |
| T1003 (Mimikatz) | R100505 | 15 | 1s | 14s | ✅ | ✅ |

**Tasa de detección Windows: 6/6 = 100%** | MTTD medio: ~3s

> Limitación honesta documentada: T1218 (certutil como LOLBAS) no se validó — bloqueado por una capa de contención no identificada del sistema (Defender/AppLocker), incluso con Defender en tiempo real deshabilitado.

---

## Métricas Globales

| Métrica | Valor |
|---|---|
| Técnicas MITRE validadas | 18 (12 Linux + 6 Windows) |
| Tasa de detección global | 100% |
| MTTD medio | 1–8 s |
| MTTR medio pipeline completo (Wazuh→Shuffle→TheHive) | 12–19 s |
| Tiempo de aislamiento automático | < 30 s |
| Acciones automatizadas por evento (Flujo Interno) | 7 |
| Acciones automatizadas por evento (Flujo IPs, score ≥ 40) | 15 |
| Alertas reales procesadas (11 semanas) | 347.324 |
| Alertas accionables (nivel ≥ 10) | 21.421 (6,2% del total) |
| Casos generados en TheHive | 21.421 |
| Países atacantes identificados | 36 |
| Tácticas MITRE detectadas en producción | 10 |
| IoCs exportados automáticamente a MISP | 71 |
| Coste infraestructura | 179,98 €/mes (2.159,76 €/año) |
| **MTTR sector — referencia (IBM Cost of a Data Breach 2025)** | **194 días** |

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

Watchlist adaptativa 
IPs con score > 0 pero < 40 se añaden a watchlist MISP
→ en el siguiente intento, MISP hit +30 puede superar el umbral,
resolviendo el gap de detección ante IPs "day-zero" sin reputación previa
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

**MISP antes que VirusTotal**: consulta local (<1ms, sin rate limit) antes de gastar las 4 llamadas/min gratuitas de VT.

**Scoring ponderado vs condición binaria**: evita falsos negativos por IPs sin reputación (day-zero) y falsos positivos por una detección aislada en VT.

**Flujo Interno sin scoring**: los eventos que lo activan (modificación de /etc/sudoers, acceso a /etc/shadow, nuevo servicio systemd) son intrínsecamente anómalos por diseño de la regla; no requieren validación externa.

**No bloqueo automático de IP atacante**: riesgo de falso positivo inaceptable (NAT compartido). Se documenta como "block-candidate" con aprobación manual.

**Aislamiento NSG sí es automático**: a diferencia del bloqueo de IP, contener el *endpoint* ante técnicas críticas confirmadas (ransomware, C2) se considera de bajo riesgo y alto impacto en tiempo de respuesta.

**Anti-alert-fatigue en port scan**: reconocimiento aislado genera alerta informativa sin caso TheHive; solo escala si se combina con brute force o login exitoso posterior.

**CTI cerrado con watchlist adaptativa**: la retroalimentación del analista y el registro de IPs sin reputación confirmada convergen en una base de conocimiento local que mejora la precisión del scoring ante ataques futuros.

**Docker solo en el stack SOAR/CTI, no en el SIEM**: TheHive, MISP y Shuffle
se containerizan para aislar dependencias y facilitar recuperación ante
fallo; Wazuh Manager permanece nativo por ser el componente de detección
crítico, evitando una capa adicional de virtualización entre el agente y
el motor de correlación.
---

## Autor

Arturo Giusseppe Valverde Avendaño

TFG — Grado en Ingeniería de Tecnologías de Telecomunicación, Universidad de Castilla-La Mancha
Curso académico 2025-2026

---

> **Nota**: Este repositorio documenta el proceso de implementación de un SOC académico funcional. IPs, credenciales, tokens y configuraciones específicas de la infraestructura desplegada han sido eliminados del repositorio. Adicionalmente cabe recalcar que este proyecto ya no se encuentra operativo en producción.
