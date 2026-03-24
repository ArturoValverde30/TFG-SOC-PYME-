# TFG-SOC-PYME-
# TFG — SOC Automatizado con IA para PYMEs
**Grado en Ingeniería de Tecnologías de Telecomunicación**  
Escuela Politécnica de Cuenca — UCLM · 2024–2025

![Estado](https://img.shields.io/badge/estado-en%20desarrollo-yellow)
![Coste](https://img.shields.io/badge/coste-100%25%20open%20source-green)
![Cloud](https://img.shields.io/badge/cloud-Azure%20%2B%20DigitalOcean-blue)

---

## ¿Qué es este proyecto?

Diseño e implementación de un SOC (Security Operations Center) automatizado, 100% open source y coste prácticamente cero, orientado a pequeñas y medianas empresas que no pueden permitirse soluciones comerciales.

El sistema detecta, correlaciona y responde a incidentes de seguridad de forma automática en menos de 30 segundos, desde la alerta hasta el aislamiento de la VM comprometida.

---

## Stack tecnológico

| Capa | Herramienta | Función |
|------|-------------|---------|
| SIEM/XDR | Wazuh 4.7+ | Detección, correlación, ML, agentes |
| IDS de red | Suricata 7.x | Análisis de tráfico con reglas ET Open |
| Honeypots | OpenCanary | Detección en fase de reconocimiento |
| CTI | MISP | Threat intelligence, feeds IoC en tiempo real |
| SOAR | Shuffle | Automatización del flujo de respuesta |
| Case Mgmt | TheHive 5 | Gestión del ciclo de vida del incidente |
| Hunting | Velociraptor 0.7+ | Threat hunting proactivo con VQL |
| Vuln Mgmt | OpenVAS/Greenbone | Escaneo automático de vulnerabilidades |
| Monitorización | Grafana OSS 10.x | Dashboards + alertas para dirección |

---

## Infraestructura cloud

```
Azure UCLM ($100 disponibles)
├── VM1 — Wazuh Manager   [Ubuntu 22.04 · B2s  · ~$12/mes con auto-shutdown]
└── VM2 — SOC Stack       [Ubuntu 22.04 · B4ms · ~$25/mes con auto-shutdown]

DigitalOcean ($200 disponibles)
├── VM3 — Atacante Kali   [2vCPU/4GB · ~$8/mes]
└── VM4 — Víctima Windows [2vCPU/4GB · ~$9/mes solo semanas 6-9]
```

**Coste estimado total: ~$130 en 3 meses** — dentro del presupuesto disponible.

---

## Flujo de automatización (14 pasos, <30 segundos)

```
Ataque (T=0s)
  └─> Wazuh detecta (T+5s)
        └─> Shuffle recibe webhook (T+6s)
              ├─> Consulta MISP — ¿IoC conocido? (T+8s)
              ├─> Consulta VirusTotal (T+10s)
              ├─> Consulta AbuseIPDB (T+12s)
              ├─> Crea caso TheHive enriquecido (T+15s)
              ├─> Lanza escaneo OpenVAS (T+18s)
              ├─> Notifica al analista por email (T+20s)
              └─> [Si nivel 12+] Aisla VM automáticamente via Azure API (T+25s)
```


## Resultados de validación

> *Esta sección se completará en la semana 9-10 con los datos reales del laboratorio.*

| Métrica | SOC v1 (objetivo) | SOC v2 (objetivo) |
|---------|-------------------|-------------------|
| Tasa de detección | >70% | >85% |
| MTTD promedio | <180s | <120s |
| Tasa FP/hora | <8 | <5 |
| TTPs cubiertos (20 totales) | >14 | >17 |

---

## Cómo replicar el laboratorio

Consulta la guía completa en [`infrastructure/README.md`](infrastructure/README.md).

**Prerrequisitos:**
- Cuenta Azure con crédito activo (UCLM o Azure for Students)
- Cuenta DigitalOcean con crédito activo
- Cuenta GitHub para clonar este repositorio

```bash
# Clonar el repositorio
git clone https://github.com/TU_USUARIO/tfg-soc-pyme.git
cd tfg-soc-pyme

# Seguir la guía de infraestructura
cat infrastructure/README.md
```

---

## Tutor

José Antonio Ballesteros Garrido — Coordinador GITT, UCLM Cuenca

---

## Licencia

MIT — Libre para uso académico y replicación en entornos de laboratorio.
