# TFG-SOC-PYME-
# TFG — SOC Automatizado para PYMEs
**Grado en Ingeniería de Tecnologías de Telecomunicación**  
Escuela Politécnica de Cuenca — UCLM · 2025–2026


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
└── VM4 — Víctima Windows [2vCPU/4GB · ~$9/mes]
```

**Coste estimado total: ~$130 en 3 meses** — dentro del presupuesto disponible.

---

## Resultados de validación

---

## Cómo replicar el laboratorio
---

## Tutor

José Antonio Ballesteros Garrido — Coordinador GITT, UCLM Cuenca

---

## Licencia

MIT — Libre para uso académico y replicación en entornos de laboratorio.
