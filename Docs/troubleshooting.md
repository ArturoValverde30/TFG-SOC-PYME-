# Troubleshooting real durante la implementación

Incidencias técnicas encontradas y resueltas durante el desarrollo,
documentadas con causa raíz y fix aplicado.

## 1. TheHive caído por br_netfilter (Docker Swarm + Azure)
**Síntoma**: TheHive no se comunicaba con Cassandra tras despliegue en Azure.
**Causa raíz**: el módulo de kernel br_netfilter interceptaba el tráfico
entre contenedores Docker; las reglas de Docker Swarm lo bloqueaban.
**Fix**: `/etc/sysctl.d/99-docker-bridge.conf`
net.bridge.bridge-nf-call-iptables=0
net.bridge.bridge-nf-call-ip6tables=0
net.bridge.bridge-nf-call-arptables=0
Persistido como servicio systemd tras detectar que el fix en sysctl no
sobrevivía a reinicios completos de la VM.

## 2. Workers de Shuffle no alcanzaban TheHive
**Causa raíz**: los workers efímeros de Shuffle (Docker Swarm) usaban la
IP pública de Azure para comunicación interna, en vez de la red privada.
**Fix**: `OUTER_HOSTNAME` cambiado de IP pública a IP privada en
`.env` de Shuffle; nodo TheHive migrado de nativo a HTTP genérico
resolviendo vía gateway Docker bridge (172.17.0.1).

## 3. if_sid teóricos vs reales en reglas Windows/Sysmon
**Síntoma**: 5 reglas custom de Windows no disparaban pese a que el
evento sí llegaba a Wazuh.
**Causa raíz**: los if_sid escritos según documentación oficial no
coincidían con los IDs reales que Wazuh asigna al decodificar eventos
Sysmon.
**Fix**: validación empírica evento por evento contra alerts.log.
Tabla de correcciones aplicadas: 100500 (91802→92027), 100502
(7040→61138), 100503 (61614→92302 + fix regex pcre2 backslash),
100504 (60106→60109).
**Lección**: la documentación oficial no siempre refleja el pipeline
real de decodificación interno de Wazuh; solo la validación empírica
lo confirma.

## 4. Alert fatigue por scan_on_start tras cambios de configuración FIM/Auditd
**Síntoma**: pico de 109.858 alertas en un único día.
**Causa raíz**: cada modificación del bloque syscheck + reinicio del
agente con scan_on_start activo generaba un volcado masivo de eventos
legítimos reinterpretados como nuevos.
**Fix**: vaciado de cola Shuffle vía OpenSearch, exclusiones <ignore>
en directorios de alta actividad legítima, refinamiento de reglas
Auditd con negate="yes" sobre procesos del sistema.

## 5. Corrupción de estado tras 2 meses de inactividad (créditos cloud)
**Síntoma**: Shuffle devolvía "You don't have access to this workflow";
TheHive no respondía.
**Diagnóstico**: alias de OpenSearch con más de un índice asociado
(illegal_argument_exception); contenedor de TheHive en estado `Created`
tras el reinicio, nunca llegó a arrancar el proceso.
**Fix**: reindexado con op_type: create + eliminación del alias
duplicado; arranque manual del contenedor huérfano.
**Lección documentada**: limitación real de entornos de laboratorio
dependientes de créditos cloud con interrupciones no controladas,
frente a un entorno productivo con continuidad garantizada.

## 6. Wazuh manager caído por regla con frequency inválido
**Causa raíz**: atributo `frequency="1"` en una regla de correlación;
Wazuh exige un mínimo de 2.
**Fix**: validación con `python3 ET.parse()` antes de todo restart
de wazuh-manager como práctica de control de cambios.
