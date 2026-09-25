## Configuración en `ossec.conf` (Wazuh Manager)

Estos bloques van dentro de `<ossec_config>` en
`/var/ossec/etc/ossec.conf` del **manager** (no del endpoint). Definen
el comando ejecutable y la regla que lo dispara.

```xml
<!-- 1. Declaración del comando -->
<command>
  <name>kill-attacker</name>
  <executable>kill-attacker.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<!-- 2. Asociación comando ↔ regla ↔ agente -->
<active-response>
  <disabled>no</disabled>
  <command>kill-attacker</command>
  <location>defined-agent</location>
  <agent_id>004</agent_id>
  <rules_id>100610</rules_id>
</active-response>
```

### Explicación de cada campo

| Campo | Valor usado | Significado |
|---|---|---|
| `<name>` | `kill-attacker` | Identificador interno del comando, debe coincidir con el nombre en `<active-response><command>` |
| `<executable>` | `kill-attacker.sh` | Nombre del script — Wazuh lo busca en `active-response/bin/` del agente, **no** hace falta ruta absoluta |
| `<timeout_allowed>` | `no` | El comando no admite reversión automática por timeout (a diferencia de, p. ej., un bloqueo temporal de IP) |
| `<location>` | `defined-agent` | El Active Response se ejecuta **solo** en el agente especificado, no en todos los agentes que matcheen la regla — evita expulsiones accidentales en endpoints no destinados a contención |
| `<agent_id>` | `004` | ID del agente objetivo (sustituir por el ID real, visible con `agent_control -l`) |
| `<rules_id>` | `100610` | Rule ID(s) que disparan este Active Response — en este caso, el honeypot/canary file. Puede ser una lista separada por comas para disparar el mismo comando con múltiples reglas |

### Validar la sintaxis antes de reiniciar

Wazuh no reinicia si el XML es inválido, pero conviene comprobarlo
antes para evitar downtime del manager:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

Solo si el output confirma configuración válida:

```bash
sudo systemctl restart wazuh-manager
```

### Confirmar que el Active Response está cargado

```bash
sudo grep -A5 "active-response" /var/ossec/etc/ossec.conf
sudo tail -f /var/ossec/logs/ossec.log | grep -i "active response"
```

### Extender a más reglas críticas

Para que el mismo mecanismo dispare ante ransomware (T1486) o C2
(T1071) además del canary, basta con ampliar `rules_id`:

```xml
<active-response>
  <disabled>no</disabled>
  <command>kill-attacker</command>
  <location>defined-agent</location>
  <agent_id>004</agent_id>
  <rules_id>100006,100007,100610</rules_id>
</active-response>
```
