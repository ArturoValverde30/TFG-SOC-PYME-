# Active Response — Respuesta activa automatizada

Esta carpeta contiene los componentes que implementan **contención
automática** ante la detección de técnicas críticas (ransomware, C2,
credential dumping), sin intervención humana.

## Arquitectura de dos capas

El sistema implementa dos mecanismos de contención complementarios,
activados desde puntos distintos del pipeline, ante la misma detección:

**Trigger común**: Wazuh detecta una regla crítica (T1486 ransomware,
T1071 C2, T1003.001 LSASS dump, honeypot/canary).

| | Capa Host (Active Response nativo) | Capa Red (vía Shuffle → NSG) |
|---|---|---|
| **Ruta de ejecución** | Wazuh ejecuta `kill-attacker.sh` directamente en el agente, sin pasar por el SOAR | Shuffle → HTTP POST → `isolation_webhook.py` (VM1:9876) → `isolate_vm.sh` → Azure Management API |
| **Acción** | Mata la sesión TCP ya establecida (`pkill` + `passwd -l`) | Aplica regla NSG `deny-all inbound` |
| **Tiempo** | 1-2 segundos | < 30 segundos |
| **Cubre** | Sesiones ya abiertas (el NSG no las corta) | Previene reentrada tras la expulsión |

**Por qué dos capas y no una sola**: un aislamiento de red (NSG) no
interrumpe una sesión TCP que ya está establecida — el atacante sigue
teniendo su shell activa aunque no pueda abrir conexiones nuevas. La
capa de host (`kill-attacker.sh`) resuelve exactamente ese hueco,
expulsando la sesión en el mismo segundo de la detección. La capa de
red complementa evitando que el atacante vuelva a entrar tras ser
expulsado.
`````
**Por qué dos capas y no una sola**: un aislamiento de red (NSG) no
interrumpe una sesión TCP que ya está establecida — el atacante sigue
teniendo su shell activa aunque no pueda abrir conexiones nuevas. La
capa de host (`kill-attacker.sh`) resuelve exactamente ese hueco,
expulsando la sesión en el mismo segundo de la detección. La capa de
red complementa evitando que el atacante vuelva a entrar tras ser
expulsado.

## Orden de ejecución del pipeline completo

1. **Preservar evidencia primero**: Velociraptor lanza el hunt forense
   antes de cualquier acción de contención (principio NIST SP 800-61r3:
   *preserve evidence before containment*)
2. **Contención de host**: `kill-attacker.sh` expulsa y bloquea la
   sesión activa del atacante
3. **Contención de red**: `isolate_vm.sh` aplica la regla NSG `deny-all
   inbound` para evitar reconexión
4. **Canal forense preservado**: el cliente Velociraptor conecta en
   modo *outbound* hacia el servidor (VM1:8000), por lo que el
   aislamiento entrante no interrumpe la adquisición forense posterior

## Componentes de esta carpeta

| Archivo | Dónde se ejecuta | Rol |
|---|---|---|
| `kill-attacker.sh` | Endpoint comprometido (Active Response nativo de Wazuh) | Expulsa y bloquea sesiones activas no-admin |
| `isolation_webhook.py` | VM del manager (Wazuh Manager), puerto 9876 | Recibe la orden de Shuffle, valida token, invoca `isolate_vm.sh` |
| `isolate_vm.sh` | VM del manager | Obtiene token vía Managed Identity y aplica la regla NSG en Azure |
| `systemd/isolation-webhook.service` | VM del manager | Mantiene el webhook activo como servicio persistente |

## Requisitos previos en Azure

- **Managed Identity** asignada a la VM del manager (System Assigned),
  con rol **Network Contributor** sobre el resource group que contiene
  el NSG objetivo. No se usan credenciales estáticas: el token se
  obtiene en tiempo real del servicio de metadatos interno
  (`169.254.169.254`).
- El NSG del endpoint a aislar debe existir previamente; el script
  crea/actualiza una única regla llamada `ISOLATE-AUTOMATED` (prioridad
  200) sobre él.

## Instalación paso a paso

### 1. Managed Identity (una vez, desde Azure CLI)

```bash
az vm identity assign --resource-group <RESOURCE_GROUP> --name <MANAGER_VM_NAME>

az role assignment create --role "Network Contributor" \
  --assignee-object-id <PRINCIPAL_ID_DEVUELTO_ARRIBA> \
  --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>"
```

### 2. Copiar y configurar los scripts en la VM del manager

```bash
sudo cp isolate_vm.sh /var/ossec/bin/isolate_vm.sh
sudo cp isolation_webhook.py /var/ossec/bin/isolation_webhook.py
sudo chmod +x /var/ossec/bin/isolate_vm.sh
sudo chown root:wazuh /var/ossec/bin/isolate_vm.sh
```

Edita ambos scripts y sustituye los placeholders:
- `isolate_vm.sh`: `SUBSCRIPTION`, `RESOURCE_GROUP`, `NSG_NAME`
- `isolation_webhook.py`: `TOKEN`, `ALLOWED_AGENTS`

### 3. Registrar el servicio systemd del webhook

```bash
sudo cp systemd/isolation-webhook.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now isolation-webhook.service
sudo systemctl status isolation-webhook.service
```

### 4. Instalar `kill-attacker.sh` en el endpoint víctima

⚠️ **Punto crítico** (ver más abajo, sección "Advertencia"): copiar el
script en la ruta de **ejecución real** del agente, no en `shared/`.

```bash
# En el endpoint que se va a monitorizar/aislar:
sudo cp kill-attacker.sh /var/ossec/active-response/bin/kill-attacker.sh
sudo chmod 750 /var/ossec/active-response/bin/kill-attacker.sh
```

Edita el script y sustituye `ADMIN_USER="<YOUR_ADMIN_USERNAME>"` por tu
usuario administrador real (la cuenta que nunca debe ser expulsada).

### 5. Configurar `ossec.conf` en el manager

Ver sección siguiente.

### 6. Configurar reglas NSG de acceso al webhook

El webhook (puerto 9876) solo debe aceptar tráfico desde la VM donde
corre Shuffle:

```bash
az network nsg rule create \
  --resource-group <RESOURCE_GROUP> \
  --nsg-name <MANAGER_VM_NSG> \
  --name Allow-Isolation-Webhook \
  --priority 400 \
  --destination-port-ranges 9876 \
  --protocol Tcp \
  --source-address-prefixes <IP_PRIVADA_VM_SHUFFLE>
```

## Validación end-to-end

```bash
# 1. Probar el webhook directamente
curl -X POST http://localhost:9876 \
  -H "Content-Type: application/json" \
  -d '{"token":"<TU_TOKEN>","rule_id":"test","agent_name":"<TU_AGENTE>"}'
# Esperado: {"status": "isolated", "agent": "..."}

# 2. Verificar la regla creada en el NSG
az network nsg rule show --resource-group <RG> --nsg-name <NSG> \
  --name ISOLATE-AUTOMATED

# 3. Revisar el log
sudo tail -20 /var/ossec/logs/isolation.log
```

## Des-aislamiento (rollback manual)

El aislamiento es deliberadamente **irreversible de forma automática**
— requiere intervención humana para levantar la cuarentena, ya que es
una decisión que debe validar un analista:

```bash
TOKEN=$(curl -s -H "Metadata: true" \
"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
| python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X DELETE \
"https://management.azure.com/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>/providers/Microsoft.Network/networkSecurityGroups/<NSG_NAME>/securityRules/ISOLATE-AUTOMATED?api-version=2023-05-01" \
-H "Authorization: Bearer ${TOKEN}"
```

## Advertencia de troubleshooting real

Durante la validación se descubrió que en Wazuh sobre Linux, el
**Active Response no se ejecuta desde `/var/ossec/etc/shared/`**
(el directorio pensado para distribución vía grupos de agentes), sino
desde **`/var/ossec/active-response/bin/`**, local a cada agente. La
sincronización entre ambos directorios no es automática ni inmediata
tras un `systemctl restart wazuh-agent`. Si el script se actualiza
solo en `shared/`, el agente sigue ejecutando la versión antigua sin
ningún error visible.

**Consecuencia práctica**: siempre copiar/actualizar directamente en
`active-response/bin/` en el endpoint, y verificar la versión activa
con:

```bash
md5sum /var/ossec/active-response/bin/kill-attacker.sh
md5sum /var/ossec/etc/shared/kill-attacker.sh   # puede estar desactualizado
```

## Notas de seguridad para producción

- **Token estático**: el webhook usa un token fijo en texto plano en
  el código. Válido para entorno de laboratorio; en producción debe
  sustituirse por un secreto gestionado (Azure Key Vault, HashiCorp
  Vault) con rotación automática.
- **Allowlist de agentes**: el webhook solo aísla agentes en
  `ALLOWED_AGENTS`. Ampliar esta lista con criterio — cada agente
  añadido es un endpoint que puede quedar desconectado
  automáticamente sin aprobación humana previa.
- **Alcance de la Managed Identity**: el rol Network Contributor
  debería restringirse al NSG específico protegido, no a todo el
  resource group, en un despliegue productivo.
- **Scope deliberadamente limitado**: el aislamiento automático solo
  se activa ante un conjunto reducido de reglas verdaderamente
  críticas (ransomware, C2, LSASS dump, honeypot/canary). No se
  bloquean IPs atacantes automáticamente — ese mecanismo se mantiene
  como decisión manual del analista (`block-candidate`) por el riesgo
  de falso positivo sobre IPs compartidas/NAT.

  
