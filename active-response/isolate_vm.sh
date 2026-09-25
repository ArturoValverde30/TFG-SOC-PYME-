#!/bin/bash
# isolate_vm.sh — Aísla un endpoint comprometido mediante Azure NSG
# Uso: isolate_vm.sh <rule_id> <agent_name>
# Requiere: Managed Identity de la VM con rol "Network Contributor"
#           sobre el resource group objetivo (sin credenciales estáticas)

set -euo pipefail

RULE_ID="${1:-unknown}"
AGENT="${2:-unknown}"

# ── CONFIGURAR ANTES DE USAR ──────────────────────────────────────
SUBSCRIPTION="<AZURE_SUBSCRIPTION_ID>"
RESOURCE_GROUP="<RESOURCE_GROUP_NAME>"
NSG_NAME="<TARGET_NSG_NAME>"
RULE_NAME="ISOLATE-AUTOMATED"
API_VERSION="2023-05-01"
# ────────────────────────────────────────────────────────────────

log() { echo "$(date -u +%FT%TZ) $*" >> /var/ossec/logs/isolation.log; }

# Obtener token via Managed Identity (metadata service interno Azure)
TOKEN=$(curl -sf \
  -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token\
?api-version=2018-02-01\
&resource=https://management.azure.com/" \
  | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['access_token'])")

if [ -z "$TOKEN" ]; then
  log "ERROR: no se pudo obtener token Managed Identity"
  exit 1
fi

# Body de la regla NSG (deny-all inbound, prioridad 200)
BODY=$(cat <<EOF
{
  "properties": {
    "priority": 200,
    "protocol": "*",
    "access": "Deny",
    "direction": "Inbound",
    "sourceAddressPrefix": "*",
    "sourcePortRange": "*",
    "destinationAddressPrefix": "*",
    "destinationPortRange": "*",
    "description": "SOC auto-isolation: rule=${RULE_ID} agent=${AGENT}"
  }
}
EOF
)

ENDPOINT="https://management.azure.com/subscriptions/${SUBSCRIPTION}\
/resourceGroups/${RESOURCE_GROUP}\
/providers/Microsoft.Network/networkSecurityGroups/${NSG_NAME}\
/securityRules/${RULE_NAME}?api-version=${API_VERSION}"

HTTP_CODE=$(curl -sf -o /tmp/isolate_response.json -w "%{http_code}" \
  -X PUT "$ENDPOINT" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$BODY")

if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "201" ]]; then
  log "NSG_RULE_CREATED rule=${RULE_ID} agent=${AGENT} http=${HTTP_CODE}"
  exit 0
else
  log "NSG_RULE_FAILED http=${HTTP_CODE} response=$(cat /tmp/isolate_response.json)"
  exit 1
fi
