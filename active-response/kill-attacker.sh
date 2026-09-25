#!/bin/bash
# kill-attacker.sh — Active Response nativo de Wazuh
# Expulsa (kill -9) y bloquea (passwd -l) cualquier sesión activa
# distinta del usuario administrador, al dispararse una regla crítica
# (ej. canary file / honeypot tocado).
#
# Contención de dos capas: este script actúa a nivel de HOST (mata
# la sesión ya establecida en 1-2s); se complementa con el aislamiento
# NSG a nivel de RED (isolate_vm.sh), que evita reentrada pero no
# corta sesiones TCP ya abiertas.

LOG_FILE="/var/ossec/logs/active-responses.log"
ADMIN_USER="<YOUR_ADMIN_USERNAME>"   # cuenta que nunca debe ser expulsada

echo "$(date '+%Y-%m-%d %H:%M:%S') KILL-ATTACKER: iniciando expulsion masiva" >> $LOG_FILE

USERS_ACTIVOS=$(who | awk '{print $1}' | sort -u | grep -v "^${ADMIN_USER}$")

if [ -z "$USERS_ACTIVOS" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') KILL-ATTACKER: no hay sesiones activas distintas de ${ADMIN_USER}" >> $LOG_FILE
else
    for u in $USERS_ACTIVOS; do
        echo "$(date '+%Y-%m-%d %H:%M:%S') KILL-ATTACKER: expulsando y bloqueando usuario: $u" >> $LOG_FILE
        pkill -9 -u "$u"
        passwd -l "$u"
    done
fi

echo "$(date '+%Y-%m-%d %H:%M:%S') KILL-ATTACKER: completado" >> $LOG_FILE
exit 0
