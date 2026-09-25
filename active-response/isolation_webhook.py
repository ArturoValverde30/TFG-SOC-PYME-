#!/usr/bin/env python3
"""
SOC Isolation Webhook
Recibe POST de Shuffle y llama a isolate_vm.sh para contener
el endpoint comprometido.

Puerto: 9876
Autenticación: token estático (ver nota de seguridad abajo)

NOTA DE SEGURIDAD: el token estático es válido para entorno de
laboratorio/TFG. En producción debe sustituirse por un secreto
gestionado (Azure Key Vault, HashiCorp Vault) con rotación
automática — nunca hardcodeado en el archivo.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess, json, logging

LOG_FILE = "/var/ossec/logs/isolation.log"
TOKEN    = "<SET_YOUR_OWN_TOKEN_HERE>"   # cambiar antes de desplegar
PORT     = 9876
ALLOWED_AGENTS = ["<YOUR_VICTIM_AGENT_NAME>"]  # allowlist de endpoints aislables

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

class IsolationHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid json"})
            return

        token      = data.get("token", "")
        rule_id    = data.get("rule_id", "")
        agent_name = data.get("agent_name", "")

        if token != TOKEN:
            logging.warning("INVALID_TOKEN rule=%s agent=%s", rule_id, agent_name)
            self._respond(403, {"error": "forbidden"})
            return

        if agent_name not in ALLOWED_AGENTS:
            logging.warning("AGENT_NOT_ALLOWED agent=%s", agent_name)
            self._respond(403, {"error": "agent not in allowlist"})
            return

        logging.info("ISOLATION_TRIGGERED rule=%s agent=%s", rule_id, agent_name)

        result = subprocess.run(
            ["/var/ossec/bin/isolate_vm.sh", rule_id, agent_name],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode == 0:
            logging.info("ISOLATION_SUCCESS agent=%s", agent_name)
            self._respond(200, {"status": "isolated", "agent": agent_name})
        else:
            logging.error("ISOLATION_FAILED stderr=%s", result.stderr)
            self._respond(500, {"error": "isolation failed", "detail": result.stderr})

    def _respond(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # silenciar log HTTP por defecto

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), IsolationHandler)
    logging.info("Isolation webhook listening on :%d", PORT)
    server.serve_forever()
