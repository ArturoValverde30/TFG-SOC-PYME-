"""

import json
import re
import datetime

score = 0

def parse_body(raw):
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip() and not raw.startswith('$'):
        try:
            return json.loads(raw)
        except:
            return {}
    return {}

def safe_int(val):
    try:
        cleaned = re.sub(r'[^\d]', '', str(val))
        return int(cleaned) if cleaned else 0
    except:
        return 0

# ── MISP: hit en feeds locales/públicos → +30 ──────────────────────
try:
    misp_raw = """$misp.body"""
    misp = parse_body(misp_raw)
    if misp.get("response", {}).get("Attribute"):
        score += 30
except:
    pass

# ── VirusTotal: fail-safe rate limit + detecciones ──────────────────
try:
    vt_status = safe_int("""$virustotal.status""")
    if vt_status != 429:
        vt_raw = """$virustotal.body"""
        vt = parse_body(vt_raw)
        malicious = safe_int(
            vt.get("data", {})
              .get("attributes", {})
              .get("last_analysis_stats", {})
              .get("malicious", 0)
        )
        if malicious > 0:
            score += 20
        if malicious > 5:
            score += 40   # acumulable sobre el +20 anterior
except:
    pass

# ── AbuseIPDB: índice de confianza de la comunidad ──────────────────
try:
    abuse_raw = """$abuseipdb.body"""
    abuse = parse_body(abuse_raw)
    confidence = safe_int(abuse.get("data", {}).get("abuseConfidenceScore", 0))
    if confidence > 50:
        score += 15
    if confidence > 75:
        score += 30   # acumulable sobre el +15 anterior
except:
    pass

# ── GeoIP: país de origen de alto riesgo ────────────────────────────
try:
    country = """$virustotal.body.data.attributes.country"""
    if not country or country.startswith("$"):
        country = ""
    high_risk_countries = ["RO", "US", "DE", "CN", "IN", "MX", "NL", "RU", "BG", "ES"]
    if country in high_risk_countries:
        score += 10
except:
    pass

# ── Wazuh: nivel de severidad de la regla ───────────────────────────
try:
    level = safe_int("""$exec.all_fields.rule.level""")
    if level > 12:
        score += 10
except:
    pass

# ── Correlación temporal: regla intrínsecamente anómala → +20 ───────
try:
    rule_id = """$exec.all_fields.rule.id"""
    correlation_rules = ["100050", "100200", "100203", "100204", "40112"]
    if rule_id in correlation_rules:
        score += 20
except:
    pass

# ── Asset criticality: activos críticos del SOC ──────────────────────
try:
    agent = """$exec.all_fields.agent.name"""
    if not agent.startswith('$'):
        critical_assets = ["vm2-soc", "vm1-wazuh"]
        if agent.strip() in critical_assets:
            score += 15
except:
    pass

# ── Horario fuera de ventana laboral UTC 07:00–22:00 ─────────────────
try:
    hour = datetime.datetime.utcnow().hour
    if hour < 7 or hour > 22:
        score += 10
except:
    pass

# ── Normalización y clasificación final ───────────────────────────────
score = min(score, 100)   # tope de clasificación (máximo teórico: 165)

if score >= 70:
    severity = 4  # Critical
elif score >= 40:
    severity = 3  # High
else:
    severity = 2  # Medium

print(score)
