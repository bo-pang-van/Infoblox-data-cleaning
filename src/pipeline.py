import csv
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from ipaddress import ip_address, IPv4Address, IPv4Network


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

PROMPTS_LOG_PATH = Path(__file__).resolve().parent.parent / "documentations" / "prompts.md"
OPENAI_KEY_FILE = Path(__file__).resolve().parent.parent / "config" / "openai_api_key.txt"


def normalize_ip(s):
    steps = []
    if s is None:
        return {
            "ip": "",
            "ip_valid": False,
            "ip_version": "",
            "reverse_ptr": "",
            "subnet_cidr": "",
            "steps": ["ip_missing"],
            "issue": ("ip", "missing", s),
        }
    raw = str(s).strip()
    steps.append("ip_trim")
    ip_input = raw
    if "%" in raw and ":" in raw:
        base, _, _ = raw.partition("%")
        if base:
            ip_input = base
            steps.append("ip_scope_id_strip")
    try:
        ip = ip_address(ip_input)
        steps.append("ip_parse")
        # Canonical form
        if isinstance(ip, IPv4Address):
            canon = str(ip)
            ip_ver = "4"
            # Heuristic subnet for private IPv4
            subnet = ""
            if ip.is_private:
                net = IPv4Network(f"{canon}/24", strict=False)
                subnet = str(net)
        else:
            # IPv6 compressed canonical
            canon = ip.compressed
            ip_ver = "6"
            subnet = ""
        steps.append("ip_normalize")
        return {
            "ip": canon,
            "ip_valid": True,
            "ip_version": ip_ver,
            "reverse_ptr": ip.reverse_pointer + "." if hasattr(ip, "reverse_pointer") else "",
            "subnet_cidr": subnet,
            "steps": steps,
            "issue": None,
        }
    except ValueError as e:
        # quick reason tags
        reason = "invalid_ip"
        if ":" in raw:
            reason = "ipv6_or_non_ipv4"
        elif raw.count(".") != 3:
            reason = "wrong_part_count"
        elif any(p == "" for p in raw.split(".")):
            reason = "empty_octet"
        return {
            "ip": raw,
            "ip_valid": False,
            "ip_version": "",
            "reverse_ptr": "",
            "subnet_cidr": "",
            "steps": steps + [f"ip_invalid_{reason}"],
            "issue": ("ip", reason, s),
        }


def is_valid_hostname_label(label: str) -> bool:
    return bool(HOST_LABEL_RE.match(label))


def normalize_hostname(hostname):
    steps = []
    if not hostname:
        return {"hostname": "", "hostname_valid": "", "steps": ["hostname_missing"], "issue": None}
    raw = str(hostname).strip().lower()
    steps.append("hostname_trim_lower")
    valid = is_valid_hostname_label(raw)
    step = "hostname_valid" if valid else "hostname_invalid"
    steps.append(step)
    issue = None if valid else ("hostname", "invalid_format", hostname)
    return {"hostname": raw, "hostname_valid": "true" if valid else "false", "steps": steps, "issue": issue}


def normalize_fqdn(fqdn, hostname_out):
    steps = []
    if not fqdn:
        return {"fqdn": "", "fqdn_consistent": "", "steps": ["fqdn_missing"], "issue": None}
    raw = str(fqdn).strip().lower().rstrip(".")
    steps.append("fqdn_trim_lower")
    labels = [l for l in raw.split(".") if l]
    valid = all(is_valid_hostname_label(l) for l in labels) and len(labels) >= 2
    consistent = ""
    issue = None
    if valid and hostname_out:
        consistent = "true" if labels[0] == hostname_out else "false"
        if consistent == "false":
            issue = ("fqdn", "hostname_mismatch", fqdn)
    elif not valid:
        issue = ("fqdn", "invalid_format", fqdn)
    steps.append("fqdn_valid" if valid else "fqdn_invalid")
    return {"fqdn": raw, "fqdn_consistent": consistent, "steps": steps, "issue": issue}


def normalize_mac(mac):
    steps = []
    if not mac:
        return {"mac": "", "mac_valid": "", "steps": ["mac_missing"], "issue": None}
    raw = str(mac).strip().lower()
    steps.append("mac_trim_lower")
    # remove common separators and Cisco dotted format
    hex_only = re.sub(r"[^0-9a-f]", "", raw)
    if len(hex_only) == 12 and HEX_RE.match(hex_only):
        norm = ":".join(hex_only[i:i+2] for i in range(0, 12, 2))
        steps.append("mac_normalize")
        return {"mac": norm, "mac_valid": "true", "steps": steps, "issue": None}
    else:
        steps.append("mac_invalid")
        return {"mac": raw, "mac_valid": "false", "steps": steps, "issue": ("mac", "invalid_format", mac)}


TEAM_CANON = {
    "platform": "platform",
    "ops": "operations",
    "operations": "operations",
    "sec": "security",
    "security": "security",
    "facilities": "facilities",
}


def parse_owner(raw_owner):
    steps = []
    if not raw_owner:
        return {"owner": "", "owner_email": "", "owner_team": "", "steps": ["owner_missing"], "issue": None}
    s = str(raw_owner).strip()
    steps.append("owner_trim")
    # email
    email = ""
    m = EMAIL_RE.search(s)
    if m:
        email = m.group(0)
        steps.append("owner_email_extract")
    # team (parenthetical or tokens)
    team = ""
    paren = re.findall(r"\(([^)]+)\)", s)
    if paren:
        cand = paren[0].strip().lower()
        team = TEAM_CANON.get(cand, cand)
        steps.append("owner_team_paren")
    else:
        for key in TEAM_CANON:
            if re.search(rf"\b{re.escape(key)}\b", s, flags=re.I):
                team = TEAM_CANON[key]
                steps.append("owner_team_token")
                break
    # owner name heuristic
    owner = s
    if email:
        local = email.split("@", 1)[0]
        owner = local
        steps.append("owner_from_email_localpart")
    owner = owner.strip()
    return {"owner": owner, "owner_email": email, "owner_team": team, "steps": steps, "issue": None}


def _load_openai_api_key():
    key = os.getenv("OPENAI_API_KEY", "").strip()
    if key:
        return key
    if OPENAI_KEY_FILE.exists():
        fallback = OPENAI_KEY_FILE.read_text().strip()
        if fallback:
            return fallback
    raise RuntimeError(
        "OpenAI API key not configured. Set OPENAI_API_KEY or create config/openai_api_key.txt."
    )


def _log_llm_interaction(source_row_id, prompt, payload, response_json, model):
    fingerprint_src = json.dumps(
        {"source_row_id": source_row_id, "payload": payload}, sort_keys=True
    )
    fingerprint = hashlib.sha256(fingerprint_src.encode("utf-8")).hexdigest()
    if PROMPTS_LOG_PATH.exists():
        contents = PROMPTS_LOG_PATH.read_text()
        if f"Fingerprint: {fingerprint}" in contents:
            return
    entry = [
        "---",
        f"Date: {datetime.utcnow().isoformat()}Z",
        f"Context: Device type classification for source_row_id {source_row_id}",
        f"Fingerprint: {fingerprint}",
        "Prompt:",
        '"""',
        prompt,
        '"""',
        f"Constraints: temperature=0.1; JSON-only output; model={model}",
        "Expected JSON schema: {device_type: string, device_type_confidence: string, reason: string}",
        "Rationale: Deterministic rules could not determine device_type; escalating to LLM for guidance.",
        "Response:",
        "```json",
        json.dumps(response_json, indent=2),
        "```",
        "---",
        "",
    ]
    PROMPTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(PROMPTS_LOG_PATH, "a") as log_file:
        log_file.write("\n".join(entry))


def _invoke_llm_device_type(row):
    source_row_id = str(row.get("source_row_id") or "").strip()
    payload = {
        "source_row_id": source_row_id,
        "ip": str(row.get("ip") or ""),
        "hostname": str(row.get("hostname") or ""),
        "fqdn": str(row.get("fqdn") or ""),
        "mac": str(row.get("mac") or ""),
        "owner": str(row.get("owner") or ""),
        "site": str(row.get("site") or ""),
        "notes": str(row.get("notes") or ""),
    }
    instructions = (
        "You are a precise network inventory classifier. "
        'Choose one device_type from ["server","router","switch","printer","iot","unknown"]. '
        'Return JSON {"device_type": string, "device_type_confidence": one_of["low","medium","high"], "reason": string}. '
        "Do not include any explanatory prose outside the JSON object."
    )
    prompt = instructions + "\nInput: " + json.dumps(payload, sort_keys=True)
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError(
            "The openai package is required. Install it with `pip install openai`."
        ) from exc

    api_key = _load_openai_api_key()
    client = OpenAI(api_key=api_key)
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    response = client.chat.completions.create(
        model=model,
        temperature=0.1,
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": "You respond with valid JSON only.",
            },
            {"role": "user", "content": prompt},
        ],
        max_tokens=200,
    )
    content = response.choices[0].message.content
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"LLM returned non-JSON payload: {content}") from exc
    _log_llm_interaction(source_row_id or "unknown", prompt, payload, parsed, model)
    return parsed


def classify_device_type(row):
    steps = []
    confidence = ""
    device_type_raw = row.get("device_type")
    if device_type_raw:
        dt = str(device_type_raw).strip().lower()
        steps.append("device_type_trim_lower")
        return {"device_type": dt, "device_type_confidence": "high", "steps": steps, "issue": None}
    # heuristics
    hostname = row.get("hostname")
    notes = row.get("notes")
    text = " ".join([str(hostname or ""), str(notes or "")]).lower()
    dt = ""
    if re.search(r"\bprinter\b", text):
        dt = "printer"
    elif re.search(r"\bswitch\b", text):
        dt = "switch"
    elif re.search(r"\brouter\b|\bedge\b|\bgw\b", text):
        dt = "router"
    elif re.search(r"\biot|cam|camera\b", text):
        dt = "iot"
    elif re.search(r"\bsrv|server\b", text):
        dt = "server"
    if dt:
        confidence = "medium"
        steps.append("device_type_heuristic")
    else:
        llm_result = _invoke_llm_device_type(row)
        dt = str(llm_result.get("device_type", "") or "").lower()
        confidence = str(llm_result.get("device_type_confidence", "") or "").lower()
        if dt:
            steps.append("device_type_llm")
    return {"device_type": dt, "device_type_confidence": confidence, "steps": steps, "issue": None}


def normalize_site(site_raw):
    steps = []
    if not site_raw or str(site_raw).strip().lower() in ("n/a", "na", "none"):
        return {"site": "", "site_normalized": "", "steps": ["site_missing"], "issue": None}
    s = str(site_raw).strip()
    steps.append("site_trim")
    # canonical: uppercase, non-alnum -> '-', collapse repeats
    canon = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").upper()
    canon = re.sub(r"-+", "-", canon)
    steps.append("site_normalize")
    return {"site": s, "site_normalized": canon, "steps": steps, "issue": None}


def process_inventory(input_csv: Path, out_csv: Path, anomalies_json: Path):
    anomalies = []
    with open(input_csv, newline="") as f, open(out_csv, "w", newline="") as g:
        reader = csv.DictReader(f)
        fieldnames = [
            "ip",
            "ip_valid",
            "ip_version",
            "subnet_cidr",
            "hostname",
            "hostname_valid",
            "fqdn",
            "fqdn_consistent",
            "reverse_ptr",
            "mac",
            "mac_valid",
            "owner",
            "owner_email",
            "owner_team",
            "device_type",
            "device_type_confidence",
            "site",
            "site_normalized",
            "source_row_id",
            "normalization_steps",
        ]
        # include passthrough columns not in target schema
        passthrough = [c for c in reader.fieldnames if c not in set(["ip", "hostname", "fqdn", "mac", "owner", "device_type", "site", "source_row_id"]) ]
        writer = csv.DictWriter(g, fieldnames=fieldnames + passthrough)
        writer.writeheader()

        for row in reader:
            steps = []
            src_id = row.get("source_row_id")

            ip_res = normalize_ip(row.get("ip"))
            steps += ip_res["steps"]
            if ip_res["issue"]:
                field, typ, val = ip_res["issue"]
                anomalies.append({
                    "source_row_id": src_id,
                    "issues": [{"field": field, "type": typ, "value": val}],
                    "recommended_actions": ["Correct IP or mark for review"],
                })

            host_res = normalize_hostname(row.get("hostname"))
            steps += host_res["steps"]
            if host_res["issue"]:
                field, typ, val = host_res["issue"]
                anomalies.append({
                    "source_row_id": src_id,
                    "issues": [{"field": field, "type": typ, "value": val}],
                    "recommended_actions": ["Fix hostname to RFC1123 compliant"],
                })

            fqdn_res = normalize_fqdn(row.get("fqdn"), host_res.get("hostname"))
            steps += fqdn_res["steps"]
            if fqdn_res["issue"]:
                field, typ, val = fqdn_res["issue"]
                anomalies.append({
                    "source_row_id": src_id,
                    "issues": [{"field": field, "type": typ, "value": val}],
                    "recommended_actions": ["Align hostname and FQDN or correct FQDN format"],
                })

            mac_res = normalize_mac(row.get("mac"))
            steps += mac_res["steps"]
            if mac_res["issue"]:
                field, typ, val = mac_res["issue"]
                anomalies.append({
                    "source_row_id": src_id,
                    "issues": [{"field": field, "type": typ, "value": val}],
                    "recommended_actions": ["Correct MAC format (e.g., aa:bb:cc:dd:ee:ff)"],
                })

            owner_res = parse_owner(row.get("owner"))
            steps += owner_res["steps"]

            dev_res = classify_device_type(row)
            steps += dev_res["steps"]

            site_res = normalize_site(row.get("site"))
            steps += site_res["steps"]

            out_row = {
                "ip": ip_res["ip"],
                "ip_valid": "true" if ip_res["ip_valid"] else ("false" if ip_res["ip"] else ""),
                "ip_version": ip_res["ip_version"],
                "subnet_cidr": ip_res["subnet_cidr"],
                "hostname": host_res["hostname"],
                "hostname_valid": host_res["hostname_valid"],
                "fqdn": fqdn_res["fqdn"],
                "fqdn_consistent": fqdn_res["fqdn_consistent"],
                "reverse_ptr": ip_res["reverse_ptr"],
                "mac": mac_res["mac"],
                "mac_valid": mac_res["mac_valid"],
                "owner": owner_res["owner"],
                "owner_email": owner_res["owner_email"],
                "owner_team": owner_res["owner_team"],
                "device_type": dev_res["device_type"],
                "device_type_confidence": dev_res["device_type_confidence"],
                "site": site_res["site"],
                "site_normalized": site_res["site_normalized"],
                "source_row_id": src_id,
                "normalization_steps": "|".join(steps),
            }

            # pass through any extra columns
            for k in passthrough:
                out_row[k] = row.get(k)

            writer.writerow(out_row)

    with open(anomalies_json, "w") as h:
        json.dump(anomalies, h, indent=2)
