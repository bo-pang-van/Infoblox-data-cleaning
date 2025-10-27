# Approach

This solution cleans and normalizes a small, messy network inventory CSV using a deterministic-first pipeline with optional AI assistance. It validates key fields, applies canonical normalization, derives helpful context, and emits both a cleaned CSV and a structured anomaly report for follow-up.

## Goals
- Validate and normalize: IP, hostname, FQDN, MAC, owner, device_type, site
- Derive: subnet_cidr (heuristic), reverse_ptr (for valid IPs)
- Report: anomalies.json with source_row_id, issues, and recommended actions
- Reproducible: single entrypoint `run.py` to regenerate outputs end-to-end

## Architecture
- `run.py`: Orchestrator entrypoint. Reads `inventory_raw.csv`, writes `inventory_clean.csv` and `anomalies.json`.
- `src/pipeline.py`: All validation/normalization logic.
  - IP: Uses Python `ipaddress` to validate IPv4 and IPv6, produce canonical textual form, reverse_ptr, and a heuristic `/24` subnet for private IPv4.
  - Hostname: RFC 1123 label rules; lowercase and strip; flag invalid labels.
  - FQDN: Validate label-by-label; ensure at least two labels; flag mismatch with hostname when both present.
  - MAC: Accepts common formats (colon, hyphen, Cisco dotted); outputs `aa:bb:cc:dd:ee:ff` canonical; flags invalid.
  - Owner: Extracts `owner_email`; heuristically parses `owner` and `owner_team` from tokens/parentheses.
  - Device type: Uses provided value if present (high confidence); otherwise heuristics then a low-temperature OpenAI call to classify ambiguous assets.
  - Site: Canonical uppercase with non-alnum normalized to `-` (and collapsed).
  - Anomalies: A list of structured records with recommended actions.

## Target Schema
ip, ip_valid, ip_version, subnet_cidr,
hostname, hostname_valid, fqdn, fqdn_consistent, reverse_ptr,
mac, mac_valid,
owner, owner_email, owner_team,
device_type, device_type_confidence,
site, site_normalized,
source_row_id, normalization_steps

## Reproducibility
1. Ensure Python 3.9+.
2. From repo root, run: `python run.py` (or `python run.py inventory_raw.csv`).
3. Outputs are written to `inventory_clean.csv` and `anomalies.json`.

## Deterministic vs. AI
Deterministic rules run first. When they cannot classify `device_type`, the pipeline calls the OpenAI API live (temperature 0.1, JSON-only response). Each interaction is logged to `documentations/prompts.md` for transparency and reproducibility. Provide the API key via `OPENAI_API_KEY` or `config/openai_api_key.txt`.

## Notes
- Special addresses: Loopback/APIPA/private/public are recognized via `ipaddress` properties.
- IPv6 support: Validated and canonicalized; reverse_ptr derived; `subnet_cidr` left empty (limitation).
