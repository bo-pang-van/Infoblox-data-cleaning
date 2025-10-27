# prompts.md

Entries are appended automatically by `run.py` whenever the pipeline calls an LLM. Each entry includes the full prompt, response, and a fingerprint so duplicate requests are skipped. Delete entries manually only if you want to re-run the pipeline and capture fresh logs.
---
Date: 2025-10-27T22:19:01.246680Z
Context: Device type classification for source_row_id 15
Fingerprint: a690a225dfce19b7628ee0ee62bfbc86dc2d8e5c3b72b2b196c5c247da803402
Prompt:
"""
You are a precise network inventory classifier. Choose one device_type from ["server","router","switch","printer","iot","unknown"]. Return JSON {"device_type": string, "device_type_confidence": one_of["low","medium","high"], "reason": string}. Do not include any explanatory prose outside the JSON object.
Input: {"fqdn": "", "hostname": "missing-ip", "ip": "N/A", "mac": "", "notes": "", "owner": "", "site": "", "source_row_id": "15"}
"""
Constraints: temperature=0.1; JSON-only output; model=gpt-4o-mini
Expected JSON schema: {device_type: string, device_type_confidence: string, reason: string}
Rationale: Deterministic rules could not determine device_type; escalating to LLM for guidance.
Response:
```json
{
  "device_type": "unknown",
  "device_type_confidence": "high",
  "reason": "Insufficient information provided to classify the device."
}
```
---
