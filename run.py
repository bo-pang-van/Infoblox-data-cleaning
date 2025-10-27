#!/usr/bin/env python3
"""
End-to-end runner to validate, normalize, and enrich inventory data.

Outputs:
- inventory_clean.csv
- anomalies.json

Usage:
  python run.py [inventory_raw.csv]
"""
from pathlib import Path
import sys

from src.pipeline import process_inventory


def main():
    here = Path(__file__).parent
    in_csv = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "inventory_raw.csv"
    out_csv = here / "inventory_clean.csv"
    anomalies_json = here / "anomalies.json"

    process_inventory(in_csv, out_csv, anomalies_json)
    print(f"Wrote {out_csv} and {anomalies_json}")


if __name__ == "__main__":
    main()

