# WiFitch Export Decryptor & Map

A tiny utility to **decrypt WiFitch export ZIPs** and **generate interactive heat-maps** from the recorded GPS data.

## What it does
- Reads a WiFitch export `.zip` (with one or more `wifitch_*.enc` recordings).
- Supports exports that use a **device key** and/or a **pass-phrase**.
- Writes decrypted **JSON** files and one **interactive HTML heat-map** per dataset.
- Optionally creates an **aggregate** heat-map when there are multiple datasets with GPS.

## Requirements
- **Python 3.10+**
- Packages: `cryptography`, `folium`, `colorama`

Install:
```bash
python -m pip install cryptography folium colorama
```

## Usage
```bash
python wifitch_generate_map.py <export.zip> [output_dir]
```

- If `output_dir` is **omitted**, the script creates a directory next to the ZIP with the same name (without the `.zip` suffix).
- If the export requires a pass-phrase, you’ll be prompted in the terminal.

## Inputs
A typical WiFitch export ZIP may contain:
- One or more encrypted recordings: `wifitch_*.enc`
- Optional device key: `wifitch_key.txt` (Base64)
- Optional salt: `wifitch_salt.txt` (Base64)

The script handles both key-based and pass-phrase-based exports.

## Outputs
In the output directory you’ll find:
- `wifitch_*.json` — decrypted, newline-delimited JSON for each `.enc`
- `wifitch_heatmap_<json_timestamp>.html` — per-dataset heat-map (if GPS data present)
- `wifitch_heatmap_<zip_timestamp>.html` — aggregate heat-map (created **only** when >1 dataset has GPS)

Example:
```text
output/
├─ wifitch_20250924_135429.json
├─ wifitch_heatmap_20250924_135429.html
└─ wifitch_heatmap_20250924_135436.html    # aggregate (only if >1 dataset with GPS)
```

**Notes**
- If a dataset has no GPS points, a heat-map for it is not generated.
- The script does not modify the input ZIP.

## License
MIT
