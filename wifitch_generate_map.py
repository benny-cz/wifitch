#!/usr/bin/env python3
"""
WiFitch ZIP-decryptor & visualiser
----------------------------------
Opens a WiFitch export ZIP and decrypts all recordings automatically.
– If the ZIP contains a device key, it tries that first.
– If that yields no records and a salt is present, it quietly retries with your pass-phrase.
– The first attempt’s failures are downgraded to INFO when a fallback is possible
– You’re asked for your pass-phrase only when needed.
"""

import argparse, base64, getpass, json, logging, re, struct, sys, tempfile, traceback, zipfile
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from colorama import Fore, Style, init as colorama_init
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import folium
from folium.plugins import HeatMap

# ═════════════════════════════════════════════ logging ═════════════════════════════════════════════
class ColourFormatter(logging.Formatter):
    COLORS = {logging.INFO: Fore.GREEN, logging.WARNING: Fore.YELLOW, logging.ERROR: Fore.RED}
    def format(self, rec):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level = f"{self.COLORS.get(rec.levelno,'')}{rec.levelname}{Style.RESET_ALL}"
        return f"{ts}\t{level}\t{super().format(rec)}"

def setup_logging():
    colorama_init()
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(ColourFormatter("%(message)s"))
    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger().addHandler(h)

# ════════════════════════════════════════════ constants ════════════════════════════════════════════
TAG_LEN, NONCE_LEN, FRAME_HDR = 16, 12, 4
POPUP_WIDTH = 1100
PBKDF2_ITERATIONS = 200_000
DERIVED_KEY_LEN = 32

# ═════════════════════════════════════════════ decrypt ═════════════════════════════════════════════
def decrypt_stream(enc: Path, key: bytes, json_out: Path, log,
                   err_level=logging.ERROR):
    """
    Decrypts one .enc file with a provided key.
    Returns (coords_with_gps, details, records_count).
    - records_count > 0  => decryption produced at least one record (success)
    - coords_with_gps    => only frames with GPS (used for heat-maps)
    """
    aes = AESGCM(key)
    coords, details = [], []
    recs = 0
    with enc.open('rb') as f, json_out.open('w', encoding='utf-8') as j:
        idx = 0
        while hdr := f.read(FRAME_HDR):
            if len(hdr) < FRAME_HDR:
                log.warning(f"{enc.name}: header truncated")
                break
            frame_len, = struct.unpack("<I", hdr)
            payload = f.read(frame_len)
            if len(payload) != frame_len:
                log.warning(f"{enc.name}: frame truncated")
                break
            nonce  = payload[:NONCE_LEN]
            tag    = payload[NONCE_LEN:NONCE_LEN+TAG_LEN]
            cipher = payload[NONCE_LEN+TAG_LEN:]
            try:
                plain = aes.decrypt(nonce, cipher + tag, b'')
            except Exception as ex:
                log.log(err_level, f"{enc.name}: decrypt failed – {ex}")
                continue
            txt = plain.decode()
            j.write(txt + "\n")
            recs += 1
            try:
                obj = json.loads(txt)
                gps = obj.get("Gps") or {}
                lat, lng = gps.get("Latitude"), gps.get("Longitude")
                if lat is not None and lng is not None:
                    coords.append((lat, lng))
                    details.append((idx, obj))
            except Exception as ex:
                log.warning(f"{enc.name}: malformed JSON – {ex}")
            idx += 1
    log.info(f"{enc.name}: {recs} records, {len(coords)} with GPS")
    return coords, details, recs

# ──────────────────── timestamp helpers ────────────────────
def timestamp_from_json_path(json_path: Path):
    """
    Extract 'YYYYMMDD_HHMMSS' from a JSON file's stem (e.g.
    wifitch_20250609_195154.json → 20250609_195154). Falls back to
    current time if pattern not found.
    """
    m = re.search(r'_(\d{8})_(\d{6})$', json_path.stem)
    if m:
        return f"{m.group(1)}_{m.group(2)}"
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def nice_time(iso: str):
    try:
        base = iso.split('.')[0].rstrip('Z')
        return datetime.fromisoformat(base).replace(tzinfo=timezone.utc)\
                   .astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso

# ───────────────────────── HTML helpers ────────────────────
SORT_JS = """<script>
if(!window.wifitchSort){
window.wifitchSort=true;
function sortTable(id,col,th){
  const tbl=document.getElementById(id);
  let dir=tbl.getAttribute('data-dir')==='asc'?'desc':'asc';
  const rows=[...tbl.tBodies[0].rows];
  const num=th.getAttribute('data-type')==='num';
  rows.sort((a,b)=>{let x=a.cells[col].innerText.trim(),y=b.cells[col].innerText.trim();
    if(num){x=parseFloat(x)||0;y=parseFloat(y)||0;}
    return dir==='asc'?(x>y)-(x<y):(y>x)-(y<x);});
  rows.forEach(r=>tbl.tBodies[0].appendChild(r));
  tbl.setAttribute('data-dir',dir);
  [...tbl.tHead.rows[0].cells].forEach(c=>{const s=c.querySelector('.arrow');if(s)s.textContent='';});
  const arrow=th.querySelector('.arrow');if(arrow)arrow.textContent=dir==='asc'?'↑':'↓';
}}
</script>"""

def build_table(tid, batch):
    nets = batch.get("Networks", [])
    if not nets:
        return "<p><em>No networks.</em></p>"

    cols = [
        ("SSID",            "str"),
        ("BSSID",           "str"),
        ("Manufacturer",    "str"),
        ("Capabilities",    "str"),
        ("Frequency",       "str"),  # uses FrequencyString
        ("SignalStrength",  "num"),
        ("Channel",         "num"),  # uses ChannelString
        ("ChannelWidth",    "num"),  # uses ChannelWidthString
        ("PhyType",         "str"),
        ("Dot11Standards",  "str"),
    ]

    alias = {
        "Frequency":    "FrequencyString",
        "Channel":      "ChannelString",
        "ChannelWidth": "ChannelWidthString",
    }

    head = "".join(
        f"<th data-type='{typ}' onclick=\"sortTable('{tid}',{i},this)\" "
        f"style='padding:8px 12px;white-space:nowrap;cursor:pointer;'>"
        f"{escape(name)}<span class='arrow' style='margin-left:4px'></span></th>"
        for i, (name, typ) in enumerate(cols))

    rows = []
    for n in nets:
        tds = []
        for name, _ in cols:
            key   = alias.get(name, name)
            val   = escape(str(n.get(key, '')))
            style = ("padding:6px 12px;white-space:nowrap;"
                     if name in ("SSID", "BSSID") else
                     "padding:6px 12px;")
            if name == "SSID":
                style += "font-size:13px;font-weight:bold;"
            tds.append(f"<td style='{style}'>{val}</td>")
        rows.append("<tr>" + ''.join(tds) + "</tr>")

    return (f"<table id='{tid}' style='border-collapse:collapse;width:100%;font-size:12px;text-align:left;"
            "background:rgba(250,250,250,0.9);'>"
            f"<thead style='background:rgba(220,224,228,0.9)'><tr>{head}</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>")

# ──────────────────────── map generation ───────────────────
def gen_map(coords, details, out_dir: Path, out_name: str, log):
    log.info(f"Building map '{out_name}'...")
    m = folium.Map(location=coords[0], zoom_start=15)
    HeatMap(coords, radius=15).add_to(m)
    folium.PolyLine(coords, weight=2).add_to(m)

    legend_items = []

    for (lat, lng), (idx, obj) in zip(coords, details):
        tid = f"tbl_{idx}"
        table = build_table(tid, obj)
        nrows = len(obj.get("Networks", []))
        height = min(140 + nrows * 28, 700)

        popup_html = (SORT_JS +
                      f"<div style='width:{POPUP_WIDTH-40}px;'>"
                      f"<h4 style='margin:4px 0'>Measurement #{idx}</h4>"
                      f"<p style='margin:4px 0'><small>{escape(nice_time(obj.get('TimestampUtc','')))}</small></p>"
                      f"{table}</div>")

        iframe = folium.IFrame(popup_html, width=POPUP_WIDTH, height=height)
        marker = folium.Marker(location=(lat, lng),
                               popup=folium.Popup(iframe, max_width=POPUP_WIDTH),
                               tooltip=f"Measurement #{idx}")
        marker.add_to(m)

        legend_items.append(
            f"<li style='cursor:pointer;padding:2px 4px;' "
            f"onclick='openMeasurement({idx})'>Measurement #{idx}</li>")

    legend_html = (
        "<div id='wifitchLegend' "
        "style='position:absolute;top:10px;right:10px;z-index:9999;"
        "background:white;font-size:13px;padding:6px 8px;border:1px solid #999;"
        "max-height:300px;overflow:auto;cursor:move;'>"
        "<b style='user-select:none;'>Measurements</b>"
        "<hr style='margin:4px 0'>"
        "<ul style='list-style:none;margin:0;padding:0;'>" +
        "".join(legend_items) +
        "</ul></div>"
    )
    m.get_root().html.add_child(folium.Element(legend_html))

    helper_js = (
        "<script>"
        "window.measureMarkers = [];"
        "window.addEventListener('load', () => {"
        "  for (const k in window) {"
        "    if(k.startsWith('marker_')){"
        "      const mk = window[k];"
        "      if(mk && mk.getTooltip && mk.getTooltip()){"
        "        const m = /Measurement #(\\d+)/.exec(mk.getTooltip()._content);"
        "        if(m){ window.measureMarkers[parseInt(m[1])] = mk; }"
        "      }"
        "    }"
        "  }"
        "  const lg = document.getElementById('wifitchLegend');"
        "  if(lg){"
        "     let pos1=0,pos2=0,pos3=0,pos4=0;"
        "     lg.onmousedown = dragMouseDown;"
        "     function dragMouseDown(e){"
        "       e = e || window.event; e.preventDefault();"
        "       const rect = lg.getBoundingClientRect();"
        "       lg.style.left  = rect.left + 'px';"
        "       lg.style.top   = rect.top  + 'px';"
        "       lg.style.right = 'auto';"
        "       pos3 = e.clientX; pos4 = e.clientY;"
        "       document.onmouseup = closeDragElement;"
        "       document.onmousemove = elementDrag;"
        "     }"
        "     function elementDrag(e){"
        "       e = e || window.event; e.preventDefault();"
        "       pos1 = pos3 - e.clientX; pos2 = pos4 - e.clientY;"
        "       pos3 = e.clientX; pos4 = e.clientY;"
        "       lg.style.top  = (lg.offsetTop - pos2) + 'px';"
        "       lg.style.left = (lg.offsetLeft - pos1) + 'px';"
        "       lg.style.right = 'auto';"
        "     }"
        "     function closeDragElement(){"
        "       document.onmouseup = null; document.onmousemove = null;"
        "     }"
        "  }"
        "});"
        "function openMeasurement(i){"
        "  const mk = window.measureMarkers[i];"
        "  if(mk && mk._map){ mk.openPopup(); mk._map.setView(mk.getLatLng(), mk._map.getZoom()); }"
        "}"
        "</script>"
    )
    m.get_root().html.add_child(folium.Element(helper_js))

    out_html = out_dir / out_name
    m.save(out_html)
    log.info(f"Heat-map saved to {out_html}")

# ───────────────────────── main ────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("zipfile", help="input WiFitch export ZIP")
    parser.add_argument("outdir", nargs='?', help="optional output directory")
    args = parser.parse_args()

    setup_logging()
    log = logging.getLogger()

    zip_path = Path(args.zipfile).resolve()

    # determine output directory
    if args.outdir:
        out_dir = Path(args.outdir).resolve()
        log.info(f"Using specified output directory: {out_dir}")
    else:
        out_dir = zip_path.with_suffix('').resolve()
        log.info(f"No output directory provided – defaulting to {out_dir}")

    out_dir.mkdir(parents=True, exist_ok=True)

    # extract timestamp from ZIP filename (for aggregate map)
    ts_match = re.search(r'_(\d{8})_(\d{6})\.zip$', zip_path.name)
    ts_str = f"{ts_match.group(1)}_{ts_match.group(2)}" if ts_match else "unknown"
    if ts_match:
        log.info(f"Timestamp '{ts_str}' extracted from ZIP filename")
    else:
        log.warning("Could not extract timestamp – using 'unknown' suffix")
    map_filename = f"wifitch_heatmap_{ts_str}.html"

    with tempfile.TemporaryDirectory() as tdir:
        tmp = Path(tdir)
        zipfile.ZipFile(zip_path).extractall(tmp)

        # discover assets
        enc_files = sorted(tmp.glob("wifitch_*.enc"))
        key_path  = tmp / "wifitch_key.txt"
        salt_path = tmp / "wifitch_salt.txt"

        have_key  = key_path.exists()
        have_salt = salt_path.exists()

        key: bytes | None = None
        pass_key  : bytes | None = None
        salt: bytes | None = None

        if have_key:
            key = base64.b64decode(key_path.read_text().strip())
            log.info("Found ‘wifitch_key.txt’ – symmetric key available.")

        if have_salt:
            salt_b64 = salt_path.read_text().strip()
            salt = base64.b64decode(salt_b64)
            log.info("Salt read from ‘wifitch_salt.txt’.")
        else:
            salt = None  # no pass-phrase fallback possible without salt (we won't prompt)

        # decrypt every .enc file
        coords, details = [], []
        dataset_count   = 0  # counts datasets that produced GPS data

        for enc in enc_files:
            json_out = out_dir / f"{enc.stem}.json"

            # ── First attempt: KEY (if present) ───────────────────────────────
            enc_coords = []
            enc_details = []
            enc_recs = 0
            decrypt_ok = False

            if key:
                # downgrade decrypt errors to INFO ONLY if pass-phrase fallback is possible (salt present)
                lvl = logging.INFO if salt is not None else logging.ERROR
                log.info(f"Decrypting {enc.name} with key...")
                enc_coords, enc_details, enc_recs = decrypt_stream(enc, key, json_out, log, err_level=lvl)
                decrypt_ok = enc_recs > 0

            # ── Fallback: ask pass-phrase only if key produced zero records ──
            if not decrypt_ok and salt is not None:
                if pass_key is None:
                    passphrase = getpass.getpass("Enter pass-phrase: ")
                    if not passphrase:
                        log.error("Empty pass-phrase entered – aborting.")
                        sys.exit(1)
                    kdf = PBKDF2HMAC(
                        algorithm = hashes.SHA512(),
                        length     = DERIVED_KEY_LEN,
                        salt       = salt,
                        iterations = PBKDF2_ITERATIONS,
                    )
                    pass_key = kdf.derive(passphrase.encode())
                    log.info("Key successfully derived from pass-phrase.")

                log.info(f"Retrying {enc.name} with pass-phrase key...")
                enc_coords, enc_details, enc_recs = decrypt_stream(enc, pass_key, json_out, log)
                decrypt_ok = enc_recs > 0

            # ── Results / mapping ────────────────────────────────────────────
            if decrypt_ok and enc_coords:
                dataset_count += 1
                coords.extend(enc_coords)
                details.extend(enc_details)
                log.info(f"{enc.name}: JSON saved to {json_out}")

                # per-JSON heat-map
                ts_json = timestamp_from_json_path(json_out)
                per_map_name = f"wifitch_heatmap_{ts_json}.html"
                gen_map(enc_coords, enc_details, out_dir, per_map_name, log)
            elif decrypt_ok and not enc_coords:
                log.info(f"{enc.name}: decrypted with 0 GPS frames – no heat-map generated.")
            else:
                log.warning(f"{enc.name}: decryption unsuccessful – skipping.")

        # aggregate heat-map (only if >1 dataset with GPS)
        if dataset_count > 1 and coords:
            gen_map(coords, details, out_dir, map_filename, log)
        elif dataset_count == 1:
            log.info("Single dataset detected – aggregate heat-map skipped.")
        else:
            log.warning("No GPS data – heat-map not generated.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        logging.getLogger().warning("Interrupted by user.")
    except Exception as exc:
        traceback.print_exc()
        logging.getLogger().error(f"Unhandled exception – {exc}")
