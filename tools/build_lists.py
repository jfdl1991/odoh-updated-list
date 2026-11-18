#!/usr/bin/env python3
"""Genera listas ODoH (relays y targets) en formatos legibles y de maquina.

Fuente: DNSCrypt/dnscrypt-resolvers (v3/odoh-relays.md y v3/odoh-servers.md).
Los stamps `sdns://` se decodifican a URLs https:// completas (host + puerto + ruta).

Formatos de salida por lista (<lista>.md, <lista>.txt, <lista>.json):
  .md   humano: nombre, descripcion original, URL, flags, stamp
  .txt  maquina: una URL completa por linea
  .json maquina con detalle: nombre, url, host, puerto, ruta, flags, hashes, ...

Uso:
  python tools/build_lists.py              # descarga y regenera todas las salidas
  python tools/build_lists.py --check      # descarga y solo reporta si hubo cambios
  python tools/build_lists.py --commit     # regenera y commitea/pushea si hay cambios
  python tools/build_lists.py --summary    # imprime resumen al final
  python tools/build_lists.py --offline odoh-relays=ruta.md odoh-servers=ruta.md

Sin dependencias externas (solo stdlib).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

UPSTREAM_OWNER = "DNSCrypt"
UPSTREAM_REPO = "dnscrypt-resolvers"
UPSTREAM_REF = "master"
RAW_BASE = f"https://raw.githubusercontent.com/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/{UPSTREAM_REF}/"
COMMITS_API = f"https://api.github.com/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/commits"

# Propiedades del stamp: bits de `props` (little-endian, 8 bytes).
PROP_DNSSEC = 1
PROP_NO_LOGS = 2
PROP_NO_FILTER = 4

PROTO_DOH = 0x02
PROTO_ODOH_TARGET = 0x05
PROTO_ODOH_RELAY = 0x85

LISTS: dict[str, dict] = {
    "odoh-relays": {
        "source_path": "v3/odoh-relays.md",
        "kind": "odoh-relay",
        "title": "ODoH relays",
        "expected_proto": PROTO_ODOH_RELAY,
    },
    "odoh-servers": {
        "source_path": "v3/odoh-servers.md",
        "kind": "odoh-target",
        "title": "ODoH targets",
        "expected_proto": PROTO_ODOH_TARGET,
    },
}

SECTION_RE = re.compile(r"^##\s+(.+?)\s*$")
STAMP_RE = re.compile(r"^sdns://[A-Za-z0-9_\-]+=*\s*$")


class StampError(ValueError):
    """Stamp malformado o de un protocolo no soportado."""


# --------------------------------------------------------------------------- #
# Decodificacion de stamps
# --------------------------------------------------------------------------- #

def _read_lp(buf: bytes, pos: int) -> tuple[str, int]:
    """LP(x) = len(1 byte) || x."""
    length = buf[pos]
    if length & 0x80:
        raise StampError("se esperaba LP(), se recibio VLP()")
    end = pos + 1 + length
    return buf[pos + 1:end].decode("utf-8"), end


def _read_vlp(buf: bytes, pos: int) -> tuple[list[bytes], int]:
    """VLP: elementos de longitud prefijada; el ultimo no lleva el bit 0x80."""
    items: list[bytes] = []
    while True:
        length = buf[pos]
        pos += 1
        n = length & 0x7F          # el bit 0x80 solo marca "quedan mas elementos"
        items.append(buf[pos:pos + n])
        pos += n
        if not length & 0x80:
            break
    # Un conjunto vacio se codifica como un unico byte 0x00 (longitud 0):
    # los hashes son SHA-256 (32 bytes), asi que una longitud 0 nunca es un hash real.
    if items == [b""]:
        items = []
    return items, pos


def _split_hostport(hostport: str) -> tuple[str, str]:
    """Separa 'host', 'host:puerto', '[ipv6]' y '[ipv6]:puerto'."""
    if hostport.startswith("["):
        host, sep, rest = hostport[1:].partition("]")
        if sep and rest.startswith(":"):
            return host, rest[1:]
        return host, "443"
    host, sep, port = hostport.rpartition(":")
    if sep and port.isdigit():
        return host, port
    return hostport, "443"


def _url_for(hostname: str, port: str, path: str) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port == "443":
        return f"https://{host}{path}"
    return f"https://{host}:{port}{path}"


def decode_stamp(stamp: str) -> dict:
    """Decodifica un stamp sdns:// segun https://dnscrypt.info/stamps-specifications/."""
    raw = stamp.strip()
    if not raw.startswith("sdns://"):
        raise StampError(f"no empieza con sdns://: {raw[:40]}")
    encoded = raw[len("sdns://"):]
    try:
        buf = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except Exception as exc:  # noqa: BLE001 - error de formato base64
        raise StampError(f"base64 invalido: {exc}") from exc
    if len(buf) < 9:
        raise StampError("stamp demasiado corto")

    proto = buf[0]
    props = struct.unpack("<Q", buf[1:9])[0]
    pos = 9
    out: dict = {
        "stamp": raw,
        "proto": proto,
        "props": props,
        "dnssec": bool(props & PROP_DNSSEC),
        "no_logs": bool(props & PROP_NO_LOGS),
        "no_filter": bool(props & PROP_NO_FILTER),
        "addr": "",
        "hashes": [],
    }

    if proto == PROTO_ODOH_TARGET:
        hostname, pos = _read_lp(buf, pos)
        path, pos = _read_lp(buf, pos)
    elif proto == PROTO_ODOH_RELAY:
        addr, pos = _read_lp(buf, pos)
        hashes, pos = _read_vlp(buf, pos)
        hostname, pos = _read_lp(buf, pos)
        path, pos = _read_lp(buf, pos)
        out["addr"] = addr
        out["hashes"] = [h.hex() for h in hashes]
    elif proto == PROTO_DOH:
        addr, pos = _read_lp(buf, pos)
        hashes, pos = _read_vlp(buf, pos)
        hostname, pos = _read_lp(buf, pos)
        path, pos = _read_lp(buf, pos)
        out["addr"] = addr
        out["hashes"] = [h.hex() for h in hashes]
    else:
        raise StampError(f"protocolo 0x{proto:02x} no soportado")

    host, port = _split_hostport(hostname)
    out["hostname"] = host
    out["port"] = int(port)
    out["path"] = path
    out["url"] = _url_for(host, port, path)
    return out


# --------------------------------------------------------------------------- #
# Parseo de las listas .md
# --------------------------------------------------------------------------- #

def parse_list_md(text: str, kind: str) -> list[dict]:
    """Secciones '## nombre' seguidas de descripcion, URL del sitio y stamp."""
    entries: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        stripped = line.strip()
        match = SECTION_RE.match(stripped)
        if match:
            current = {"name": match.group(1), "kind": kind,
                       "description": [], "site": "", "stamp": ""}
            entries.append(current)
            continue
        if current is None or not stripped:
            continue
        if STAMP_RE.match(stripped):
            current["stamp"] = stripped
        elif stripped.startswith(("http://", "https://")):
            current["site"] = stripped
        else:
            current["description"].append(stripped)

    for entry in entries:
        if entry["stamp"]:
            entry.update(decode_stamp(entry["stamp"]))
    return entries


# --------------------------------------------------------------------------- #
# Salida
# --------------------------------------------------------------------------- #

def _flags_line(entry: dict) -> str:
    flags = []
    if entry["dnssec"]:
        flags.append("DNSSEC")
    if entry["no_logs"]:
        flags.append("sin logs")
    if entry["no_filter"]:
        flags.append("sin filtro")
    return ", ".join(flags) if flags else "sin anotaciones"


def write_markdown(list_key: str, cfg: dict, entries: list[dict], outdir: str) -> None:
    path = os.path.join(outdir, f"{list_key}.md")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# {cfg['title']} - URLs completas\n\n")
        fh.write(f"Generado desde `{UPSTREAM_OWNER}/{UPSTREAM_REPO}` "
                 f"(`{UPSTREAM_REF}/{cfg['source_path']}`).\n\n")
        fh.write(f"Total: {len(entries)} entradas.\n\n")
        for entry in entries:
            fh.write(f"## {entry['name']}\n\n")
            for desc in entry["description"]:
                fh.write(f"{desc}\n")
            if entry["description"]:
                fh.write("\n")
            fh.write(f"- URL: {entry['url']}\n")
            fh.write(f"- Flags: {_flags_line(entry)}\n")
            fh.write(f"- Stamp: `{entry['stamp']}`\n\n")


def write_txt(list_key: str, entries: list[dict], outdir: str) -> None:
    path = os.path.join(outdir, f"{list_key}.txt")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for entry in entries:
            fh.write(f"{entry['url']}\n")


def write_json(list_key: str, cfg: dict, entries: list[dict], outdir: str,
               raw_sha256: str, upstream_commit: str | None) -> None:
    payload = {
        "name": list_key,
        "kind": cfg["kind"],
        "source": f"{UPSTREAM_OWNER}/{UPSTREAM_REPO}/{UPSTREAM_REF}/{cfg['source_path']}",
        "source_sha256": raw_sha256,
        "upstream_commit": upstream_commit,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "count": len(entries),
        "entries": entries,
    }
    path = os.path.join(outdir, f"{list_key}.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


# --------------------------------------------------------------------------- #
# Descarga y estado
# --------------------------------------------------------------------------- #

def fetch_raw(source_path: str) -> bytes:
    url = RAW_BASE + source_path
    req = urllib.request.Request(url, headers={"User-Agent": "odoh-updated-list/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - URL fija y conocida
        return resp.read()


def fetch_upstream_commit(source_path: str) -> str | None:
    """Ultimo commit que toco el archivo (1 llamada a la API de GitHub)."""
    url = f"{COMMITS_API}?path={source_path}&per_page=1"
    req = urllib.request.Request(url, headers={
        "User-Agent": "odoh-updated-list/1.0",
        "Accept": "application/vnd.github+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            data = json.loads(resp.read())
        if isinstance(data, list) and data:
            return data[0].get("sha")
    except Exception:  # noqa: BLE001 - opcional: la lista igual se genera
        return None
    return None


def load_state(outdir: str) -> dict:
    path = os.path.join(outdir, "state.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_state(outdir: str, state: dict) -> None:
    path = os.path.join(outdir, "state.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


# --------------------------------------------------------------------------- #
# Flujo principal
# --------------------------------------------------------------------------- #

def build(list_key: str, cfg: dict, outdir: str, offline: str | None,
          with_commit_sha: bool) -> dict:
    if offline:
        with open(offline, "rb") as fh:
            raw = fh.read()
    else:
        raw = fetch_raw(cfg["source_path"])
    sha256 = hashlib.sha256(raw).hexdigest()
    entries = parse_list_md(raw.decode("utf-8"), cfg["kind"])
    missing = [e["name"] for e in entries if not e["stamp"]]
    if missing:
        raise SystemExit(f"[{list_key}] entradas sin stamp: {missing}")

    commit_sha = fetch_upstream_commit(cfg["source_path"]) if with_commit_sha else None
    write_markdown(list_key, cfg, entries, outdir)
    write_txt(list_key, entries, outdir)
    write_json(list_key, cfg, entries, outdir, sha256, commit_sha)
    return {"sha256": sha256, "count": len(entries), "commit": commit_sha}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="solo descargar y reportar si el contenido cambio")
    parser.add_argument("--commit", action="store_true",
                        help="commitear y pushear si hay cambios")
    parser.add_argument("--summary", action="store_true", help="imprimir resumen")
    parser.add_argument("--no-commit-sha", action="store_true",
                        help="no consultar el SHA del commit upstream")
    parser.add_argument("--outdir", default=os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), help="carpeta de salida (por defecto: raiz del repo)")
    parser.add_argument("--offline", action="append", default=[], metavar="LISTA=RUTA",
                        help="usar un archivo local en vez de descargar (por lista)")
    args = parser.parse_args(argv)

    offline_map = dict(item.split("=", 1) for item in args.offline)
    previous = load_state(args.outdir)
    changed = []
    results: dict[str, dict] = {}

    for list_key, cfg in LISTS.items():
        offline = offline_map.get(list_key)
        raw_local = None
        if offline:
            with open(offline, "rb") as fh:
                raw_local = fh.read()
            sha = hashlib.sha256(raw_local).hexdigest()
        else:
            sha = hashlib.sha256(fetch_raw(cfg["source_path"])).hexdigest()
        prev_sha = (previous.get("lists", {}).get(list_key) or {}).get("raw_sha256")
        if prev_sha != sha:
            changed.append(list_key)
        results[list_key] = {"sha256": sha}

    if args.check:
        print(f"changed={'true' if changed else 'false'}")
        for list_key in LISTS:
            print(f"  {list_key}: {results[list_key]['sha256'][:12]}"
                  f" ({'nuevo' if list_key in changed else 'sin cambios'})")
        return 0

    for list_key, cfg in LISTS.items():
        info = build(list_key, cfg, args.outdir, offline_map.get(list_key),
                     with_commit_sha=not args.no_commit_sha)
        results[list_key] = info

    state = {
        "upstream": {"owner": UPSTREAM_OWNER, "repo": UPSTREAM_REPO, "ref": UPSTREAM_REF},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "lists": {
            key: {"raw_sha256": val["sha256"], "count": val["count"],
                  "upstream_commit": val["commit"]}
            for key, val in results.items()
        },
    }
    save_state(args.outdir, state)

    if args.summary:
        for key, val in results.items():
            print(f"{key}: {val['count']} entradas, sha256 {val['sha256'][:12]}"
                  + (f", commit {val['commit'][:12]}" if val["commit"] else ""))

    if args.commit and changed:
        git = ["git", "-C", args.outdir,
               "-c", "user.name=github-actions[bot]",
               "-c", "user.email=github-actions[bot]@users.noreply.github.com"]
        subprocess.run(git + ["add", "-A"], check=True)
        if subprocess.run(git + ["diff", "--cached", "--quiet"]).returncode != 0:
            msg = (f"Update ODoH lists ({', '.join(changed)})\n\n"
                   + "\n".join(f"- {k}: {results[k]['count']} entradas" for k in changed))
            subprocess.run(git + ["commit", "-m", msg], check=True)
            subprocess.run(git + ["push"], check=True)
            print(f"cambiado: {', '.join(changed)} (commiteado y pusheado)")
            return 0
    if args.commit:
        print("sin cambios: no hay commit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
