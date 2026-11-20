# ODoH over HTTPS — full URL lists

**English** · [Español](#espanol)

Derived from [DNSCrypt/dnscrypt-resolvers](https://github.com/DNSCrypt/dnscrypt-resolvers)
(`v3/odoh-relays.md` and `v3/odoh-servers.md`, `master`).

This repository converts the `sdns://` DNS stamps published by DNSCrypt into
**complete `https://` URLs** (host, port and path), so they can be consumed by
clients and tools that are **not** `dnscrypt-proxy` and only speak HTTPS.

It also keeps the original DNSCrypt stamp data alongside, for anyone who needs it.

## Generated files

| File | Content | Use |
|---|---|---|
| `odoh-relays.txt` / `odoh-servers.txt` | one full URL per line | scripts and tools |
| `odoh-relays.json` / `odoh-servers.json` | all fields, including the original stamp data | apps that want detail |
| `odoh-relays.md` / `odoh-servers.md` | name, description, URL, flags, location | human reading |
| `state.json` | source hash, counts, last upstream commit | change detection without parsing |

The `.txt` files are the simplest form: one `https://` URL per line. The `.json`
files contain the decoded endpoint **and** the original DNSCrypt stamp fields,
so nothing is lost.

### Example entry (`odoh-servers.json`)

```json
{
  "name": "dnscry.pt-odoh-adelaide",
  "kind": "target",
  "location": { "city": "Adelaide", "country": "AU", "anycast": false, "source": "name" },
  "stamp": "sdns://BQcAAAAAAAAAD2FkbDAxLmRuc2NyeS5wdAovZG5zLXF1ZXJ5",
  "url": "https://adl01.dnscry.pt/dns-query",
  "hostname": "adl01.dnscry.pt",
  "port": 443,
  "path": "/dns-query",
  "dnssec": true,
  "no_logs": true,
  "no_filter": true,
  "proto": 5,
  "props": 7,
  "addr": "",
  "hashes": [],
  "description": ["dnscry.pt Adelaide ODoH target.", "..."],
  "site": "https://www.dnscry.pt"
}
```

### Fields

| Field | Meaning |
|---|---|
| `kind` | `target` or `proxy` (RFC 9230 terminology), derived from the stamp protocol |
| `url` | complete endpoint: `https://<host>[:port]<path>` |
| `hostname`, `port`, `path` | the parts of the URL |
| `dnssec`, `no_logs`, `no_filter` | decoded from the stamp `props` bits (1 / 2 / 4) |
| `proto`, `props`, `addr`, `hashes` | raw DNSCrypt stamp fields, kept for compatibility |
| `location` | operator-declared location (see below) |
| `stamp` | the original `sdns://` string |

### Location

`location` is **operator-declared metadata**, never IP geolocation. It comes from
the description text plus `tools/locations.json` (a curated city → country
table), and it is never guessed:

| `source` | Meaning |
|---|---|
| `name` | city taken from the entry name + country resolved from the table |
| `description` | country or "anycast" detected in the description text |
| `unknown` | the operator does not say where the server is |

- `country` is ISO 3166-1 alpha-2 (`"AU"`, `"DE"`, ...) or `null` when unknown.
- `anycast` is `true` when the text indicates global distribution (Cloudflare,
  crypto.sx, tiarap, ...).
- A sample of 22 cities was verified against the official dnscry.pt pages
  (`/public-resolvers/<code>`); all 22 matched. A newly added city that is not
  in the table gets `country: null` and the tests report it.

## How it updates

`.github/workflows/update.yml` regenerates the lists and commits only when the
upstream content changed. It runs:

- once a day (`schedule`), exiting early when nothing changed;
- manually (`workflow_dispatch`);
- via `repository_dispatch` (`upstream-change`), so an external service can wake it up;
- on changes to `tools/` or the workflow itself.

GitHub Actions is free for public repositories.

```bash
# force an update from outside
gh api -X POST repos/<owner>/<repo>/dispatches -f event_type=upstream-change
```

## Local use

```bash
python tools/build_lists.py          # download and regenerate everything
python tools/build_lists.py --check  # only report whether the source changed
python tools/build_lists.py --commit # regenerate and push if there are changes
```

No dependencies: Python 3.9+ standard library only.

## Tests

```bash
python -m unittest discover -s tests -v
```

## License

The code in this repository is yours to use. The data comes from
[DNSCrypt/dnscrypt-resolvers](https://github.com/DNSCrypt/dnscrypt-resolvers),
which is distributed under its own terms; check that repository before
redistributing the data.

---

# Español

Derivado de [DNSCrypt/dnscrypt-resolvers](https://github.com/DNSCrypt/dnscrypt-resolvers)
(`v3/odoh-relays.md` y `v3/odoh-servers.md`, rama `master`).

Este repositorio convierte los stamps `sdns://` que publica DNSCrypt en
**URLs `https://` completas** (host, puerto y ruta), para que las puedan consumir
clientes y herramientas que **no** son `dnscrypt-proxy` y solo hablan HTTPS.

También conserva los datos originales del stamp DNSCrypt, por si alguien los necesita.

## Archivos generados

| Archivo | Contenido | Para qué |
|---|---|---|
| `odoh-relays.txt` / `odoh-servers.txt` | una URL completa por línea | scripts y herramientas |
| `odoh-relays.json` / `odoh-servers.json` | todos los campos, incluidos los del stamp original | apps que quieren detalle |
| `odoh-relays.md` / `odoh-servers.md` | nombre, descripción, URL, flags, ubicación | lectura humana |
| `state.json` | hash del origen, conteos, último commit upstream | detectar cambios sin parsear |

Los `.txt` son la forma más simple: una URL `https://` por línea. Los `.json`
incluyen el endpoint decodificado **y** los campos del stamp DNSCrypt original.

### Campos

| Campo | Significado |
|---|---|
| `kind` | `target` o `proxy` (terminología del RFC 9230), derivado del protocolo del stamp |
| `url` | endpoint completo: `https://<host>[:puerto]<ruta>` |
| `hostname`, `port`, `path` | las partes de la URL |
| `dnssec`, `no_logs`, `no_filter` | decodificados de los bits de `props` del stamp (1 / 2 / 4) |
| `proto`, `props`, `addr`, `hashes` | campos crudos del stamp DNSCrypt, por compatibilidad |
| `location` | ubicación declarada por el operador (ver abajo) |
| `stamp` | el string `sdns://` original |

### Ubicación

`location` es **metadato declarado por el operador**, nunca geolocalización por
IP. Se deriva del texto de la descripción más `tools/locations.json` (una tabla
curada de ciudad → país) y nunca se adivina:

| `source` | Significado |
|---|---|
| `name` | ciudad tomada del nombre de la entrada + país resuelto con la tabla |
| `description` | país o "anycast" detectado en el texto de la descripción |
| `unknown` | el operador no dice dónde está el servidor |

- `country` es ISO 3166-1 alpha-2 (`"AU"`, `"DE"`, ...) o `null` si no se sabe.
- `anycast` es `true` cuando el texto indica distribución global (Cloudflare,
  crypto.sx, tiarap, ...).
- Una muestra de 22 ciudades se verificó contra las fichas oficiales de dnscry.pt
  (`/public-resolvers/<código>`); las 22 coincidieron. Una ciudad nueva que no
  esté en la tabla recibe `country: null` y los tests la reportan.

## Cómo se actualiza

`.github/workflows/update.yml` regenera las listas y commitea solo si cambió el
contenido origen. Se ejecuta:

- una vez al día (`schedule`), con salida temprana si no hay novedad;
- manualmente (`workflow_dispatch`);
- por `repository_dispatch` (`upstream-change`), para que un servicio externo lo despierte;
- al cambiar `tools/` o el propio workflow.

GitHub Actions es gratis en repositorios públicos.

```bash
# forzar una actualización desde fuera
gh api -X POST repos/<dueño>/<repo>/dispatches -f event_type=upstream-change
```

## Uso local

```bash
python tools/build_lists.py          # descarga y regenera todo
python tools/build_lists.py --check  # solo indica si cambió el origen
python tools/build_lists.py --commit # regenera y pushea si hay cambios
```

Sin dependencias: solo Python 3.9+ (stdlib).

## Tests

```bash
python -m unittest discover -s tests -v
```

## Licencia

El código de este repositorio es tuyo. Los datos provienen de
[DNSCrypt/dnscrypt-resolvers](https://github.com/DNSCrypt/dnscrypt-resolvers),
que se distribuye bajo sus propios términos; revisa ese repositorio antes de
redistribuir los datos.
