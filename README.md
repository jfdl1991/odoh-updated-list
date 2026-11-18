# ODoH updated list

Listas de relays y targets de Oblivious DNS-over-HTTPS (ODoH) derivadas de
[DNSCrypt/dnscrypt-resolvers](https://github.com/DNSCrypt/dnscrypt-resolvers),
con los stamps `sdns://` decodificados a **URLs `https://` completas** (host, puerto y ruta).

Fuente: `v3/odoh-relays.md` y `v3/odoh-servers.md` (rama `master`).

## Archivos generados

| Archivo | Contenido | Para qué |
|---|---|---|
| `odoh-relays.txt` / `odoh-servers.txt` | una URL completa por línea | consumo por programa |
| `odoh-relays.json` / `odoh-servers.json` | array con todos los campos | consumo con niveles de detalle |
| `odoh-relays.md` / `odoh-servers.md` | nombre, descripción original, URL y flags | lectura humana |
| `state.json` | hash del origen, conteos y último commit upstream | detectar novedad sin parsear |

Ejemplo de entrada en el `.json`:

```json
{
  "name": "odohrelay-numa",
  "kind": "proxy",
  "location": { "city": null, "country": "DE", "anycast": false, "source": "description" },
  "stamp": "sdns://hQcAAAAAAAAAAAASb2RvaC1yZWxheS5udW1hLnJzBi9yZWxheQ",
  "url": "https://odoh-relay.numa.rs/relay",
  "hostname": "odoh-relay.numa.rs",
  "port": 443,
  "path": "/relay",
  "dnssec": true,
  "no_logs": true,
  "no_filter": true,
  "description": ["Numa ODoH relay.", "..."],
  "site": ""
}
```

### Notas sobre los datos

- El endpoint sale del **stamp**, no de la URL de "página del servicio" que a veces
  aparece en el `.md` original (por ejemplo `https://www.dnscry.pt` no es el endpoint).
- `kind` es `target` o `proxy` (terminología del RFC 9230), derivado del protocolo
  del stamp (`0x05` / `0x85`).
- `dnssec` / `no_logs` / `no_filter` salen de los bits de `props` del stamp
  (1 = DNSSEC, 2 = sin logs, 4 = sin filtro).
- No se incluyen `proto`, `props`, `addr` ni `hashes`: son campos internos del
  formato de stamp que no aportan nada a una URL (el `stamp` original queda en el
  campo `stamp`, así que nada se pierde).
- Los relays (`kind: "proxy"`) y los targets van por separado: un proxy solo debe
  combinarse con un target ODoH, nunca con un servidor DNSCrypt.

### Ubicación

El campo `location` es **metadato declarado por el operador**, no geolocalización
por IP. Se deriva de dos fuentes y nunca se adivina:

| `source` | Significado |
|---|---|
| `name` | ciudad tomada del nombre/descripción y país resuelto con `tools/locations.json` |
| `description` | país o "anycast" detectado en el texto de la descripción |
| `unknown` | el operador no dice dónde está |

- `country` es ISO 3166-1 alpha-2 (`"AU"`, `"DE"`, ...) o `null` si no se sabe.
- `anycast` es `true` cuando el texto indica distribución global (Cloudflare,
  crypto.sx, tiarap...).
- `tools/locations.json` es una tabla curada de 110 ciudades; una muestra de 22 se
  verificó contra las fichas oficiales de dnscry.pt (`/public-resolvers/<codigo>`),
  todas correctas. Si el repo upstream añade una ciudad nueva, el país queda en
  `null` hasta que se añada a la tabla (y los tests avisan de las ciudades sin país).

## Cómo se actualiza

`.github/workflows/update.yml` regenera las listas y commitea solo si el contenido
de origen cambió. Se dispara:

- una vez al día (`schedule`), con salida temprana si no hay novedad;
- manualmente (`workflow_dispatch`);
- por `repository_dispatch` (tipo `upstream-change`), para que un servicio externo lo despierte;
- al modificar `tools/` o el propio workflow.

En un repositorio **público**, GitHub Actions no consume minutos de pago.

### Despertar el workflow desde fuera (opcional)

```bash
gh api -X POST repos/<tu-usuario>/<este-repo>/dispatches \
  -f event_type=upstream-change
```

## Uso local

```bash
python tools/build_lists.py --summary          # descarga y regenera todo
python tools/build_lists.py --check            # solo dice si cambió
python tools/build_lists.py --commit           # regenera y commitea/pushea si hay cambios
python tools/build_lists.py --offline odoh-relays=odoh-relays.md odoh-servers=odoh-servers.md
```

Sin dependencias: solo Python 3.9+ (stdlib).

## Tests

```bash
python -m unittest discover -s tests -v
```

## Licencia

El código es tuyo. Los datos provienen de
[DNSCrypt/dnscrypt-resolvers](https://github.com/DNSCrypt/dnscrypt-resolvers),
que se distribuye bajo términos propios; revisa ese repositorio antes de redistribuir.
