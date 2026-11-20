"""Tests de build_lists.py (stdlib unittest, sin dependencias)."""
import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import build_lists as bl  # noqa: E402


class TestStampDecoding(unittest.TestCase):
    """Casos tomados de las listas reales de DNSCrypt/dnscrypt-resolvers."""

    def test_odoh_target_con_ruta(self):
        # dnscry.pt-odoh-adelaide: props 7 (DNSSEC + sin logs + sin filtro)
        out = bl.decode_stamp("sdns://BQcAAAAAAAAAD2FkbDAxLmRuc2NyeS5wdAovZG5zLXF1ZXJ5")
        self.assertEqual(out["proto"], 0x05)
        self.assertEqual(out["hostname"], "adl01.dnscry.pt")
        self.assertEqual(out["port"], 443)
        self.assertEqual(out["path"], "/dns-query")
        self.assertEqual(out["url"], "https://adl01.dnscry.pt/dns-query")
        self.assertTrue(out["dnssec"] and out["no_logs"] and out["no_filter"])

    def test_odoh_target_con_puerto(self):
        hostport = b"host:8443"
        buf = (b"\x05" + b"\x03\x00\x00\x00\x00\x00\x00\x00"
               + bytes([len(hostport)]) + hostport
               + bytes([5]) + b"/odoh")
        stamp = "sdns://" + base64.urlsafe_b64encode(buf).decode().rstrip("=")
        out = bl.decode_stamp(stamp)
        self.assertEqual(out["hostname"], "host")
        self.assertEqual(out["port"], 8443)
        self.assertEqual(out["url"], "https://host:8443/odoh")

    def test_odoh_relay_sin_hashes(self):
        # El 0x00 tras addr es un VLP vacio (conjunto vacio), no un hash.
        out = bl.decode_stamp("sdns://hQcAAAAAAAAAAAASb2RvaC1yZWxheS5udW1hLnJzBi9yZWxheQ")
        self.assertEqual(out["proto"], 0x85)
        self.assertEqual(out["addr"], "")
        self.assertEqual(out["hashes"], [])
        self.assertEqual(out["hostname"], "odoh-relay.numa.rs")
        self.assertEqual(out["path"], "/relay")
        self.assertEqual(out["url"], "https://odoh-relay.numa.rs/relay")

    def test_odoh_relay_con_hash_real(self):
        # 0x85 || props || LP(addr) || VLP(hash SHA-256) || LP(host) || LP(path)
        h = bytes(range(32))
        hostport = b"odoh-relay.ejemplo.com"
        path = b"/relay"
        buf = (b"\x85" + b"\x07\x00\x00\x00\x00\x00\x00\x00"
               + b"\x00"                                  # addr vacio
               + bytes([0x80 | 32]) + h                   # VLP: quedan mas elementos
               + bytes([32]) + h                          # ultimo hash (sin 0x80)
               + bytes([len(hostport)]) + hostport
               + bytes([len(path)]) + path)
        stamp = "sdns://" + base64.urlsafe_b64encode(buf).decode().rstrip("=")
        out = bl.decode_stamp(stamp)
        self.assertEqual(out["hashes"], [h.hex(), h.hex()])
        self.assertEqual(out["url"], "https://odoh-relay.ejemplo.com/relay")

    def test_props_sin_filtro(self):
        out = bl.decode_stamp("sdns://BQMAAAAAAAAADGRvaC50aWFyLmFwcAUvb2RvaA")
        self.assertEqual(out["props"], 3)
        self.assertTrue(out["dnssec"])
        self.assertTrue(out["no_logs"])
        self.assertFalse(out["no_filter"])

    def test_protocolo_no_soportado(self):
        with self.assertRaises(bl.StampError):
            bl.decode_stamp("sdns://" + base64.urlsafe_b64encode(b"\x01\x00").decode())

    def test_split_hostport_ipv6(self):
        self.assertEqual(bl._split_hostport("[2001:db8::1]:8443"), ("2001:db8::1", "8443"))
        self.assertEqual(bl._split_hostport("[2001:db8::1]"), ("2001:db8::1", "443"))
        self.assertEqual(bl._split_hostport("ejemplo.com"), ("ejemplo.com", "443"))


SAMPLE_MD = """# Oblivious DoH servers list

Preample que no debe parsearse.
urls = ['https://ejemplo.com']

## target-uno

Primera linea de descripcion.
Segunda linea.
https://sitio-ejemplo.com

sdns://BQcAAAAAAAAAD2FkbDAxLmRuc2NyeS5wdAovZG5zLXF1ZXJ5

## target-dos

Otro target.
sdns://BQMAAAAAAAAADGRvaC50aWFyLmFwcAUvb2RvaA
"""


class TestParseMarkdown(unittest.TestCase):
    def test_parse_secciones(self):
        entries = bl.parse_list_md(SAMPLE_MD, "odoh-target")
        self.assertEqual([e["name"] for e in entries], ["target-uno", "target-dos"])
        self.assertEqual(entries[0]["url"], "https://adl01.dnscry.pt/dns-query")
        self.assertEqual(entries[0]["site"], "https://sitio-ejemplo.com")
        self.assertEqual(entries[0]["description"],
                         ["Primera linea de descripcion.", "Segunda linea."])
        self.assertEqual(entries[1]["url"], "https://doh.tiar.app/odoh")

    def test_preample_ignorado(self):
        entries = bl.parse_list_md(SAMPLE_MD, "odoh-target")
        self.assertNotIn("urls = ['https://ejemplo.com']",
                         entries[0]["description"])


class TestEndToEnd(unittest.TestCase):
    def test_genera_los_tres_formatos(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries = bl.parse_list_md(SAMPLE_MD, bl.LISTS["odoh-servers"]["kind"])
            sha = "a" * 64
            bl.write_markdown("odoh-servers", bl.LISTS["odoh-servers"], entries, tmp)
            bl.write_txt("odoh-servers", entries, tmp)
            bl.write_json("odoh-servers", bl.LISTS["odoh-servers"], entries, tmp, sha, None)

            with open(os.path.join(tmp, "odoh-servers.txt"), encoding="utf-8") as fh:
                txt = fh.read()
            self.assertEqual(txt.splitlines(),
                             ["https://adl01.dnscry.pt/dns-query",
                              "https://doh.tiar.app/odoh"])

            with open(os.path.join(tmp, "odoh-servers.json"), encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["count"], 2)
            self.assertEqual(data["source_sha256"], sha)
            self.assertEqual(data["entries"][0]["hostname"], "adl01.dnscry.pt")
            # los datos del stamp original tambien se exponen (estilo DNSCrypt)
            self.assertEqual(data["entries"][0]["proto"], 0x05)
            self.assertEqual(data["entries"][0]["props"], 7)
            self.assertEqual(data["entries"][0]["addr"], "")
            self.assertEqual(data["entries"][0]["hashes"], [])
            self.assertEqual(data["entries"][0]["kind"], "target")

            with open(os.path.join(tmp, "odoh-servers.md"), encoding="utf-8") as fh:
                md = fh.read()
            self.assertIn("## target-uno", md)
            self.assertIn("- URL: https://adl01.dnscry.pt/dns-query", md)
            # el .md es la lista en formato https, no una copia de los sdns
            self.assertNotIn("sdns://", md)


class TestLocation(unittest.TestCase):
    """La ubicacion se deriva del texto/nombre, nunca se infiere de la IP."""

    @classmethod
    def setUpClass(cls):
        cls.locations = bl.load_locations()

    def _loc(self, name, desc):
        return bl.derive_location({"name": name, "description": desc}, self.locations)

    def test_ciudad_y_pais_de_dnscry_pt(self):
        loc = self._loc("dnscry.pt-odoh-adelaide",
                        ["dnscry.pt Adelaide ODoH target.",
                         "Operated by dnscry.pt. No query logs."])
        self.assertEqual(loc, {"city": "Adelaide", "country": "AU",
                               "anycast": False, "source": "name"})

    def test_sufijo_numerico_ignorado(self):
        loc = self._loc("dnscry.pt-odoh-amsterdam02",
                        ["dnscry.pt Amsterdam 02 ODoH target."])
        self.assertEqual(loc["city"], "Amsterdam")
        self.assertEqual(loc["country"], "NL")

    def test_anycast_por_texto(self):
        loc = self._loc("odoh-cloudflare", ["Cloudflare ODoH target.",
                                            "Available through servers in multiple "
                                            "locations around the world."])
        self.assertTrue(loc["anycast"])
        self.assertIsNone(loc["country"])
        self.assertEqual(loc["source"], "description")

    def test_pais_por_texto(self):
        loc = self._loc("odohrelay-numa", ["Numa ODoH relay.",
                                           "Run by the Numa project on Hetzner in "
                                           "Falkenstein, Germany."])
        self.assertEqual(loc["country"], "DE")
        self.assertEqual(loc["source"], "description")

    def test_sin_datos_de_ubicacion(self):
        loc = self._loc("odoh-snowstorm", ["Snowstorm ODoH target.",
                                           "Hosted by Snowstorm. No logs."])
        self.assertEqual(loc, {"city": None, "country": None,
                               "anycast": False, "source": "unknown"})

    def test_ciudad_sin_tabla_da_pais_nulo(self):
        loc = self._loc("dnscry.pt-odoh-nuevaciudad",
                        ["dnscry.pt Nuevaciudad ODoH target."])
        self.assertEqual(loc["city"], "Nuevaciudad")
        self.assertIsNone(loc["country"])

    def test_tabla_cobertura_y_formato(self):
        self.assertGreater(len(self.locations), 100)
        for key, info in self.locations.items():
            self.assertEqual(key, key.lower())
            self.assertRegex(info["country"], r"^[A-Z]{2}$")

    def test_linea_ubicacion_markdown(self):
        self.assertEqual(bl._location_line(
            {"location": {"city": "Adelaide", "country": "AU"}}), "Adelaide, AU")
        self.assertEqual(bl._location_line(
            {"location": {"country": "DE"}}), "DE")
        self.assertIn("anycast", bl._location_line(
            {"location": {"anycast": True}}))
        self.assertEqual(bl._location_line({}), "desconocida")


if __name__ == "__main__":
    unittest.main()
