import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from cbom_scan import cli
from cbom_scan.output import to_cbom, to_markdown, to_sarif
from cbom_scan.scanner import scan_path
from cbom_scan.score import compute
from cbom_scan.tls import _split
from helpers import make_sample


class ScanSample(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = make_sample()
        cls.root = Path(cls.tmp.name) / "sample"
        cls.inv = scan_path(cls.root)
        cls.score = compute(cls.inv)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def asset(self, name, kind="algorithm"):
        return self.inv.assets.get(f"{kind}:{name}")

    def where(self, name):
        return {(o.path, o.line) for o in self.asset(name).occurrences}

    def test_languages(self):
        self.assertIn(("src/legacy.py", 6), self.where("MD5"))
        self.assertIn(("src/legacy.py", 8), self.where("RSA-1024"))
        self.assertIn(("src/legacy.py", 10), self.where("AES-ECB"))
        self.assertIn(("src/Crypto.java", 4), self.where("3DES"))
        self.assertIn(("src/Crypto.java", 8), self.where("ML-KEM-768"))
        self.assertIn(("src/server.go", 11), self.where("RSA-2048"))
        self.assertIn(("src/server.go", 14), self.where("ML-KEM-768"))
        self.assertIn(("src/app.ts", 3), self.where("RSA-3072"))   # modulusLength is on a later line
        self.assertIn(("src/app.ts", 7), self.where("ECDSA-P-384"))
        self.assertIn(("src/tls.c", 5), self.where("RSA-4096"))
        self.assertIn(("src/tls.c", 6), self.where("ML-DSA-65"))

    def test_comments_ignored(self):
        self.assertIsNone(self.asset("RC4"))

    def test_configs(self):
        self.assertIn(("config/nginx.conf", 5), self.where("X25519MLKEM768"))
        self.assertIn(("config/sshd_config", 2), self.where("X25519MLKEM768"))
        self.assertIn(("config/nginx.conf", 4), self.where("3DES"))

    def test_certificates_and_keys(self):
        certs = [a for a in self.inv.assets.values() if a.kind == "certificate"]
        self.assertEqual(len(certs), 2)
        legacy = next(c for c in certs if "legacy" in c.name)
        self.assertEqual(legacy.status, "broken")
        self.assertEqual(legacy.properties["public_key"], "RSA-1024")
        keys = [a for a in self.inv.assets.values() if a.kind == "related-crypto-material"]
        self.assertEqual(keys[0].properties["type"], "private-key")

    def test_issues(self):
        rules = {(i.rule, i.path) for i in self.inv.issues}
        for expected in [("committed-private-key", "certs/dev.key"), ("expired-certificate", "certs/legacy.crt"),
                         ("tls-legacy-protocol", "config/nginx.conf"), ("tls-legacy-protocol", "src/server.go"),
                         ("tls-verification-disabled", "src/legacy.py"), ("tls-verification-disabled", "src/server.go"),
                         ("long-lived-quantum-vulnerable-cert", "certs/api.pem")]:
            self.assertIn(expected, rules)

    def test_score(self):
        self.assertEqual(self.score.value, 0)  # the sample is deliberately terrible
        self.assertEqual(self.score.grade, "F")
        self.assertIn("ML-KEM-768", self.score.pqc)

    def test_cbom(self):
        bom = to_cbom(self.inv, self.score, "sample")
        self.assertEqual(bom["specVersion"], "1.6")
        refs = {c["bom-ref"] for c in bom["components"]}
        self.assertEqual(len(refs), len(bom["components"]))
        for c in bom["components"]:
            props = c["cryptoProperties"]
            cp = props.get("certificateProperties") or props.get("relatedCryptoMaterialProperties") or {}
            for key in ("subjectPublicKeyRef", "signatureAlgorithmRef", "algorithmRef"):
                if key in cp:
                    self.assertIn(cp[key], refs)
        md5 = next(c for c in bom["components"] if c["name"] == "MD5")
        self.assertEqual(md5["cryptoProperties"]["algorithmProperties"]["primitive"], "hash")
        self.assertEqual(md5["evidence"]["occurrences"][0]["location"], "src/legacy.py")

    def test_sarif_and_markdown(self):
        sarif = to_sarif(self.inv)
        levels = {r["level"] for r in sarif["runs"][0]["results"]}
        self.assertEqual(levels, {"error", "warning", "note"})
        rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertTrue({r["ruleId"] for r in sarif["runs"][0]["results"]} <= rule_ids)
        md = to_markdown(self.inv, self.score, "sample")
        for section in ("## Fix now", "## Plan the post-quantum migration", "## Certificates", "## Algorithm inventory"):
            self.assertIn(section, md)

    def test_cli_outputs_and_gate(self):
        out = Path(self.tmp.name)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main([str(self.root), "--cbom", str(out / "c.json"), "--sarif", str(out / "s.sarif"),
                             "--markdown", str(out / "r.md"), "--fail-under", "50", "--no-color"])
        self.assertEqual(code, 1)
        self.assertIn("PQC readiness 0/100 (F)", buf.getvalue())
        self.assertEqual(json.loads((out / "c.json").read_text())["bomFormat"], "CycloneDX")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main([str(self.root / "src" / "app.ts"), "-q"]), 0)


class Misc(unittest.TestCase):
    def test_inline_ignore(self):
        from cbom_scan.scanner import Inventory, scan_text
        inv = Inventory()
        scan_text(inv, "a = hashlib.md5(x)  # cbom-scan: ignore\nb = hashlib.sha1(y)\n", "x.py", ".py")
        self.assertEqual([a.name for a in inv.algorithms()], ["SHA-1"])

    def test_endpoint_parsing(self):
        self.assertEqual(_split("example.com"), ("example.com", 443))
        self.assertEqual(_split("https://example.com:8443/path"), ("example.com", 8443))
        self.assertEqual(_split("[::1]:4433"), ("::1", 4433))


if __name__ == "__main__":
    unittest.main()
