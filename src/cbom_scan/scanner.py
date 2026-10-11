"""Walks a directory tree and produces an inventory of cryptographic assets with where they occur."""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import algorithms as A
from .algorithms import Algorithm, from_name
from .rules import COMMENT, ISSUE_RULES, LANGUAGE, RULES

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "third_party", "venv", ".venv", "env", "__pycache__",
             "dist", "build", "target", ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".vscode", "site-packages",
             ".gradle", "bower_components", ".next", "coverage"}
CERT_EXTS = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".csr"}
KEYSTORE_EXTS = {".p12", ".pfx", ".jks", ".keystore", ".bks"}
CONFIG_NAMES = {"nginx.conf", "httpd.conf", "ssl.conf", "apache2.conf", "sshd_config", "ssh_config", "openssl.cnf",
                "haproxy.cfg", "envoy.yaml", "Caddyfile"}
MAX_BYTES = 2_000_000


@dataclass
class Occurrence:
    path: str
    line: int
    snippet: str
    rule: str
    function: str = ""


@dataclass
class Asset:
    kind: str                       # algorithm | certificate | related-crypto-material | protocol
    algorithm: Algorithm | None = None
    name: str = ""
    properties: dict = field(default_factory=dict)
    refs: list[str] = field(default_factory=list)   # names of algorithm assets this one uses
    occurrences: list[Occurrence] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.name}"

    @property
    def status(self) -> str:
        if self.algorithm:
            return self.algorithm.status
        return self.properties.get("status", A.SAFE)


@dataclass
class Issue:
    rule: str
    severity: str        # error | warning | note
    message: str
    path: str
    line: int
    snippet: str = ""


@dataclass
class Inventory:
    assets: dict[str, Asset] = field(default_factory=dict)
    issues: list[Issue] = field(default_factory=list)
    files_scanned: int = 0
    targets: list[str] = field(default_factory=list)

    def add(self, asset: Asset, occ: Occurrence | None = None) -> Asset:
        existing = self.assets.get(asset.key)
        if existing is None:
            self.assets[asset.key] = existing = asset
        elif asset.algorithm and existing.algorithm:
            # keep the most specific details seen (e.g. a later key size or curve)
            for attr in ("key_size", "curve", "mode", "classical_bits", "oid"):
                if getattr(existing.algorithm, attr) is None and getattr(asset.algorithm, attr) is not None:
                    setattr(existing.algorithm, attr, getattr(asset.algorithm, attr))
        if occ:
            if occ.function and asset.algorithm and occ.function not in existing.algorithm.functions:
                existing.algorithm.functions.append(occ.function)
            if not any(o.path == occ.path and o.line == occ.line for o in existing.occurrences):
                existing.occurrences.append(occ)
        return existing

    def add_algorithm(self, alg: Algorithm, occ: Occurrence | None = None) -> Asset:
        return self.add(Asset("algorithm", alg, alg.name), occ)

    def algorithms(self) -> list[Asset]:
        return [a for a in self.assets.values() if a.kind == "algorithm"]


# ---- cipher suites, TLS groups and SSH algorithms -----------------------------------------------
def parse_cipher_suite(name: str) -> list[Algorithm]:
    s = name.upper().replace("TLS_", "", 1) if name.upper().startswith("TLS_") else name.upper()
    toks = re.split(r"[-_]", s)
    out: list[Algorithm] = []
    if "NULL" in toks or "EXPORT" in toks or "EXP" in toks or "ANON" in s or "ADH" in toks or "AECDH" in toks:
        out.append(A.broken("NULL/EXPORT/anon", "other", f"cipher suite {name} offers no or weak protection"))
    if "ECDHE" in toks or "ECDH" in toks:
        out.append(A.ec("ECDH"))
    elif "DHE" in toks or "EDH" in toks or "DH" in toks:
        out.append(Algorithm("DH", "key-agree", A.VULNERABLE, 0))
    if "ECDSA" in toks:
        out.append(A.ec("ECDSA"))
    if "RSA" in toks:
        out.append(A.rsa(primitive="signature" if ("ECDHE" in toks or "DHE" in toks) else "pke"))
    m = re.search(r"AES[-_]?(128|256)[-_]?(GCM|CBC|CCM|SHA)?", s)
    if m:
        mode = m.group(2) if m.group(2) in ("GCM", "CBC", "CCM") else "CBC"
        out.append(A.aes(int(m.group(1)), mode))
    if "CHACHA20" in toks:
        out += from_name("CHACHA20-POLY1305")
    if "3DES" in toks or "CBC3" in toks or "DES-CBC3" in s or ("DES" in toks and "EDE" in toks):
        out += from_name("3DES")
    elif "DES" in toks:
        out += from_name("DES")
    if "RC4" in toks:
        out += from_name("RC4")
    if toks and toks[-1] in ("SHA", "MD5") and "GCM" not in toks:
        out += from_name("HMAC-SHA1" if toks[-1] == "SHA" else "HMAC-MD5")
    return out


def parse_group(name: str) -> list[Algorithm]:
    n = name.strip().strip("'\"")
    low = n.lower()
    if not n or n.startswith("!") or n.startswith("-") or n.upper() in ("HIGH", "MEDIUM", "LOW", "DEFAULT", "ALL", "COMPLEMENTOFDEFAULT"):
        return []
    if "mlkem" in low or "kyber" in low:
        if "x25519" in low or "25519" in low:
            return [A.pqc("ML-KEM-768", hybrid_with="X25519")]
        if "p256" in low or "secp256r1" in low:
            return [A.pqc("ML-KEM-768", hybrid_with="P256")]
        return from_name(n)
    if "sntrup761" in low:
        return [Algorithm("X25519+sntrup761", "kem", A.SAFE, 1, parameter_set="sntrup761x25519", hybrid=True,
                          note="hybrid classical + post-quantum key exchange (OpenSSH)")]
    if low.startswith("curve25519") or low == "x25519":
        return [Algorithm("ECDH", "key-agree", A.VULNERABLE, 0, 128, curve="X25519")]
    if low in ("x448", "curve448-sha512"):
        return [Algorithm("ECDH", "key-agree", A.VULNERABLE, 0, 224, curve="X448")]
    m = re.match(r"ecdh-sha2-nistp(\d+)", low)
    if m:
        return [A.ec("ECDH", f"P-{m.group(1)}")]
    if low.startswith("diffie-hellman"):
        algs = [Algorithm("DH", "key-agree", A.VULNERABLE, 0)]
        if low.endswith("sha1") or "group1-" in low:
            algs = [A.broken("DH", "key-agree", f"{n} uses a small group or SHA-1")]
        return algs
    curve = A.CURVES.get(A._curve_key(n))
    if curve:
        return [A.ec("ECDH", curve[0])]
    return []


def _parse_list(text: str, rule_id: str) -> list[Algorithm]:
    algs = []
    for item in re.split(r"[:,\s]+", text):
        if not item or item.startswith("!") or item.startswith("-") or item.startswith("@"):
            continue
        item = item.lstrip("+")
        algs += parse_group(item) if rule_id == "cfg-tls-groups" else parse_cipher_suite(item)
    return algs


# ---- certificates and keys ------------------------------------------------------------------------
def _key_algorithm(key) -> Algorithm | None:
    from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return A.rsa(key.key_size)
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return A.ec("EC", key.curve.name)
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):  # cbom-scan: ignore
        return from_name("Ed25519")[0]
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):  # cbom-scan: ignore
        return from_name("Ed448")[0]
    if isinstance(key, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):  # cbom-scan: ignore
        return from_name("X25519")[0]
    if isinstance(key, (x448.X448PrivateKey, x448.X448PublicKey)):  # cbom-scan: ignore
        return from_name("X448")[0]
    if isinstance(key, (dsa.DSAPrivateKey, dsa.DSAPublicKey)):
        return A.dsa(key.key_size)
    if isinstance(key, (dh.DHPrivateKey, dh.DHPublicKey)):
        return Algorithm("DH", "key-agree", A.VULNERABLE, 0, key_size=key.key_size)
    return None


def _sig_algorithms(cert) -> list[Algorithm]:
    from cryptography.exceptions import UnsupportedAlgorithm
    oid = cert.signature_algorithm_oid
    name = (oid._name or oid.dotted_string).lower()
    if "ml-dsa" in name or "mldsa" in name:
        return from_name(name)
    if "rsa" in name or "pss" in name:
        algs = [A.rsa(primitive="signature")]
    elif "ecdsa" in name:
        algs = [A.ec("ECDSA")]
    elif "dsa" in name:
        algs = [A.dsa()]
    elif "ed25519" in name or "ed448" in name:
        algs = from_name("Ed25519" if "25519" in name else "Ed448")
    else:
        algs = []
    try:
        h = cert.signature_hash_algorithm
        if h is not None:
            algs += from_name(h.name.upper().replace("-", "") if h.name.startswith("sha") and "3" not in h.name else h.name)
    except UnsupportedAlgorithm:  # e.g. EdDSA has no separate hash
        pass
    return algs


def scan_cert_or_key(inv: Inventory, path: Path, rel: str) -> None:
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization as ser

    data = path.read_bytes()[:MAX_BYTES]
    text = data.decode("latin-1")
    found = False
    blocks = re.findall(r"(-----BEGIN ([A-Z0-9 ]+)-----.+?-----END \2-----)", text, re.S)
    if not blocks and path.suffix.lower() in (".der", ".cer", ".crt"):
        blocks = [(None, "DER CERTIFICATE")]
    for block, label in blocks or []:
        try:
            if "CERTIFICATE" in label and "REQUEST" not in label:
                cert = x509.load_der_x509_certificate(data) if block is None else x509.load_pem_x509_certificate(block.encode())
                _add_certificate(inv, cert, rel)
                found = True
            elif "PRIVATE KEY" in label:
                inv.issues.append(Issue("committed-private-key", "error",
                                        "Private key file committed to the repository. Remove it, purge it from history and rotate it.",
                                        rel, 1))
                try:
                    key = (ser.load_ssh_private_key if "OPENSSH" in label else ser.load_pem_private_key)(block.encode(), password=None)
                    alg = _key_algorithm(key)
                    fmt = "OpenSSH" if "OPENSSH" in label else "PEM"
                except TypeError:
                    alg, fmt = None, "PEM (encrypted)"
                except ValueError:
                    alg, fmt = None, "PEM (unreadable)"
                _add_key(inv, "private-key", alg, fmt, rel)
                found = True
            elif "PUBLIC KEY" in label:
                key = ser.load_pem_public_key(block.encode())
                _add_key(inv, "public-key", _key_algorithm(key), "PEM", rel)
                found = True
        except (ValueError, TypeError, UnsupportedAlgorithm):  # malformed or unusual PEM blocks: skip them
            continue
    if not found and text.startswith(("ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-", "ssh-dss ")):
        for line in text.splitlines():
            try:
                key = ser.load_ssh_public_key(line.strip().encode())
            except (ValueError, UnsupportedAlgorithm):
                continue
            _add_key(inv, "public-key", _key_algorithm(key), "OpenSSH", rel)


def _add_key(inv: Inventory, kind: str, alg: Algorithm | None, fmt: str, rel: str) -> None:
    refs = []
    if alg:
        refs.append(inv.add_algorithm(alg, Occurrence(rel, 1, f"{kind} ({fmt})", "key-file", "keygen")).name)
    name = f"{kind}:{alg.name if alg else 'unknown'}:{rel}"
    inv.add(Asset("related-crypto-material", None, name,
                  {"type": kind, "format": fmt, "size": alg.key_size if alg else None,
                   "status": alg.status if alg else A.SAFE}, refs), Occurrence(rel, 1, fmt, "key-file"))


def _add_certificate(inv: Inventory, cert, rel: str) -> None:
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    line = 0 if rel.startswith("tls://") else 1
    occ = Occurrence(rel, line, cert.subject.rfc4514_string()[:120], "certificate")
    key_alg = _key_algorithm(cert.public_key())
    refs = []
    if key_alg:
        if key_alg.family == "EC":
            key_alg.family = "ECDSA"
            key_alg.primitive = "signature"
        refs.append(inv.add_algorithm(key_alg, occ).name)
    sig_algs = _sig_algorithms(cert)
    for a in sig_algs:
        refs.append(inv.add_algorithm(a, occ).name)
    statuses = [a.status for a in ([key_alg] if key_alg else []) + sig_algs]
    status = min(statuses, key=lambda s: A.STATUS_ORDER[s]) if statuses else A.SAFE
    name = f"{cert.subject.rfc4514_string() or 'unnamed'} ({cert.serial_number:x})"[:200]
    inv.add(Asset("certificate", None, name, {
        "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(), "not_after": not_after.isoformat(),
        "signature_algorithm": sig_algs[0].name if sig_algs else cert.signature_algorithm_oid.dotted_string,
        "public_key": key_alg.name if key_alg else "unknown", "status": status, "format": "X.509",
    }, refs), occ)
    if not_after < now:
        inv.issues.append(Issue("expired-certificate", "warning", f"Certificate expired on {not_after.date()}: {name}", rel, line))
    elif key_alg and key_alg.status in (A.VULNERABLE,) and (not_after - now).days > 365 * 5:
        inv.issues.append(Issue("long-lived-quantum-vulnerable-cert", "note",
                                f"Quantum-vulnerable certificate valid until {not_after.date()} (harvest-now, forge-later risk)",
                                rel, line))


# ---- source and config files ----------------------------------------------------------------------
def _ext(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".env.example"):
        return ".env.example"
    if path.name in CONFIG_NAMES or name.endswith(("_config", ".conf")):
        return ".conf" if name.endswith(".conf") else ""
    return path.suffix.lower()


def _apply_bits_curve(alg: Algorithm, m: re.Match) -> Algorithm:
    gd = m.groupdict()
    bits = gd.get("bits")
    curve = gd.get("curve")
    if bits and alg.family == "RSA":
        alg = A.rsa(int(bits), alg.primitive)
    elif bits and alg.family == "AES" and int(bits) in (128, 192, 256):
        alg = A.aes(int(bits), alg.mode)
    if curve and alg.family in ("EC", "ECDSA", "ECDH"):
        alg = A.ec(alg.family, curve)
    if gd.get("mode") and alg.family == "AES":
        alg = A.aes(alg.key_size, gd["mode"])
    return alg


def scan_text(inv: Inventory, text: str, rel: str, ext: str) -> None:
    rules = [r for r in RULES if ext in r.exts]
    issue_rules = [r for r in ISSUE_RULES if ext in r.exts]
    if not rules and not issue_rules:
        return
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 2000 or "cbom-scan: ignore" in line:
            continue
        is_comment = bool(COMMENT.match(line)) and ext not in ("", ".conf", ".cnf", ".cfg", ".ini")
        for rule in issue_rules:
            if rule.pattern.search(line) and not (is_comment and rule.id != "hardcoded-private-key"):
                inv.issues.append(Issue(rule.id, rule.issue[0], rule.issue[1], rel, i, line.strip()[:200]))
        if is_comment or (ext in ("", ".conf", ".cnf", ".cfg", ".ini") and line.lstrip().startswith(("#", ";"))):
            continue
        window = " ".join(lines[i - 1:i + 3])  # key sizes are often on the next lines (e.g. modulusLength)
        for rule in rules:
            for m in rule.pattern.finditer(line):
                occ_m = rule.pattern.search(window) if rule.pattern.groupindex.keys() & {"bits", "curve"} else m
                occ_m = occ_m or m
                gd = m.groupdict()
                snippet = line.strip()[:200]
                if "list" in gd and gd["list"]:
                    algs = _parse_list(gd["list"], rule.id)
                elif rule.algs:
                    algs = [x for name in rule.algs for x in from_name(name, line)] or \
                           [A.ec(n) for n in rule.algs if n == "EC"]
                else:
                    raw = gd.get("param") or gd.get("alg") or gd.get("alg2") or ""
                    if rule.id == "go-mlkem":
                        raw = f"ML-KEM-{raw}"
                    algs = from_name(raw.replace("_", "-") if rule.id in ("c-evp-md", "c-evp-cipher", "c-pkey") else raw, line)
                    if not algs and raw.upper() in ("EC", "P256", "P384", "P521"):
                        algs = [A.ec("ECDH", raw)] if raw.upper() != "EC" else [A.ec("EC")]
                for alg in algs:
                    alg = _apply_bits_curve(alg, occ_m)
                    inv.add_algorithm(alg, Occurrence(rel, i, snippet, rule.id, rule.function))


def _excluded(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel.split("/")[0], p) for p in patterns)


def scan_path(root: str | Path, inv: Inventory | None = None, exclude: list[str] | None = None) -> Inventory:
    inv = inv or Inventory()
    root = Path(root)
    inv.targets.append(str(root))
    exclude = exclude or []
    paths = [root] if root.is_file() else None
    if paths is None:
        paths = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
            for f in filenames:
                paths.append(Path(dirpath) / f)
    for p in sorted(paths):
        rel = p.name if p == root else p.relative_to(root).as_posix()
        if _excluded(rel, exclude):
            continue
        try:
            if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        ext = _ext(p)
        if ext in KEYSTORE_EXTS:
            inv.issues.append(Issue("committed-keystore", "warning",
                                    "Keystore file committed to the repository. Keep keystores out of source control.", rel, 1))
            inv.files_scanned += 1
            continue
        if ext in CERT_EXTS:
            inv.files_scanned += 1
            scan_cert_or_key(inv, p, rel)
            continue
        if ext not in LANGUAGE and ext not in {e for r in RULES + ISSUE_RULES for e in r.exts}:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "\x00" in text[:1024]:
            continue
        inv.files_scanned += 1
        scan_text(inv, text, rel, ext)
    return inv
