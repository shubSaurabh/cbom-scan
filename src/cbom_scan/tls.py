"""Live TLS endpoint probe: protocol version, cipher suite, certificate, whether the server agrees to a
post-quantum hybrid key exchange (X25519MLKEM768), and whether it still accepts TLS 1.0/1.1.

The post-quantum and legacy checks use the `openssl` command (3.5+ for ML-KEM groups), because Python's
ssl module cannot choose key-exchange groups. Without it, those checks are reported as "unknown".
"""
from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess

from . import algorithms as A
from .scanner import Asset, Inventory, Issue, Occurrence, _add_certificate, parse_cipher_suite, parse_group

CLIENT_GROUPS = "X25519MLKEM768:X25519:secp256r1:secp384r1"


def _split(endpoint: str) -> tuple[str, int]:
    endpoint = re.sub(r"^\w+://", "", endpoint).split("/")[0]
    if endpoint.startswith("["):  # [ipv6]:port
        host, _, port = endpoint[1:].partition("]:")
        return host, int(port or 443)
    host, _, port = endpoint.rpartition(":") if endpoint.count(":") == 1 else (endpoint, "", "443")
    return host, int(port or 443)


def _openssl_version() -> tuple[int, int] | None:
    exe = shutil.which("openssl")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"OpenSSL (\d+)\.(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else None


def _s_client(host: str, port: int, *args: str, timeout: float = 10) -> str:
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-brief", *args]
    try:
        r = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except (OSError, subprocess.SubprocessError):
        return ""


def probe(inv: Inventory, endpoint: str, timeout: float = 10) -> Asset | None:
    host, port = _split(endpoint)
    where = f"tls://{host}:{port}"
    inv.targets.append(where)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # cbom-scan: ignore
    ctx.verify_mode = ssl.CERT_NONE  # cbom-scan: ignore (inspection only: we read the certificate, we do not trust it)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=host) as tls:
            version, (suite, _, _) = tls.version(), tls.cipher()
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as e:
        inv.issues.append(Issue("tls-unreachable", "warning", f"Could not complete a TLS handshake: {e}", where, 0))
        return None

    occ = Occurrence(where, 0, f"{version} {suite}", "tls-probe")
    refs = [inv.add_algorithm(a, occ).name for a in parse_cipher_suite(suite)]
    if der:
        from cryptography import x509
        _add_certificate(inv, x509.load_der_x509_certificate(der), where)

    props = {"endpoint": f"{host}:{port}", "version": version.replace("TLSv", ""), "cipher_suite": suite,
             "pq_key_exchange": "unknown", "legacy_protocols": "unknown", "status": A.SAFE}
    ver = _openssl_version()
    if ver and ver >= (3, 5):
        out = _s_client(host, port, "-groups", CLIENT_GROUPS, timeout=timeout)
        m = re.search(r"(?:Negotiated TLS1\.3 group|Server Temp Key|Peer Temp Key):\s*([\w\-]+)", out)
        if m:
            group = m.group(1)
            props["group"] = group
            for a in parse_group(group):
                refs.append(inv.add_algorithm(a, occ).name)
            props["pq_key_exchange"] = "yes" if re.search(r"(?i)mlkem|kyber", group) else "no"
    if ver:
        accepted = []
        for flag, label in (("-tls1", "TLS 1.0"), ("-tls1_1", "TLS 1.1")):
            out = _s_client(host, port, flag, "-cipher", "DEFAULT:@SECLEVEL=0", timeout=timeout)
            if re.search(r"Protocol version: TLSv1(\.1)?\s*$", out, re.M) and "CONNECTION ESTABLISHED" in out:
                accepted.append(label)
        props["legacy_protocols"] = ", ".join(accepted) or "none"
        if accepted:
            inv.issues.append(Issue("tls-legacy-protocol", "error",
                                    f"Server accepts {' and '.join(accepted)}. Disable them; require TLS 1.2+.", where, 0))
    if props["pq_key_exchange"] == "no":
        props["status"] = A.VULNERABLE
        inv.issues.append(Issue("tls-no-pq-key-exchange", "warning",
                                "Server did not agree to a post-quantum hybrid key exchange (X25519MLKEM768), so recorded "
                                "traffic is exposed to harvest-now, decrypt-later attacks.", where, 0))
    asset = Asset("protocol", None, f"TLS {props['version']} {host}:{port}", props, refs, [occ])
    return inv.add(asset)
