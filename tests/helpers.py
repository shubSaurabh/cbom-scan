import datetime as dt
import shutil
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample"


def _cert(key, cn, start, days):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1000 + days).not_valid_before(start).not_valid_after(start + dt.timedelta(days=days))
            .sign(key, hashes.SHA256() if isinstance(key, rsa.RSAPrivateKey) else hashes.SHA384()))


def make_sample() -> tempfile.TemporaryDirectory:
    """Copy the sample project and add certificates and keys, generated fresh so none are committed."""
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name) / "sample"
    shutil.copytree(SAMPLE, root)
    certs = root / "certs"
    certs.mkdir()
    old = dt.datetime(2015, 1, 1, tzinfo=dt.timezone.utc)
    now = dt.datetime.now(dt.timezone.utc)
    weak = rsa.generate_private_key(65537, 1024)
    (certs / "legacy.crt").write_bytes(_cert(weak, "legacy.example", old, 365).public_bytes(ser.Encoding.PEM))
    k = ec.generate_private_key(ec.SECP384R1())
    (certs / "api.pem").write_bytes(_cert(k, "api.example", now, 3650).public_bytes(ser.Encoding.PEM))
    (certs / "dev.key").write_bytes(k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    return tmp
