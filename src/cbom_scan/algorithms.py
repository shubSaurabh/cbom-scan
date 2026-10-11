"""Catalogue of cryptographic algorithms: what they are, how strong they are today, and what a
cryptographically relevant quantum computer does to them.

Status values:
  broken              weak or deprecated today, regardless of quantum (MD5, SHA-1, DES, RC4, RSA-1024, ECB...)
  quantum-vulnerable  secure today, broken by Shor's algorithm (RSA, ECC, DH, DSA)
  quantum-weakened    Grover's algorithm halves the strength; fine under NIST, below CNSA 2.0 (AES-128)
  quantum-safe        post-quantum or strong enough symmetric/hash primitives
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

BROKEN, VULNERABLE, WEAKENED, SAFE = "broken", "quantum-vulnerable", "quantum-weakened", "quantum-safe"
STATUS_ORDER = {BROKEN: 0, VULNERABLE: 1, WEAKENED: 2, SAFE: 3}


@dataclass
class Algorithm:
    family: str                  # RSA, ECDSA, AES, SHA-256, ML-KEM ...
    primitive: str               # CycloneDX 1.6 primitive: pke, signature, kem, key-agree, hash, mac, ae, block-cipher...
    status: str
    nist_level: int | None       # NIST post-quantum security category, 0 = none, None = unknown
    classical_bits: int | None = None
    key_size: int | None = None
    mode: str | None = None
    curve: str | None = None
    parameter_set: str | None = None
    oid: str | None = None
    note: str = ""
    hybrid: bool = False
    functions: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        if self.parameter_set and self.family not in ("ECDSA", "ECDH", "EC"):
            return self.parameter_set
        parts = [self.family]
        if self.curve:
            parts.append(self.curve)
        elif self.key_size and self.family in ("RSA", "DSA", "DH", "AES", "HMAC"):
            parts.append(str(self.key_size))
        if self.mode:
            parts.append(self.mode.upper())
        return "-".join(parts)

    @property
    def is_pqc(self) -> bool:
        return self.primitive in ("kem", "signature") and self.status == SAFE


RSA_STRENGTH = {512: 56, 768: 64, 1024: 80, 1536: 96, 2048: 112, 3072: 128, 4096: 140, 7680: 192, 8192: 200, 15360: 256}
CURVES = {
    "P-256": ("P-256", 128, "1.2.840.10045.3.1.7"), "SECP256R1": ("P-256", 128, "1.2.840.10045.3.1.7"),
    "PRIME256V1": ("P-256", 128, "1.2.840.10045.3.1.7"), "P256": ("P-256", 128, "1.2.840.10045.3.1.7"),
    "X9_62_PRIME256V1": ("P-256", 128, "1.2.840.10045.3.1.7"),
    "P-384": ("P-384", 192, "1.3.132.0.34"), "SECP384R1": ("P-384", 192, "1.3.132.0.34"), "P384": ("P-384", 192, "1.3.132.0.34"),
    "P-521": ("P-521", 256, "1.3.132.0.35"), "SECP521R1": ("P-521", 256, "1.3.132.0.35"), "P521": ("P-521", 256, "1.3.132.0.35"),
    "SECP256K1": ("secp256k1", 128, "1.3.132.0.10"), "P-224": ("P-224", 112, None), "SECP224R1": ("P-224", 112, None),
    "SECP192R1": ("P-192", 96, None), "PRIME192V1": ("P-192", 96, None),
}


def _curve_key(curve: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", curve.upper()).removeprefix("NID")


CURVES = {_curve_key(k): v for k, v in CURVES.items()}
HASH_LEVEL = {"SHA-224": (112, 1), "SHA-256": (128, 2), "SHA-384": (192, 4), "SHA-512": (256, 5),
              "SHA-512/256": (128, 2), "SHA3-224": (112, 1), "SHA3-256": (128, 2), "SHA3-384": (192, 4),
              "SHA3-512": (256, 5), "BLAKE2B": (256, 5), "BLAKE2S": (128, 2), "SHAKE128": (128, 2), "SHAKE256": (256, 5)}
PQC = {
    "ML-KEM-512": ("kem", 1, "2.16.840.1.101.3.4.4.1"), "ML-KEM-768": ("kem", 3, "2.16.840.1.101.3.4.4.2"),
    "ML-KEM-1024": ("kem", 5, "2.16.840.1.101.3.4.4.3"),
    "ML-DSA-44": ("signature", 2, "2.16.840.1.101.3.4.3.17"), "ML-DSA-65": ("signature", 3, "2.16.840.1.101.3.4.3.18"),
    "ML-DSA-87": ("signature", 5, "2.16.840.1.101.3.4.3.19"),
    "SLH-DSA": ("signature", 1, None), "FN-DSA": ("signature", 1, None), "XMSS": ("signature", 2, None),
    "LMS": ("signature", 2, None), "HQC": ("kem", 1, None), "FRODOKEM": ("kem", 1, None),
}


def rsa(bits: int | None = None, primitive: str = "pke") -> Algorithm:
    a = Algorithm("RSA", primitive, VULNERABLE, 0, RSA_STRENGTH.get(bits) if bits else None, key_size=bits,
                  oid="1.2.840.113549.1.1.1")
    if bits and bits < 2048:
        a.status, a.note = BROKEN, f"RSA-{bits} is below the 2048-bit minimum (NIST SP 800-131A)"
    return a


def ec(family: str, curve: str | None = None) -> Algorithm:
    primitive = {"ECDSA": "signature", "ECDH": "key-agree"}.get(family, "other")
    a = Algorithm(family, primitive, VULNERABLE, 0)
    if curve:
        name, bits, oid = CURVES.get(_curve_key(curve), (curve, None, None))
        a.curve, a.classical_bits, a.oid = name, bits, oid
        if bits is not None and bits < 112:
            a.status, a.note = BROKEN, f"curve {name} gives under 112-bit security"
    return a


def aes(bits: int | None = None, mode: str | None = None) -> Algorithm:
    mode = mode.lower() if mode else None
    primitive = "ae" if mode in ("gcm", "ccm", "siv", "ocb") else "block-cipher"
    level = {128: 1, 192: 3, 256: 5}.get(bits or 0)  # None: key size not visible in code
    status = WEAKENED if bits == 128 else SAFE
    a = Algorithm("AES", primitive, status, level, bits, key_size=bits, mode=mode,
                  note="AES-128 meets NIST category 1; CNSA 2.0 requires AES-256" if bits == 128 else "")
    if mode == "ecb":
        a.status, a.note = BROKEN, "ECB mode leaks plaintext patterns; use GCM"
    return a


def broken(family: str, primitive: str, note: str) -> Algorithm:
    return Algorithm(family, primitive, BROKEN, 0, note=note)


def hash_alg(family: str) -> Algorithm:
    bits, level = HASH_LEVEL[family]
    return Algorithm(family, "hash", SAFE, level, bits)


def pqc(param: str, hybrid_with: str | None = None) -> Algorithm:
    base = re.sub(r"-(SHA2|SHAKE)-.*$", "", param)
    family = next((f for f in PQC if base.startswith(f)), base)
    primitive, level, oid = PQC.get(base, PQC.get(family, ("kem", 1, None)))
    fam = re.sub(r"-\d+$", "", family)
    if hybrid_with:
        return Algorithm(f"{hybrid_with}+{fam}", "kem", SAFE, level, parameter_set=f"{hybrid_with}{param.replace('-', '')}",
                         hybrid=True, note="hybrid classical + post-quantum key exchange")
    return Algorithm(fam, primitive, SAFE, level, parameter_set=param, oid=oid)


_AES = re.compile(r"^AES[-_]?(128|192|256)?(?:[-_/](GCM|CBC|ECB|CTR|CFB\d*|OFB|CCM|SIV|OCB|KW|WRAP))?")
_AES_MODE_FIRST = re.compile(r"^AES[-_]?(GCM|CBC|ECB|CTR|CFB|OFB|CCM)(?:[-_]?(128|192|256))?$")
_SIG_WITH = re.compile(r"^(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3-256|SHA3-512)WITH(RSA|ECDSA|DSA|RSAANDMGF1|RSA/PSS)")
_HASHES = {"MD5": None, "MD4": None, "MD2": None, "SHA1": None, "SHA-1": None, "SHA": None,
           "SHA224": "SHA-224", "SHA-224": "SHA-224", "SHA256": "SHA-256", "SHA-256": "SHA-256",
           "SHA384": "SHA-384", "SHA-384": "SHA-384", "SHA512": "SHA-512", "SHA-512": "SHA-512",
           "SHA512/256": "SHA-512/256", "SHA-512/256": "SHA-512/256", "SHA3-224": "SHA3-224", "SHA3-256": "SHA3-256",
           "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512", "SHA3_256": "SHA3-256", "SHA3_512": "SHA3-512",
           "BLAKE2B": "BLAKE2B", "BLAKE2S": "BLAKE2S", "SHAKE128": "SHAKE128", "SHAKE256": "SHAKE256"}


def _hash(h: str) -> Algorithm | None:
    if h in ("MD5", "MD4", "MD2"):
        return broken(h, "hash", f"{h} is collision-broken; use SHA-256 or better")
    if h in ("SHA1", "SHA-1", "SHA"):
        return broken("SHA-1", "hash", "SHA-1 is collision-broken (SHAttered, 2017); use SHA-256 or better")
    fam = _HASHES.get(h)
    return hash_alg(fam) if fam else None


def from_name(raw: str, context: str = "") -> list[Algorithm]:
    """Map an algorithm string as written in code or config (e.g. 'AES/GCM/NoPadding', 'aes-128-ecb',
    'SHA256withRSA', 'RS256', 'X25519MLKEM768') to catalogue entries. Unknown strings give []."""
    s = raw.strip().strip("'\"`").upper().replace(" ", "")
    if not s:
        return []
    # post-quantum and hybrids first (they contain classical names)
    m = re.match(r"^(X25519|SECP256R1|P256|X448|SECP384R1)[_-]?(MLKEM|KYBER)[_-]?(512|768|1024)", s)
    if m:
        return [pqc(f"ML-KEM-{m.group(3)}", hybrid_with=m.group(1).replace("SECP256R1", "P256").title())]
    m = re.match(r"^(ML-?KEM|KYBER)[-_]?(512|768|1024)", s)
    if m:
        return [pqc(f"ML-KEM-{m.group(2)}")]
    m = re.match(r"^ML-?DSA[-_]?(44|65|87)", s)
    if m:
        return [pqc(f"ML-DSA-{m.group(1)}")]
    m = re.match(r"^DILITHIUM[-_]?([235])", s)
    if m:
        return [pqc({"2": "ML-DSA-44", "3": "ML-DSA-65", "5": "ML-DSA-87"}[m.group(1)])]
    if re.match(r"^(SLH-?DSA|SPHINCS)", s):
        return [pqc("SLH-DSA")]
    if re.match(r"^(FN-?DSA|FALCON)", s):
        return [pqc("FN-DSA")]
    if re.match(r"^(XMSS|HSS|LMS)", s):
        return [pqc("XMSS" if s.startswith("XMSS") else "LMS")]

    m = _SIG_WITH.match(s)
    if m:
        h = _hash(m.group(1))
        asym = {"RSA": rsa(primitive="signature"), "ECDSA": ec("ECDSA"), "DSA": dsa()}.get(m.group(2), rsa(primitive="signature"))
        return [asym] + ([h] if h else [])
    m = re.match(r"^RSA-(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)$", s)  # Node createSign('RSA-SHA256')
    if m:
        return [rsa(primitive="signature")] + [x for x in [_hash(m.group(1))] if x]
    m = re.match(r"^(RS|PS|ES|HS)(256|384|512)$", s)  # JOSE / JWT algorithms
    if m and (not context or "jwt" in context.lower() or "jws" in context.lower() or "jose" in context.lower()
              or "algorithm" in context.lower() or "alg" in context.lower()):
        kind, bits = m.groups()
        h = hash_alg(f"SHA-{bits}")
        if kind in ("RS", "PS"):
            return [rsa(primitive="signature"), h]
        if kind == "ES":
            return [ec("ECDSA", {"256": "P-256", "384": "P-384", "512": "P-521"}[bits]), h]
        return [Algorithm("HMAC", "mac", SAFE, 2 if bits == "256" else 4, int(bits) // 2, parameter_set=f"HMAC-SHA{bits}")]
    if s == "NONE" and context and "alg" in context.lower():
        return [broken("JWT-none", "signature", "unsigned JWTs ('alg: none') can be forged")]
    if s == "EDDSA":
        return [Algorithm("EdDSA", "signature", VULNERABLE, 0, 128, curve="Ed25519")]

    m = _AES_MODE_FIRST.match(s)
    if m:
        return [aes(int(m.group(2)) if m.group(2) else None, m.group(1))]
    m = _AES.match(s)
    if m:
        mode = m.group(2)
        mode = re.sub(r"\d+$", "", mode) if mode else None
        if mode in ("KW", "WRAP"):
            mode = None
        return [aes(int(m.group(1)) if m.group(1) else None, mode)]
    if re.match(r"^(DESEDE|TRIPLEDES|3DES|DES-EDE3|DES_EDE3|DES3|TDEA|DES-EDE)", s):
        return [broken("3DES", "block-cipher", "3DES is deprecated (NIST, 2023); use AES-256-GCM")]
    if re.match(r"^DES(?:$|[-_/])", s):
        return [broken("DES", "block-cipher", "DES uses a 56-bit key and is broken; use AES-256-GCM")]
    if s in ("RC4", "ARCFOUR", "ARC4") or s.startswith("RC4-") or s.startswith("RC4_"):
        return [broken("RC4", "stream-cipher", "RC4 is broken; use AES-GCM or ChaCha20-Poly1305")]
    if s.startswith("RC2"):
        return [broken("RC2", "block-cipher", "RC2 is broken")]
    if s.startswith("BLOWFISH") or s.startswith("BF-") or s == "BF":
        return [broken("Blowfish", "block-cipher", "Blowfish has a 64-bit block; use AES")]
    if s.startswith("CHACHA20") or s.startswith("XCHACHA20"):
        return [Algorithm("ChaCha20-Poly1305" if "POLY" in s else "ChaCha20", "ae" if "POLY" in s else "stream-cipher",
                          SAFE, 5, 256, key_size=256)]
    m = re.match(r"^HMAC[-_]?(MD5|SHA1|SHA-1|SHA224|SHA256|SHA-256|SHA384|SHA512|SHA-512)$", s)
    if m:
        h = m.group(1).replace("-", "")
        if h in ("MD5", "SHA1"):
            return [Algorithm("HMAC", "mac", WEAKENED, 1, parameter_set=f"HMAC-{h}",
                              note=f"HMAC-{h} is still unbroken but deprecated; move to HMAC-SHA256")]
        return [Algorithm("HMAC", "mac", SAFE, 2 if h in ("SHA224", "SHA256") else 4, parameter_set=f"HMAC-{h}")]
    h = _hash(s)
    if h:
        return [h]
    if re.match(r"^RSA(?:$|[-_/]|SSA|ES|-?OAEP|-?PSS|-?KEM|ENCRYPTION)", s):
        return [rsa(primitive="signature" if ("PSS" in s or "SSA" in s or "SIGN" in context.upper()) else "pke")]
    if s in ("ED25519", "ED448"):
        return [Algorithm("EdDSA", "signature", VULNERABLE, 0, 128 if s == "ED25519" else 224, curve=s.title())]
    if s in ("X25519", "X448", "CURVE25519"):
        return [Algorithm("ECDH", "key-agree", VULNERABLE, 0, 128 if s != "X448" else 224,
                          curve="X25519" if s != "X448" else "X448")]
    if s in ("ECDSA", "SHA256WITHECDSA"):
        return [ec("ECDSA")]
    if s in ("ECDH", "ECDHE", "ECMQV"):
        return [ec("ECDH")]
    if s in ("EC",):
        return [ec("EC")]
    if s in ("DSA", "DSS"):
        return [dsa()]
    if s in ("DH", "DIFFIEHELLMAN", "DHE", "FFDH", "X9.42DH"):
        return [Algorithm("DH", "key-agree", VULNERABLE, 0)]
    if s.startswith("PBKDF2") or s in ("SCRYPT", "ARGON2", "ARGON2ID", "ARGON2I", "BCRYPT", "HKDF"):
        fam = "PBKDF2" if s.startswith("PBKDF2") else s.title()
        return [Algorithm(fam, "kdf", SAFE, 0)]
    return []


def dsa(bits: int | None = None) -> Algorithm:
    return Algorithm("DSA", "signature", BROKEN, 0, key_size=bits,
                     note="DSA was withdrawn in FIPS 186-5 and is quantum-vulnerable; use ML-DSA or ECDSA for now")


RECOMMENDATIONS = {
    "RSA": "Plan migration to ML-KEM (FIPS 203) for key establishment and ML-DSA (FIPS 204) for signatures; "
           "use hybrids (e.g. X25519MLKEM768) during transition.",
    "ECDSA": "Plan migration to ML-DSA (FIPS 204), or hybrid ECDSA+ML-DSA certificates where supported.",
    "ECDH": "Move to hybrid key exchange X25519MLKEM768 (TLS 1.3, OpenSSL 3.5+, Go 1.24+, Chrome, Cloudflare).",
    "EC": "Elliptic-curve keys are quantum-vulnerable; plan migration to ML-KEM / ML-DSA.",
    "EdDSA": "Plan migration to ML-DSA (FIPS 204) or a hybrid signature.",
    "DH": "Move to hybrid key exchange X25519MLKEM768.",
    "DSA": "Replace DSA now (withdrawn in FIPS 186-5); target ML-DSA.",
    "AES": "Use AES-256 in GCM mode for long-lived data (CNSA 2.0).",
    "3DES": "Replace with AES-256-GCM.", "DES": "Replace with AES-256-GCM.", "RC4": "Replace with AES-GCM or ChaCha20-Poly1305.",
    "RC2": "Replace with AES-256-GCM.", "Blowfish": "Replace with AES-256-GCM.",
    "MD5": "Replace with SHA-256 or SHA-3 (or a password hash such as Argon2id if hashing passwords).",
    "MD4": "Replace with SHA-256.", "MD2": "Replace with SHA-256.",
    "SHA-1": "Replace with SHA-256 or SHA-3.", "HMAC": "Use HMAC-SHA256 or stronger.",
    "JWT-none": "Reject unsigned tokens; pin the expected algorithm when verifying.",
}
