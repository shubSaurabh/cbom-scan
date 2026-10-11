"""Detection rules for cryptography in source code and configuration.

Each rule is a regex for one language family. A rule either captures the algorithm name as written
(group `alg`, e.g. Cipher.getInstance("AES/ECB/PKCS5Padding")) or names fixed algorithms
(e.g. hashlib.md5). Optional groups `bits` and `curve` capture key size and curve.
Issue rules flag insecure TLS settings that are not algorithms themselves.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

PY = {".py", ".pyi"}
JAVA = {".java", ".kt", ".kts", ".scala", ".groovy"}
GO = {".go"}
JS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
C = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".m", ".mm"}
CS = {".cs"}
RUST = {".rs"}
RUBY = {".rb"}
PHP = {".php"}
CONFIG = {".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".properties", ".json", ".xml", ".env.example", ".tf", ".hcl"}
NGINX_LIKE = CONFIG | {""}  # nginx.conf, httpd.conf, sshd_config etc.
ALL_CODE = PY | JAVA | GO | JS | C | CS | RUST | RUBY | PHP
LANGUAGE = {**{e: "python" for e in PY}, **{e: "java" for e in JAVA}, **{e: "go" for e in GO},
            **{e: "javascript" for e in JS}, **{e: "c/c++" for e in C}, **{e: "c#" for e in CS},
            **{e: "rust" for e in RUST}, **{e: "ruby" for e in RUBY}, **{e: "php" for e in PHP}}

Q = r"""["'`]"""  # any quote
NAME = r"""["'`](?P<alg>[A-Za-z0-9_/\-\.]{2,60})["'`]"""


@dataclass
class Rule:
    id: str
    exts: set[str]
    pattern: re.Pattern
    algs: list[str] = field(default_factory=list)  # fixed algorithms; empty means use the `alg` group
    function: str = ""
    issue: tuple[str, str] | None = None  # (severity, message) for issue rules


def r(id: str, exts: set[str], pattern: str, algs: list[str] | None = None, function: str = "",
      issue: tuple[str, str] | None = None, flags: int = 0) -> Rule:
    return Rule(id, exts, re.compile(pattern, flags), algs or [], function, issue)


RULES: list[Rule] = [
    # ---- Python -----------------------------------------------------------------------------
    r("py-hashlib", PY, r"\bhashlib\.(?P<alg>md5|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_512|blake2b|blake2s)\s*\(", function="digest"),
    r("py-hashlib-new", PY, r"\bhashlib\.new\(\s*" + NAME, function="digest"),
    r("py-hmac", PY, r"\bhmac\.(?:new|digest)\([^)]*(?:hashlib\.|digestmod\s*=\s*[\"']?)(?P<alg>md5|sha1|sha256|sha384|sha512)", function="mac"),
    r("py-crypto-rsa", PY, r"\brsa\.generate_private_key\((?:[^)]*key_size\s*=\s*(?P<bits>\d{3,5}))?", ["RSA"], "keygen"),
    r("py-crypto-ec", PY, r"\bec\.generate_private_key\(\s*(?:curve\s*=\s*)?ec\.(?P<curve>SECP\d+[RK]1|BrainpoolP\d+R1)", ["EC"], "keygen"),
    r("py-crypto-ecdsa", PY, r"\bec\.ECDSA\(", ["ECDSA"], "sign"),
    r("py-crypto-ecdh", PY, r"\bec\.ECDH\(", ["ECDH"], "keyagree"),
    r("py-crypto-ed", PY, r"\b(?P<alg>Ed25519|Ed448)Private[Kk]ey\b", function="keygen"),
    r("py-crypto-x", PY, r"\b(?P<alg>X25519|X448)Private[Kk]ey\b", function="keyagree"),
    r("py-crypto-dsa", PY, r"\bdsa\.generate_private_key\(", ["DSA"], "keygen"),
    r("py-crypto-dh", PY, r"\bdh\.generate_parameters\(", ["DH"], "keygen"),
    r("py-crypto-cipher", PY, r"\balgorithms\.(?P<alg>AES|AES128|AES256|TripleDES|ARC4|Blowfish|CAST5|IDEA|SEED|ChaCha20|Camellia)\s*\(", function="encrypt"),
    r("py-crypto-ecb", PY, r"\bmodes\.ECB\s*\(", ["AES-ECB"], "encrypt"),
    r("py-crypto-aead", PY, r"\b(?P<alg>AESGCM|AESCCM|AESSIV|AESOCB3|ChaCha20Poly1305)\s*\(", function="encrypt"),
    r("py-crypto-hashes", PY, r"\bhashes\.(?P<alg>MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3_256|SHA3_512|BLAKE2b)\s*\(", function="digest"),
    r("py-pycryptodome-new", PY, r"\b(?P<alg>DES3|DES|ARC4|ARC2|Blowfish)\.new\(", function="encrypt"),
    r("py-pycryptodome-aes", PY, r"\bAES\.new\([^)]*AES\.MODE_(?P<mode>ECB|CBC|GCM|CTR|CFB|OFB|CCM|EAX|SIV|OCB)", function="encrypt"),
    r("py-pycryptodome-rsa", PY, r"\bRSA\.generate\(\s*(?:bits\s*=\s*)?(?P<bits>\d{3,5})", ["RSA"], "keygen"),
    r("py-pycryptodome-ecc", PY, r"\bECC\.generate\(\s*curve\s*=\s*[\"'](?P<curve>[\w\-]+)", ["EC"], "keygen"),
    r("py-pycryptodome-hash", PY, r"\b(?P<alg>MD5|SHA1|MD4)\.new\(", function="digest"),
    r("py-jwt", PY, r"\b(?:algorithm|algorithms)\s*=\s*\[?\s*" + NAME, function="sign"),
    r("py-pqc", PY, r"""\b(?:oqs\.KeyEncapsulation|oqs\.Signature|kem_alg|sig_alg)\(?\s*["'](?P<alg>[\w\-]+)""", function="keygen"),

    # ---- Java / Kotlin ----------------------------------------------------------------------
    r("java-getinstance", JAVA,
      r"\b(?:Cipher|MessageDigest|Signature|KeyPairGenerator|KeyGenerator|KeyAgreement|Mac|KeyFactory|SecretKeyFactory|KEM)"
      r"\.getInstance\(\s*" + NAME),
    r("java-keyspec", JAVA, r"\bnew\s+SecretKeySpec\([^,]+,\s*" + NAME, function="encrypt"),
    r("java-ecgenspec", JAVA, r"\bnew\s+ECGenParameterSpec\(\s*[\"'](?P<curve>[\w\-]+)", ["EC"], "keygen"),
    r("java-bc-pqc", JAVA, r"\b(?:MLKEMParameterSpec|KyberParameterSpec|MLDSAParameterSpec|DilithiumParameterSpec)\.(?P<alg>\w+)", function="keygen"),

    # ---- Go ---------------------------------------------------------------------------------
    r("go-import", GO, r"""["'](?:crypto|golang\.org/x/crypto)/(?P<alg>md5|sha1|sha256|sha512|sha3|des|rc4|dsa|rsa|ecdsa|ecdh|ed25519|curve25519|mlkem|chacha20poly1305|blowfish|md4)["']"""),
    r("go-rsa-gen", GO, r"\brsa\.GenerateKey\([^,]+,\s*(?P<bits>\d{3,5})", ["RSA"], "keygen"),
    r("go-curve", GO, r"\belliptic\.(?P<curve>P224|P256|P384|P521)\(\)", ["EC"]),
    r("go-ecdh-curve", GO, r"\becdh\.(?P<alg>X25519|P256|P384|P521)\(\)", function="keyagree"),
    r("go-mlkem", GO, r"\bmlkem\.(?:GenerateKey|NewEncapsulationKey)(?P<alg>768|1024)\b", function="keygen"),
    r("go-aes", GO, r"\baes\.NewCipher\(", ["AES"], "encrypt"),
    r("go-tls-group", GO, r"\btls\.(?P<alg>X25519MLKEM768|X25519|CurveP256|CurveP384)\b", function="keyagree"),

    # ---- JavaScript / TypeScript ------------------------------------------------------------
    r("js-node-crypto", JS, r"\b(?:createHash|createHmac|createCipheriv|createDecipheriv|createCipher|createSign|createVerify|hkdf|pbkdf2|pbkdf2Sync)\(\s*" + NAME),
    r("js-node-keypair", JS, r"\bgenerateKeyPair(?:Sync)?\(\s*" + NAME + r"(?:[^)]*?modulusLength\s*:\s*(?P<bits>\d{3,5}))?(?:[^)]*?namedCurve\s*:\s*[\"'](?P<curve>[\w\-]+))?", function="keygen"),
    r("js-webcrypto", JS, r"""\bname\s*:\s*["'](?P<alg>RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5|ECDSA|ECDH|AES-GCM|AES-CBC|AES-CTR|AES-KW|HMAC|Ed25519|X25519|PBKDF2|HKDF)["'](?:[^}]*?(?:modulusLength|length)\s*:\s*(?P<bits>\d{3,5}))?(?:[^}]*?namedCurve\s*:\s*["'](?P<curve>[\w\-]+))?"""),
    r("js-jwt", JS, r"""\b(?:algorithm|algorithms|alg)\s*:\s*\[?\s*""" + NAME, function="sign"),
    r("js-forge-rsa", JS, r"\bpki\.rsa\.generateKeyPair\(\s*\{?\s*(?:bits\s*:\s*)?(?P<bits>\d{3,5})", ["RSA"], "keygen"),
    r("js-libs", JS, r"""(?:require\(|from\s+)["'](?P<alg>md5|sha1|crypto-js/md5|crypto-js/sha1|crypto-js/tripledes|crypto-js/rc4)["']"""),

    # ---- C / C++ (OpenSSL, BoringSSL) -------------------------------------------------------
    r("c-evp-md", C, r"\bEVP_(?P<alg>md5|md4|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_512)\s*\(", function="digest"),
    r("c-evp-cipher", C, r"\bEVP_(?P<alg>(?:aes_(?:128|192|256)_(?:ecb|cbc|gcm|ctr|cfb\d*|ofb|ccm|xts))|des_ede3_\w+|des_ede_\w+|des_\w+|rc4|rc2_\w+|bf_\w+|chacha20_poly1305|chacha20)\s*\(", function="encrypt"),
    r("c-rsa-gen", C, r"\bRSA_generate_key(?:_ex)?\(\s*(?:\w+\s*,\s*)?(?P<bits>\d{3,5})?", ["RSA"], "keygen"),
    r("c-pkey", C, r"\bEVP_PKEY_(?P<alg>RSA|RSA_PSS|EC|ED25519|ED448|X25519|X448|DH|DSA|ML_KEM_\d+|ML_DSA_\d+)\b"),
    r("c-pkey-name", C, r"\bEVP_PKEY_CTX_new_from_name\([^,]*,\s*" + NAME, function="keygen"),
    r("c-nid-curve", C, r"\bNID_(?P<curve>X9_62_prime256v1|secp384r1|secp521r1|secp256k1|secp224r1|X9_62_prime192v1)\b", ["EC"]),
    r("c-legacy", C, r"\b(?P<alg>MD5|SHA1|DES_ecb_encrypt|DES_set_key)\s*\(", function="digest"),
    r("c-dsa", C, r"\bDSA_generate_parameters(?:_ex)?\(", ["DSA"], "keygen"),

    # ---- C# / .NET --------------------------------------------------------------------------
    r("cs-create", CS, r"\b(?P<alg>MD5|SHA1|SHA256|SHA384|SHA512|TripleDES|DES|RC2|Aes|ECDsa|ECDiffieHellman|DSA|HMACSHA1|HMACMD5|HMACSHA256)\.Create\(", function=""),
    r("cs-rsa", CS, r"\b(?:RSA\.Create|new\s+RSACryptoServiceProvider)\(\s*(?P<bits>\d{3,5})?", ["RSA"], "keygen"),
    r("cs-managed", CS, r"\bnew\s+(?P<alg>MD5CryptoServiceProvider|SHA1Managed|SHA1CryptoServiceProvider|TripleDESCryptoServiceProvider|DESCryptoServiceProvider|RC2CryptoServiceProvider)\b"),
    r("cs-ecb", CS, r"\bCipherMode\.ECB\b", ["AES-ECB"], "encrypt"),
    r("cs-mlkem", CS, r"\b(?P<alg>MLKem|MLDsa)\.(?:GenerateKey|ImportEncapsulationKey)\(\s*(?:MLKemAlgorithm|MLDsaAlgorithm)\.(?P<param>\w+)"),

    # ---- Rust -------------------------------------------------------------------------------
    r("rs-crates", RUST, r"\buse\s+(?P<alg>md5|sha1|md4|des|rc4|blowfish|rsa|p256|p384|ed25519_dalek|x25519_dalek|aes_gcm|chacha20poly1305|ml_kem|pqcrypto_kyber|pqcrypto_dilithium)\b"),
    r("rs-rsa-gen", RUST, r"\bRsaPrivateKey::new\([^,]+,\s*(?P<bits>\d{3,5})", ["RSA"], "keygen"),
    r("rs-ring", RUST, r"\b(?:signature|agreement)::(?P<alg>RSA_PKCS1_\w+|RSA_PSS_\w+|ECDSA_P256_\w+|ECDSA_P384_\w+|ED25519|X25519)\b"),

    # ---- Ruby / PHP -------------------------------------------------------------------------
    r("rb-openssl", RUBY, r"\bOpenSSL::(?:Digest::(?P<alg>MD5|SHA1|SHA256|SHA512)|Cipher\.new\(\s*[\"'](?P<alg2>[\w\-]+))"),
    r("rb-pkey", RUBY, r"\bOpenSSL::PKey::(?P<alg>RSA|EC|DSA|DH)\.(?:new|generate)\(\s*(?P<bits>\d{3,5})?", function="keygen"),
    r("php-legacy", PHP, r"\b(?P<alg>md5|sha1)\s*\(", function="digest"),
    r("php-openssl", PHP, r"\bopenssl_(?:encrypt|decrypt)\([^,]+,\s*" + NAME, function="encrypt"),
    r("php-hash", PHP, r"\bhash(?:_hmac)?\(\s*" + NAME, function="digest"),

    # ---- TLS / server configuration ---------------------------------------------------------
    r("cfg-tls-groups", NGINX_LIKE, r"(?i)\b(?:ssl_ecdh_curve|groups|curves|ssl_conf_command\s+Groups|SSLOpenSSLConfCmd\s+Curves|KexAlgorithms)\b[\s:=]+[\"']?(?P<list>[\w:,\-@.+]+)"),
    r("cfg-ciphers", NGINX_LIKE, r"(?i)\b(?:ssl_ciphers|SSLCipherSuite|ciphers|cipher_suites|CipherString)\b[\s:=]+[\"']?(?P<list>[\w:!+\-@.,]+)"),
]

ISSUE_RULES: list[Rule] = [
    r("tls-legacy-protocol", NGINX_LIKE | ALL_CODE,
      r"(?i:\bssl_protocols\b[^;\n]*\b(?:SSLv2|SSLv3|TLSv1|TLSv1\.1)(?:\s|;|$)|\bSSLProtocol\b[^\n]*[+\s](?:SSLv3|TLSv1|TLSv1\.1)\b(?!\.)"
      r"|^\s*MinProtocol\s*=\s*(?:TLSv1|TLSv1\.1|SSLv3)\s*$)"
      r"|SSLContext\(\s*(?:ssl\.)?PROTOCOL_(?:SSLv2|SSLv3|TLSv1|TLSv1_1)\b|ssl_version\s*=\s*(?:ssl\.)?PROTOCOL_(?:SSLv3|TLSv1|TLSv1_1)\b"
      r"|(?:minimum_version|maximum_version)\s*=\s*(?:ssl\.)?TLSVersion\.(?:SSLv3|TLSv1|TLSv1_1)\b"
      r"|MinVersion\s*[:=]\s*tls\.Version(?:TLS10|TLS11|SSL30)\b"
      r"|(?:SslProtocols|SecurityProtocol|EnabledSslProtocols)\s*=\s*[^;\n]*SslProtocols\.(?:Ssl2|Ssl3|Tls|Tls11)\b(?!\d)"
      r"|SecurityProtocolType\.(?:Ssl3|Tls|Tls11)\b(?!\d)"
      r"|set_min_proto_version\([^,]+,\s*(?:SSL3_VERSION|TLS1_VERSION|TLS1_1_VERSION)\b|\b(?:TLSv1|TLSv1_1|SSLv3)_(?:client_|server_)?method\(\)"
      r"|minVersion\s*:\s*[\"']TLSv1(?:\.1)?[\"']|secureProtocol\s*:\s*[\"'](?:TLSv1|TLSv1_1|SSLv3)_method[\"']"
      r"|SSLContext\.getInstance\(\s*\"(?:SSLv3|TLSv1|TLSv1\.1)\"\)",
      issue=("error", "Legacy SSL/TLS protocol enabled (SSLv3, TLS 1.0 or 1.1). Require TLS 1.2+, ideally TLS 1.3.")),
    r("tls-verification-disabled", ALL_CODE,
      r"(?:\b(?:requests|httpx|session|client|s)\.(?:get|post|put|patch|delete|head|request|Client|AsyncClient)\([^\n]*\bverify\s*=\s*False\b"
      r"|\.verify\s*=\s*False\b|\bInsecureSkipVerify\s*:\s*true\b|(?:verify_mode|cert_reqs)\s*=\s*(?:ssl\.)?CERT_NONE\b"
      r"|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\W+0|_create_unverified_context\(\)"
      r"|setHostnameVerifier\(\s*(?:NoopHostnameVerifier|SSLConnectionSocketFactory\.ALLOW_ALL)"
      r"|ServerCertificateValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)"
      r"|\.check_hostname\s*=\s*False)",
      issue=("error", "TLS certificate verification is disabled, which allows man-in-the-middle attacks.")),
    r("hardcoded-private-key", ALL_CODE | CONFIG,
      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
      issue=("error", "A private key is embedded in source. Move it to a secrets manager or HSM and rotate it.")),
    r("weak-random", PY | JS | JAVA,
      r"(?:\brandom\.(?:random|randint|choice|getrandbits)\([^)]*\)[^\n]*(?:key|token|secret|nonce|salt|password|iv)\b"
      r"|\b(?:key|token|secret|nonce|salt|iv)\w*\s*=\s*[^\n]*\bMath\.random\(\)"
      r"|\bnew\s+java\.util\.Random\(\)[^\n]*(?:key|token|secret|nonce|salt|iv))",
      issue=("warning", "Non-cryptographic random number generator used for secret material. Use secrets/crypto.getRandomValues/SecureRandom.")),
]

COMMENT = re.compile(r"^\s*(?:#|//|\*|/\*|--|;|<!--)")
