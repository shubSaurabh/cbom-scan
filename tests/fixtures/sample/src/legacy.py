import hashlib, ssl, requests
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def fingerprint(data):
    return hashlib.md5(data).hexdigest()  # legacy cache key

key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
signer = ec.generate_private_key(ec.SECP256R1())
cipher = Cipher(algorithms.AES(k), modes.ECB())
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
requests.get("https://internal", verify=False)
token = jwt.encode(claims, priv, algorithm="RS256")
digest = hashlib.sha256(b"ok").digest()
