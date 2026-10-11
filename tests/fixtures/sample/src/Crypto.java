import javax.crypto.Cipher;
class Crypto {
    // Cipher.getInstance("RC4") in a comment must be ignored
    Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    Cipher g = Cipher.getInstance("AES/GCM/NoPadding");
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    Signature s = Signature.getInstance("SHA256withECDSA");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768");
}
