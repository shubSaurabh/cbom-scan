#include <openssl/evp.h>
void f() {
    const EVP_CIPHER *c = EVP_des_ede3_cbc();
    const EVP_MD *m = EVP_sha256();
    RSA_generate_key_ex(rsa, 4096, e, NULL);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
}
