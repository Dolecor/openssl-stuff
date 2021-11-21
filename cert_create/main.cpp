/**
 * https://insujang.github.io/2020-01-07/self-signed-certificate/
 * https://www.opennet.ru/docs/RUS/ldap_apacheds/tech/ssl.html
 */
#include <iostream>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ec.h>



void InitOpenSSLLib(void)
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

EVP_PKEY* genRsaKeyPair(int bits)
{
    EVP_PKEY* pkey = EVP_PKEY_new();

    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, bits, bn, nullptr);

    EVP_PKEY_assign_RSA(pkey, rsa);

    BN_free(bn);

    return pkey;
}

EVP_PKEY* genEcdsaKeyPair()
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    EC_KEY_generate_key(eckey);

    EVP_PKEY_set1_EC_KEY(pkey, eckey);

    return pkey;
}

X509* genX509(EVP_PKEY *pKeyPair, const char* oName, const char* cnName)
{
    X509 *cert = X509_new();

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60*60*24*3650); // 10 years
      
    X509_set_pubkey(cert, pKeyPair);
    
    /*
        C  - CountryName - двухбуквенный код страны согласно ISO3166
        ST - StateOrProvinceName - штат или область (край)
        L  - Locality - местоположение, обычно - город
        O  - Organization - организация - название компании
        OU - OrganizationalUnit - подразделение организации, обычно - тип сертификата или бренд
        CN  - CommonName - общепринятое имя, обычно - наименование продукта или бренд
     */
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)oName, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cnName, -1, -1, 0);

    X509_set_issuer_name(cert, name);

    X509_sign(cert, pKeyPair, EVP_sha256());

    return cert;
}


int main(int argc, char *args[])
{
    if (argc != 3)
    {
        std::cout << "Usage: cert_create Organization CommonName" << std::endl;
    }

    InitOpenSSLLib();

    //EVP_PKEY *pKeyPair = genRsaKeyPair(2048);
    EVP_PKEY *pKeyPair = genEcdsaKeyPair();
    X509 *pCert = genX509(pKeyPair, args[1], args[2]);

    FILE *pkeyFile = fopen("cert.key", "wb");
    PEM_write_PrivateKey(pkeyFile, pKeyPair, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(pkeyFile);

    FILE *certFile = fopen("cert.pem", "wb");
    PEM_write_X509(certFile, pCert);
    fclose(certFile);

    X509_free(pCert);
    EVP_PKEY_free(pKeyPair);

    return 0;
}
