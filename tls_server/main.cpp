#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "common.hpp"


constexpr uint16_t PORT = 1337;
const char* CERT_FILE = NULL;
const char* CERT_PATH = "certs/";
std::string SERVER_CERT_PATH = "cert.pem";

void initOpenssl(void)
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanupOpenssl()
{
    EVP_cleanup();
}

int createSocket(uint16_t port)
{
    int sock;
    sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return sock;
}

SSL_CTX* createCtx()
{
    const SSL_METHOD *pMethod;
    SSL_CTX* pCtx;

    pMethod = TLS_server_method();

    pCtx = SSL_CTX_new(pMethod);
    
    if (!pCtx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return pCtx;
}

void configureCtx(SSL_CTX *pCtx)
{
    if (SSL_CTX_use_certificate_file(pCtx, "cert.pem", SSL_FILETYPE_PEM) != 1)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(pCtx, "cert.key", SSL_FILETYPE_PEM) != 1)
    {
        ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(pCtx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

    long res = SSL_CTX_load_verify_locations(pCtx, CERT_FILE, CERT_PATH);
}

bool auth(int sock, X509* pMyCert)
{
    FILE *myCertFile;
    bool isAlreadyTrusted;
    std::string tempCertPath;
    std::string certPath;
    FILE *clientCertFile;
    X509 *pClientCert;
    bool verified;

    // 1. Get certificate from client
    if (!recvCertificate(sock, tempCertPath))
    {
        return false;
    }

    // 2. Send my certificate
    myCertFile = fopen(SERVER_CERT_PATH.c_str(), "rb");

    if (myCertFile == nullptr)
    {
        std::cout << "Can't open file" << std::endl;
        return false;
    }

    if (!sendFile(sock, myCertFile))
    {
        return false;
    }

    // 3. Verify certs
    clientCertFile = fopen(tempCertPath.c_str(), "rb");
    pClientCert = PEM_read_X509(clientCertFile, nullptr, nullptr, nullptr);
    fclose(clientCertFile);

    certPath = "certs/" + getSubjNameHash(pClientCert) + ".0";
    isAlreadyTrusted = isFileExists(certPath.c_str());

    sendData(sock, isAlreadyTrusted ? NEED_VFY_N : NEED_VFY_Y, sizeof(NEED_VFY_Y));

    if (!isAlreadyTrusted)
    {
        std::string ans;

        std::cout << "Server (this) fingerprint:\n" << getSha1CertFingerprint(pMyCert) << std::endl
            << "Client fingerprint:\n" << getSha1CertFingerprint(pClientCert) << std::endl
            << "Are fingeprints on server and client the same? [y/N]?" << std::endl;
        
        std::cin >> ans;
        verified = ans == "y";
    }
    else
    {
        verified = true;
    }

    moveOrRemoveTempCert(tempCertPath, certPath, !verified);

    sendData(sock, verified ? SERVER_AUTH_OK : SERVER_AUTH_ERR, sizeof(SERVER_AUTH_OK));

    return verified;
}


int main()
{
    int sock;
    SSL_CTX *pCtx;

    initOpenssl();

    sock = createSocket(PORT);

    pCtx = createCtx();
    configureCtx(pCtx);

    std::cout << "--- Server started" << std::endl;

    while (true)
    {
        sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *pSsl;
        const char serverReply[] = "Hello, Client!\n";
        char buf[1024] = {};
        int bytes = 0;

        int client = accept(sock, (struct sockaddr*)&addr, &len);

        if (client < 0)
        {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        pSsl = SSL_new(pCtx);
        SSL_set_fd(pSsl, client);

        if (!auth(client, SSL_CTX_get0_certificate(pCtx)))
        {
            std::cout << "auth() err" << std::endl;
        }
        else
        {
            if (SSL_accept(pSsl) != 1)
            {
                ERR_print_errors_fp(stderr);
            }
            else
            {
                bytes = SSL_read(pSsl, buf, sizeof(buf));
                buf[bytes] = '\0';
                std:: cout << "Client msg: " << buf << std::endl;

                SSL_write(pSsl, serverReply, strlen(serverReply));

                SSL_shutdown(pSsl);
            }
        }       

        close(client);
        SSL_free(pSsl);
    }

    close(sock);
    SSL_CTX_free(pCtx);
    cleanupOpenssl();

    return EXIT_SUCCESS;
}
