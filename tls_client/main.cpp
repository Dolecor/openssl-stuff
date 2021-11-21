#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <iostream>
#include <sstream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "common.hpp"


constexpr uint16_t SERVER_PORT = 1337;
const char* CERT_FILE = NULL;
const char* CERT_PATH = "certs/";
const std::string CLIENT_CERT_PATH = "client.pem";

void initOpenssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

int openConnection(const char *hostname, int port)
{
    int sock;
    sockaddr_in addr;
    hostent *pHost = gethostbyname(hostname);

    if ( pHost == nullptr )
    {
        perror(hostname);
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    bcopy(pHost->h_addr, &addr.sin_addr, pHost->h_length);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sock);
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    return sock;
}

SSL_CTX* createCtx()
{
    const SSL_METHOD *pMethod;
    SSL_CTX* pCtx;

    pMethod = TLS_client_method();

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
    if (SSL_CTX_use_certificate_file(pCtx, "client.pem", SSL_FILETYPE_PEM) != 1)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(pCtx, "client.key", SSL_FILETYPE_PEM) != 1)
    {
        ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(pCtx, SSL_VERIFY_PEER, nullptr);

    const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    long old_opts = SSL_CTX_set_options(pCtx, flags);

    long res = SSL_CTX_load_verify_locations(pCtx, CERT_FILE, CERT_PATH);
}

bool auth(int sock, X509 *pMyCert)
{
    FILE *myCertFile;
    bool isAlreadyTrusted;
    std::string tempCertPath;
    std::string certPath;
    FILE *serverCertFile;
    X509 *pServerCert;
    char buf[sizeof(SERVER_AUTH_OK)];
    bool verified;

    // 1. Send my certificate
    myCertFile = fopen(CLIENT_CERT_PATH.c_str(), "rb");

    if (myCertFile == nullptr)
    {
        std::cout << "Can't open file" << std::endl;
        return false;
    }

    if (!sendFile(sock, myCertFile))
    {
        return false;
    }

    // 2. Get certificate from server
    if (!recvCertificate(sock, tempCertPath))
    {
        return false;
    }

    // 3. Verify certs
    serverCertFile = fopen(tempCertPath.c_str(), "rb");
    pServerCert = PEM_read_X509(serverCertFile, nullptr, nullptr, nullptr);
    fclose(serverCertFile);

    certPath = "certs/" + getSubjNameHash(pServerCert) + ".0";
//    isAlreadyTrusted = isFileExists(certPath.c_str());

    recv(sock, buf, sizeof(buf), 0);

    if (strcmp(buf, NEED_VFY_Y) == 0)
    {
        std::cout << "Check on server if next two fingerprints mathes." << std::endl
            << "Server fingerprint:\n" << getSha1CertFingerprint(pServerCert) << std::endl
            << "Client (this) fingerprint:\n" << getSha1CertFingerprint(pMyCert) << std::endl;
    }

    recv(sock, buf, sizeof(buf), 0);

    verified = strcmp(buf, SERVER_AUTH_OK) == 0;

    moveOrRemoveTempCert(tempCertPath, certPath, !verified);

    return verified;
}


int main(int argc, char *args[])
{
    if (argc != 2)
    {
        std::cout << "Hostname not specified" << std::endl;
        return EXIT_FAILURE;
    }

    int sock;
    SSL_CTX *pCtx;
    SSL *pSsl;
    const char clientMsg[] = "Hello, Server!\n";
    char buf[1024] = {};
    int len = 0;
    char *hostname = args[1];

    initOpenssl();

    sock = openConnection(hostname, SERVER_PORT);

    pCtx = createCtx();
    configureCtx(pCtx);

    pSsl = SSL_new(pCtx);
    SSL_set_fd(pSsl, sock);

    if (!auth(sock, SSL_CTX_get0_certificate(pCtx)))
    {
        std::cout << "auth() err" << std::endl;
    }
    else
    {
        std::cout << "--- Connected to server. Initiating TLS Handshake..." << std::endl;

        /* Initiate TLS handshake */
        if (SSL_connect(pSsl) != 1)
        {
            ERR_print_errors_fp(stderr);
        }
        else
        {
            /* Verification of certificate */
            X509 *pCert = SSL_get_peer_certificate(pSsl);

            if (pCert)
            {
                /* Ok. And free imidiately. */
                X509_free(pCert);
            }
            else
            {
                std::cout << "SSL_get_peer_certificate() err" << std::endl;
                return EXIT_FAILURE;
            }

            long res = SSL_get_verify_result(pSsl);

            if (res != X509_V_OK)
            {
                std::cout << "SSL_get_verify_result() err" << std::endl;
                return EXIT_FAILURE;
            }

            std::cout   << "--- TLS Handshake was successful." << std::endl
                        << "--- Ready for reading/writing operations" << std::endl;

            SSL_write(pSsl, clientMsg, strlen(clientMsg));

            len = SSL_read(pSsl, buf, sizeof(buf));
            buf[len] = '\0';

            std:: cout << "Server reply: " << buf << std::endl;

            SSL_shutdown(pSsl);
        }
    }

    close(sock);
    SSL_free(pSsl);
    SSL_CTX_free(pCtx);

    return EXIT_SUCCESS;
}