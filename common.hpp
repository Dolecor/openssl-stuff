#include <string>
#include <openssl/ssl.h>

#ifndef COMMON_H
#define COMMON_H

static const char* SERVER_AUTH_OK = "y";
static const char* SERVER_AUTH_ERR = "n";

static const char* NEED_VFY_Y = "y";
static const char* NEED_VFY_N = "n";

// Operations with X509 certificate
std::string saveCertificate(X509 *pCert, std::string certPath);
std::string getSha1CertFingerprint(X509 *pCert);
std::string getSubjNameHash(X509 *pCert);
bool recvCertificate(int sock, std::string &certTempFile);
void moveOrRemoveTempCert(std::string tempName, std::string certName, bool isAlreadyTrusted);
bool isFileExists(const char* filename);

// Send data via socket
bool sendData(int sock, const void *buf, int len);
bool sendLong(int sock, long int value);
bool sendFile(int sock, FILE *hFile);

// Read data via socket
bool recvData(int sock, void *buf, int len);
bool recvLong(int sock, long int &value);
bool recvFile(int sock, FILE *hFile);

#endif //COMMON_H
