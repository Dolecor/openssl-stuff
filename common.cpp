#include <sstream>
#include <iostream>
#include <iomanip>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <ctime>
#include <sys/stat.h>

#include "common.hpp"


static void encodeHash(unsigned long hash, unsigned char *encodedHash)
{
    encodedHash[0] = static_cast<unsigned char>(hash >> 24);
    encodedHash[1] = static_cast<unsigned char>(hash >> 16);
    encodedHash[2] = static_cast<unsigned char>(hash >> 8);
    encodedHash[3] = static_cast<unsigned char>(hash & 0xFFU);
}

std::string saveCertificate(X509 *pCert, std::string certPath)
{
    std::string fileName = getSubjNameHash(pCert) + ".0";

    FILE *pFileCert = fopen((certPath + fileName).c_str(), "wb");
    PEM_write_X509(pFileCert, pCert);
    fclose(pFileCert);

    return fileName;
}

std::string getSha1CertFingerprint(X509 *pCert)
{
    unsigned cb;
    unsigned char md[EVP_MAX_MD_SIZE];
    const EVP_MD *digest = EVP_get_digestbyname("sha1");
    std::stringstream fingerprint;

    X509_digest(pCert, digest, md, &cb);

    fingerprint << std::hex << std::uppercase;
    for (size_t i = 0; i < cb; ++i)
    {
        fingerprint << std::setw(2) << std::setfill('0') << (int)md[i] << " ";
    }

    return fingerprint.str();
}

/* Get filename like utility c_rehash doing (first four bytes of the SHA1 subject name hash) */
std::string getSubjNameHash(X509 *pCert)
{
    unsigned char encodedHash[4];
    std::stringstream fileBaseName;
    std::string fileName;

    encodeHash(X509_subject_name_hash(pCert), encodedHash);

    fileBaseName << std::hex;

    for (size_t i = 0; i < 4; ++i)
    {
        fileBaseName << std::setw(2) << std::setfill('0') 
            << static_cast<int>(encodedHash[i]);
    }

    fileName = fileBaseName.str();

    return fileName;
}

bool isFileExists(const char* filename)
{
    struct stat buf;
    return stat(filename, &buf) == 0;
}

bool recvCertificate(int sock, std::string &certTempFile)
{
    certTempFile = "temp/" + std::to_string(time(0)) + ".pem";
    FILE *hFile = fopen(certTempFile.c_str(), "wb");

    if (!recvFile(sock, hFile))
    {
        return false;
    }

    fclose(hFile);

    return true;
}

void moveOrRemoveTempCert(std::string tempName, std::string certName, bool isRemove)
{
    if (isRemove)
    {
        remove(tempName.c_str());
    }
    else
    {
        rename(tempName.c_str(), certName.c_str());
    }
}

bool sendData(int sock, const void *buf, int len)
{
    const char *pbuf = (const char *) buf;

    while (len > 0)
    {
        int nSend = send(sock, pbuf, len, 0);

        if (nSend == -1)
        {
            std::cout << "sendData() err" << std::endl;
            return false;
        }

        pbuf += nSend;
        len -= nSend;
    }

    return true;
}

bool sendLong(int sock, long int value)
{
    value = htonl(value);
    return sendData(sock, &value, sizeof(value));
}

bool sendFile(int sock, FILE *hFile)
{
    size_t nRead;
    size_t fileSize;
    char buf[1024];

    fseek(hFile, 0, SEEK_END);
    fileSize = ftell(hFile);
    rewind(hFile);

    if (fileSize == EOF || fileSize == 0)
    {
        return false;
    }

    if (!sendLong(sock, fileSize))
    {
        return false;
    }

    do
    {
        nRead = std::min(fileSize, sizeof(buf));
        nRead = fread(buf, 1, nRead, hFile);
        
        if (nRead < 1)
        {
            return false;
        }

        if (!sendData(sock, buf, nRead))
        {
            return false;
        }

        fileSize -= nRead;
    }
    while (fileSize > 0);
    
    return true;
}

bool recvData(int sock, void *buf, int len)
{
    char *pbuf = (char *) buf;

    while (len > 0)
    {
        int nRecv = recv(sock, pbuf, len, 0);

        if (nRecv == -1)
        {
            std::cout << "readData() err" << std::endl;
            return false;
        }
        else if (nRecv == 0)
        {
            std::cout << "empty data on recv()" << std::endl;
            return false;
        }

        pbuf += nRecv;
        len -= nRecv;
    }

    return true;
}

bool recvLong(int sock, long int &value)
{
    if (!recvData(sock, &value, sizeof(value)))
    {
        return false;
    }

    value = ntohl(value);

    return true;
}

bool recvFile(int sock, FILE *hFile)
{
    size_t nRead;
    long int fileSize;
    char buf[1024];

    if(!recvLong(sock, fileSize))
    {
        return false;
    }

    if (fileSize < 1)
    {
        return false;
    }

    do
    {
        nRead = std::min((unsigned long)fileSize, sizeof(buf));

        if (!recvData(sock, buf, nRead))
        {
            return false;
        }

        int offset = 0;

        do
        {
            size_t written = fwrite(&buf[offset], 1, nRead-offset, hFile);

            if (written < 1)
            {
                return false;
            }

            offset += written;
        }
        while (offset < nRead);

        fileSize -= nRead;
    }
    while (fileSize > 0);
    
    return true;
}