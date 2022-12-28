#ifndef _X509Certificate_H_
#define _X509Certificate_H_

#include <memory>
#include <openssl/x509v3.h>
#include <RsaKeyPair.h>

class X509Certificate {
public:
    X509Certificate(std::string& cname);
    std::string getPublicCert();
    std::string getPrivateKey();
    void sign(std::shared_ptr<X509Certificate> signingCertificate);
    void dumpToFile(std::string& prefix);

private:
    X509_NAME* getSubjectName();
    void addSubjectKeyIdentifierExtension(X509V3_CTX *ctx);
    void addAuthorityKeyIdentifierExtension(X509V3_CTX *ctx);
    void addBasicConstraintsExtension(X509V3_CTX *ctx);
    void addKeyUsageExtension(X509V3_CTX *ctx);
    void addExtension(int extensionNid, unsigned char *ext_der, int ext_len, int critical);
    void setVersionAndSerialNumber();
    void createRandomSerialNumber(ASN1_INTEGER *serial);
    std::unique_ptr<X509, decltype(&X509_free)> x509;
    std::unique_ptr<RsaKeyPair> keyPair = std::make_unique<RsaKeyPair>(4096);
};

#endif // _X509Certificate_H_
