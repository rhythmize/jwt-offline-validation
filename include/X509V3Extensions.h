#ifndef _X509V3Extensions_H_
#define _X509V3Extensions_H_

#include <memory>
#include <openssl/x509v3.h>


class X509V3Extensions
{
public:
    X509V3Extensions(std::shared_ptr<X509> cert);
    X509V3Extensions* SetContext(std::shared_ptr<X509> issuer, std::shared_ptr<X509_REQ> x509Req);
    void AddCaCertificateExtensions();
    void AddServerCertificateExtensions();

private:
    void addSubjectKeyIdentifierExtension();
    void addAuthorityKeyIdentifierExtension(bool isCaCert);
    void addBasicConstraintsExtension(bool isCaCert);
    void addKeyUsageExtension(bool isCaCert);
    void addNsCertTypeExtension();
    void addNsCommentExtension();
    void addExtension(int extensionNid, unsigned char *ext_der, int ext_len, int critical);
    
    std::unique_ptr<X509V3_CTX> x509V3Ctx;
    std::shared_ptr<X509> x509Cert;
};

#endif // _X509V3Extensions_H_
