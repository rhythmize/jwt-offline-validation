#ifndef _X509V3Extensions_H_
#define _X509V3Extensions_H_

#include <map>
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
    void addStringExtension(int extensionNid, std::string value, int critical);
    void addMultiValueExtension(int extensionNid, std::map<std::string, std::string> values, int critical);
    void addExtension(int extensionNid, unsigned char *ext_der, int ext_len, int critical);
    
    std::unique_ptr<X509V3_CTX> x509V3Ctx;
    std::shared_ptr<X509> x509Cert;
};

#endif // _X509V3Extensions_H_
