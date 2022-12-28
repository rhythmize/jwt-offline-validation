#ifndef _X509CertificateHelper_H_
#define _X509CertificateHelper_H_

#include <memory>
#include <openssl/x509v3.h>
#include <RsaKeyPairHelper.h>

class X509CertificateHelper {
public:
    X509CertificateHelper(std::string& cname);
    std::string getPublicCert();
    std::string getPrivateKey();
    void addCaExtensions();
    void sign(std::shared_ptr<X509CertificateHelper> signingCertificate);
    void dumpToFile(std::string& prefix);
private:
    X509_NAME* getSubjectName();
    void setVersionAndSerialNumber();
    void createRandomSerialNumber(ASN1_INTEGER *serial);
    std::unique_ptr<X509, decltype(&X509_free)> x509;
    std::unique_ptr<RsaKeyPairHelper> keyPair = std::make_unique<RsaKeyPairHelper>(4096);
};

#endif // _X509CertificateHelper_H_
