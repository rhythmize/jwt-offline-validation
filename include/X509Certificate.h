#ifndef _X509Certificate_H_
#define _X509Certificate_H_

#include <memory>
#include <openssl/x509v3.h>
#include <RsaKeyPair.h>
#include <X509V3Extensions.h>

class X509Certificate {
public:
    static std::unique_ptr<X509, decltype(&X509_free)> GetX509FromDerString(std::string& derCert);

    X509Certificate(std::string& cname);
    X509Certificate* GenerateCertificateSigningRequest();
    X509Certificate* ConfigureCertificateParameters();
    void SignAsCaCert(std::shared_ptr<X509Certificate> signingCertificate);
    void SignAsServerCert(std::shared_ptr<X509Certificate> signingCertificate);
    std::string GetPublicDerCert();
    std::string GetPrivateKey();
    void PrintCertificateInfo();
    void DumpToFile();

private:
    X509_NAME* getSubjectName();
    void setVersionAndSerialNumber();
    void createRandomSerialNumber(ASN1_INTEGER *serial);
    void sign(std::shared_ptr<X509Certificate> signingCertificate);
    
    std::string certCname;
    std::shared_ptr<X509> x509;
    std::shared_ptr<X509_REQ> x509Req;
    std::unique_ptr<RsaKeyPair> keyPair;
    std::unique_ptr<X509V3Extensions> x509V3Extensions;
};

#endif // _X509Certificate_H_
