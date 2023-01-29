#ifndef _X509CertificateChainValidator_H_
#define _X509CertificateChainValidator_H_

#include <memory>
#include <string>
#include <picojson/picojson.h>

class X509CertificateChainValidator
{
public:
    X509CertificateChainValidator(std::string trustedCertificate);
    bool ValidateCertificateChain(picojson::array caCertificates);

private:
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> trustStore;
};

#endif // _X509CertificateChainValidator_H_
