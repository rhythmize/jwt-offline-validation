#ifndef _X509CertificateChainValidator_H_
#define _X509CertificateChainValidator_H_

#include <memory>
#include <string>
#include <vector>

class X509CertificateChainValidator
{
public:
    X509CertificateChainValidator(std::string trustedCertificate);
    bool ValidateCertificateChain(const std::vector<std::string>& caCertificates);

private:
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> trustStore;
};

#endif // _X509CertificateChainValidator_H_
