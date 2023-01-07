#ifndef _X509CertificateChainValidator_H_
#define _X509CertificateChainValidator_H_

#include <string>
#include <vector>

class X509CertificateChainValidator
{
public:
    static bool ValidateCertificateChain(const std::vector<std::string>& caCertificates);
};

#endif // _X509CertificateChainValidator_H_
