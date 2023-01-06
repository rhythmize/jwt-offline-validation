#ifndef _X509CertificateChainValidator_H_
#define _X509CertificateChainValidator_H_

#include <string>
#include <vector>

class X509CertificateChainValidator
{
public:
    static bool VerifyUsingX509Store(const std::vector<std::string>& caCertificates);
    static void PrintCertificateInfo(const std::string& certificate);
};

#endif // _X509CertificateChainValidator_H_
