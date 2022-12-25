#include <iostream>
#include <JwtTokenSerializer.h>
#include <JwtTokenVerification.h>
#include <X509CertificateChainValidator.h>


void JwtTokenVerification::ValidateWithPublicKey(const std::string& token, const std::string& publicKey)
{
   JwtTokenSerializer::checkValidity(token, publicKey);
}

void JwtTokenVerification::ValidateWithPublicCertificate(const std::string& token, const std::vector<std::string>& caCerts)
{
    std::cout << "Cert Validation: " << X509CertificateChainValidator::VerifyUsingX509Store(caCerts) << "\n";
    JwtTokenSerializer::checkValidity(token, caCerts[0]);
}
