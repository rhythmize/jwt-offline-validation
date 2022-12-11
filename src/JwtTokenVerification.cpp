#include <iostream>
#include <JwtTokenVerification.h>

JwtTokenVerification::JwtTokenVerification(const std::string& jwtToken)
{
    tokenSerializer = std::make_unique<JwtTokenSerializer>(jwtToken);
}

void JwtTokenVerification::VerifyWithPublicKey(const std::string& privateKeyFile, const std::string &publicKeyFile)
{
    std::string updatedToken = getUpdatedToken(privateKeyFile);

    std::cout << "Checking validity of updated token: \n";
    tokenSerializer->checkValidity(updatedToken, publicKeyFile);
} 

void JwtTokenVerification::VerifyWithPublicCertificate(const std::string& privateKeyFile, const std::string &x509CertificateFile)
{
    std::string updatedToken = getUpdatedToken(privateKeyFile);
    
    std::cout << "Checking validity of updated token: \n";
    tokenSerializer->checkValidity(updatedToken, x509CertificateFile);

    std::cout << "Validating certificate signature against self: " << certificateValidator->Verify(x509CertificateFile, x509CertificateFile) << "\n";
    std::cout << "Validating certificate signature against default trusted CA: " << certificateValidator->Verify(x509CertificateFile) << "\n";
}

std::string JwtTokenVerification::getUpdatedToken(const std::string& privateKeyFile)
{
    std::cout << "Original token claims: \n";
    tokenSerializer->printOriginalTokenClaims();

    std::cout << "Modifying original jwt token.\n";
    auto updatedToken = tokenSerializer->updateToken(privateKeyFile);
    
    std::cout << "Updated token claims: \n";
    tokenSerializer->printTokenClaims(updatedToken);

    return updatedToken;
}
