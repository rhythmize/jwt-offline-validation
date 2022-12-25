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

void JwtTokenVerification::ValidateTokenWithCertificateSignatureVerification(const std::string& privateKeyFile, const std::vector<std::string>& certificateFiles)
{
    std::cout << "Verifying certificate chain\n";
    std::string updatedToken = getUpdatedToken(privateKeyFile);
    
    std::cout << "Validity of updated token: ";
    tokenSerializer->checkValidity(updatedToken, certificateFiles[0]);

    std::cout << "Validating certificate signature against CA chain: " << certificateValidator->VerifyUsingX509Store(certificateFiles) << "\n";
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
