#include <iostream>
#include <JwtTokenSerializer.h>
#include <JwtTokenVerificationWithCertificate.h>


void JwtTokenVerificationWithCertificate::Run(std::string jwtToken)
{
    std::unique_ptr<JwtTokenSerializer> tokenSerializer = std::make_unique<JwtTokenSerializer>(jwtToken);
    std::cout << "Original token claims: \n";
    tokenSerializer->updateToken(private_key_file);
    std::cout << "Updated token claims: \n";
    tokenSerializer->printTokenClaims();
    tokenSerializer->checkValidity(public_cert_file);
}
