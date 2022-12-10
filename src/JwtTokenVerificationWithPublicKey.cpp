#include <iostream>
#include <JwtTokenSerializer.h>
#include <JwtTokenVerificationWithPublicKey.h>


void JwtTokenVerificationWithPublicKey::Run(std::string jwtToken)
{
    std::unique_ptr<JwtTokenSerializer> tokenSerializer = std::make_unique<JwtTokenSerializer>(jwtToken);
    std::cout << "Original token claims: \n";
    tokenSerializer->printTokenClaims();
    tokenSerializer->updateToken(private_key_file);
    std::cout << "Updated token claims: \n";
    tokenSerializer->printTokenClaims();
    tokenSerializer->checkValidity(public_key_file);
}
