#include <iostream>
#include <jwt-cpp/jwt.h>
#include <TokenHelper.h>
#include <JwtTokenSerializer.h>
#include <JwtTokenVerificationWithPublicKey.h>
#include <JwtTokenVerificationWithCertificate.h>

int main(int argc, char *argv[])
{
    std::unique_ptr<TokenHelper> tokenHelper = std::make_unique<TokenHelper>();

    std::string publicKeyFile = "certs/trusted_flight/auth_server_public_key.pem";
    std::string jwtTokenFile = "certs/trusted_flight/aerobridge_trusted_flight.jwt.json";
    std::string jwtToken;

    if(!tokenHelper->getFileContents(jwtTokenFile, jwtToken)) {
        return -1;
    }

    std::unique_ptr<JwtTokenSerializer> tokenSerializer = std::make_unique<JwtTokenSerializer>(jwtToken);
    std::cout << "Original token claims:\n";
    tokenSerializer->printTokenClaims();
    tokenSerializer->checkValidity(publicKeyFile);

    std::cout << "=========================================================\n\n";
    
    std::make_unique<JwtTokenVerificationWithPublicKey>()->Run(jwtToken);

    std::cout << "=========================================================\n\n";
    
    std::make_unique<JwtTokenVerificationWithCertificate>()->Run(jwtToken);
}
