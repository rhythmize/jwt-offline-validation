#include <iostream>
#include <jwt-cpp/jwt.h>
#include <FileIoUtils.h>
#include <JwtTokenSerializer.h>
#include <JwtTokenVerificationWithPublicKey.h>
#include <JwtTokenVerificationWithCertificate.h>

int main(int argc, char *argv[])
{
    std::unique_ptr<FileIoUtils> fileIoUtils = std::make_unique<FileIoUtils>();

    std::string publicKeyFile = "certs/trusted_flight/auth_server_public_key.pem";
    std::string jwtTokenFile = "certs/trusted_flight/aerobridge_trusted_flight.jwt.json";
    std::string jwtToken;

    if(!fileIoUtils->getFileContents(jwtTokenFile, jwtToken)) {
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
