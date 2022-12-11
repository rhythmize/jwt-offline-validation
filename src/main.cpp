#include <iostream>
#include <jwt-cpp/jwt.h>
#include <FileIoUtils.h>
#include <JwtTokenSerializer.h>
#include <JwtTokenVerification.h>

int main(int argc, char *argv[])
{
    std::unique_ptr<FileIoUtils> fileIoUtils = std::make_unique<FileIoUtils>();

    std::string originalPublicKeyFile = "certs/trusted_flight/auth_server_public_key.pem";
    std::string jwtTokenFile = "certs/trusted_flight/aerobridge_trusted_flight.jwt.json";
    std::string jwtToken = fileIoUtils->getFileContents(jwtTokenFile);

    std::unique_ptr<JwtTokenSerializer> tokenSerializer = std::make_unique<JwtTokenSerializer>(jwtToken);
    std::cout << "Original token claims:\n";
    tokenSerializer->printTokenClaims(jwtToken);
    tokenSerializer->checkValidity(jwtToken, originalPublicKeyFile);

    std::cout << "=========================================================\n\n";
    
    auto tokenVerification = std::make_unique<JwtTokenVerification>(jwtToken);

    std::string privateKeyFile = "certs/test_keys/test_private.pem";
    std::string publicKeyFile = "certs/test_keys/test_public.pem";
    tokenVerification->VerifyWithPublicKey(privateKeyFile, publicKeyFile);

    std::cout << "=========================================================\n\n";
    std::string privateKeyFile2 = "certs/test_signed_cert/private.pem";
    std::string publicCertFile = "certs/test_signed_cert/certificate.crt";
    tokenVerification->VerifyWithPublicCertificate(privateKeyFile2, publicCertFile);
}
