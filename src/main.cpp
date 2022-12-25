#include <iostream>
#include <jwt-cpp/jwt.h>
#include <FileIoUtils.h>
#include <JwtTokenSerializer.h>
#include <JwtTokenVerification.h>

int main(int argc, char *argv[])
{
    std::vector<std::string> certificateChain;
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
    privateKeyFile = "certs/test_self_signed/private.pem";
    certificateChain.push_back("certs/test_self_signed/certificate.crt");
    tokenVerification->ValidateTokenWithCertificateSignatureVerification(privateKeyFile, certificateChain);

    std::cout << "=========================================================\n\n";
    privateKeyFile = "certs/test_signed_with_rootCA/leaf/private.pem";
    certificateChain.clear();
    certificateChain.push_back("certs/test_signed_with_rootCA/leaf/certificate.crt");
    certificateChain.push_back("certs/test_signed_with_rootCA/root/certificate.crt");
    tokenVerification->ValidateTokenWithCertificateSignatureVerification(privateKeyFile, certificateChain);

    std::cout << "=========================================================\n\n";
    privateKeyFile = "certs/test_signed_with_intermediateCA/leaf/private.pem";
    certificateChain.clear();
    certificateChain.push_back("certs/test_signed_with_intermediateCA/leaf/certificate.crt");
    certificateChain.push_back("certs/test_signed_with_intermediateCA/intermediate1/certificate.crt");
    certificateChain.push_back("certs/test_signed_with_intermediateCA/intermediate2/certificate.crt");
    certificateChain.push_back("certs/test_signed_with_intermediateCA/intermediate3/certificate.crt");
    certificateChain.push_back("certs/test_signed_with_intermediateCA/intermediate4/certificate.crt");
    certificateChain.push_back("certs/test_signed_with_intermediateCA/root/certificate.crt");
    tokenVerification->ValidateTokenWithCertificateSignatureVerification(privateKeyFile, certificateChain);
}
