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
    privateKeyFile = "certs/test_self_signed/private.pem";
    std::string publicCertFile = "certs/test_self_signed/certificate.crt";
    tokenVerification->VerifyWithPublicCertificate(privateKeyFile, publicCertFile);

    std::cout << "<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>\n";
    privateKeyFile = "certs/test_self_signed/private.pem";
    std::vector<std::string> certificateChain;
    certificateChain.push_back("certs/test_self_signed/certificate.crt");
    tokenVerification->ValidateTokenWithCertificateSignatureVerification(privateKeyFile, certificateChain);

    std::cout << "=========================================================\n\n";
    privateKeyFile = "certs/test_signed_with_rootCA/private.pem";
    publicCertFile = "certs/test_signed_with_rootCA/certificate.crt";
    std::string rootCaCert = "certs/test_signed_with_rootCA/root_certificate.crt";
    tokenVerification->VerifyWithPublicCertificateWithSignatureVerification(privateKeyFile, publicCertFile, rootCaCert);

    std::cout << "<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>\n";
    privateKeyFile = "certs/test_signed_with_rootCA/private.pem";
    certificateChain.clear();
    certificateChain.push_back("certs/test_signed_with_rootCA/certificate.crt");
    certificateChain.push_back("certs/test_signed_with_rootCA/root_certificate.crt");
    tokenVerification->ValidateTokenWithCertificateSignatureVerification(privateKeyFile, certificateChain);

    std::cout << "=========================================================\n\n";
    privateKeyFile = "certs/test_signed_with_intermediateCA/private.pem";
    publicCertFile = "certs/test_signed_with_intermediateCA/certificate.crt";
    rootCaCert = "certs/test_signed_with_intermediateCA/root_certificate.crt";
    std::string intermediateCaCert = "certs/test_signed_with_intermediateCA/intermediate_certificate.crt";
    tokenVerification->VerifyWithPublicCertificateWithIntermediateCaSignatureVerification(privateKeyFile, publicCertFile, intermediateCaCert, rootCaCert);

    std::cout << "<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>\n";
    privateKeyFile = "certs/test_signed_with_intermediateCA/private.pem";
    certificateChain.clear();
    certificateChain.push_back("certs/test_signed_with_intermediateCA/certificate.crt");
    certificateChain.push_back("certs/test_signed_with_intermediateCA/intermediate_certificate.crt");
    certificateChain.push_back("certs/test_signed_with_intermediateCA/root_certificate.crt");
    tokenVerification->ValidateTokenWithCertificateSignatureVerification(privateKeyFile, certificateChain);

    std::cout << "=========================================================\n\n";
    privateKeyFile = "certs/test_signed_with_intermediateCA/check/root/ca/intermediate/private/test.key.pem";
    publicCertFile = "certs/test_signed_with_intermediateCA/check/root/ca/intermediate/certs/test.cert.pem";
    rootCaCert = "certs/test_signed_with_intermediateCA/check/root/ca/certs/ca.cert.pem";
    intermediateCaCert = "certs/test_signed_with_intermediateCA/check/root/ca/intermediate/certs/intermediate.cert.pem";
    tokenVerification->VerifyWithPublicCertificateWithIntermediateCaSignatureVerification(privateKeyFile, publicCertFile, intermediateCaCert, rootCaCert);

    std::cout << "<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>\n";
    privateKeyFile = "certs/test_signed_with_intermediateCA/check/root/ca/intermediate/private/test.key.pem";
    certificateChain.clear();
    certificateChain.push_back("certs/test_signed_with_intermediateCA/check/root/ca/intermediate/certs/test.cert.pem");
    certificateChain.push_back("certs/test_signed_with_intermediateCA/check/root/ca/intermediate/certs/intermediate.cert.pem");
    certificateChain.push_back("certs/test_signed_with_intermediateCA/check/root/ca/certs/ca.cert.pem");
    tokenVerification->ValidateTokenWithCertificateSignatureVerification(privateKeyFile, certificateChain);
}
