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

    std::cout << "Validating certificate signature against self: " << certificateValidator->Verify(x509CertificateFile, x509CertificateFile)
                << " | " << certificateValidator->VerifyUsingX509Store(x509CertificateFile, x509CertificateFile) << "\n";
    std::cout << "Validating certificate signature against default trusted CA: " << certificateValidator->Verify(x509CertificateFile) << "\n";
}

void JwtTokenVerification::VerifyWithPublicCertificateWithSignatureVerification(const std::string& privateKeyFile, const std::string &x509CertificateFile, const std::string& rootCaFile)
{
    std::string updatedToken = getUpdatedToken(privateKeyFile);
    
    std::cout << "Checking validity of updated token: \n";
    tokenSerializer->checkValidity(updatedToken, x509CertificateFile);

    std::cout << "Validating certificate signature against root CA: " << certificateValidator->Verify(x509CertificateFile, rootCaFile)
                << " | " << certificateValidator->VerifyUsingX509Store(x509CertificateFile, rootCaFile) << "\n";
    std::cout << "Validating certificate signature against default trusted CA: " << certificateValidator->Verify(x509CertificateFile) << "\n";
}

void JwtTokenVerification::VerifyWithPublicCertificateWithIntermediateCaSignatureVerification(const std::string& privateKeyFile, const std::string &x509CertificateFile, const std::string &intermediateCaFile, const std::string& rootCaFile)
{
    std::cout << "Verifying public certificate with intermediate ca verification\n";
    std::string updatedToken = getUpdatedToken(privateKeyFile);
    
    std::cout << "Checking validity of updated token: \n";
    tokenSerializer->checkValidity(updatedToken, x509CertificateFile);

    std::cout << "Validating certificate signature against intermediate CA: " << certificateValidator->Verify(x509CertificateFile, intermediateCaFile)
                << " | " << certificateValidator->VerifyUsingX509Store(x509CertificateFile, intermediateCaFile) << "\n";
    std::cout << "Validating intermediate certificate signature against root CA: " << certificateValidator->Verify(intermediateCaFile, rootCaFile)
                << " | " << certificateValidator->VerifyUsingX509Store(intermediateCaFile, rootCaFile) << "\n";
    std::cout << "Validating certificate signature against root CA: " << certificateValidator->Verify(x509CertificateFile, rootCaFile)
                << " | " << certificateValidator->VerifyUsingX509Store(x509CertificateFile, rootCaFile) << "\n";
    std::cout << "Validating certificate signature against default trusted CA: " << certificateValidator->Verify(x509CertificateFile) << "\n";
    std::cout << "Validating intermediate certificate signature against default trusted CA: " << certificateValidator->Verify(intermediateCaFile) << "\n";
}

void JwtTokenVerification::ValidateTokenWithCertificateSignatureVerification(const std::string& privateKeyFile, const std::vector<std::string>& certificateFiles)
{
    std::cout << "Verifying certificate chain\n";
    std::string updatedToken = getUpdatedToken(privateKeyFile);
    
    std::cout << "Validity of updated token: ";
    tokenSerializer->checkValidity(updatedToken, certificateFiles[0]);

    //bool res = certificateValidator->VerifyUsingX509Store(x509CertificateFile, caFiles);
    std::cout << "Validating certificate signature against CA chain: " << certificateValidator->Verify(certificateFiles)
                << " | " << certificateValidator->VerifyUsingX509Store(certificateFiles) << "\n";
}

std::string JwtTokenVerification::getUpdatedToken(const std::string& privateKeyFile)
{
    //std::cout << "Original token claims: \n";
    //tokenSerializer->printOriginalTokenClaims();

    //std::cout << "Modifying original jwt token.\n";
    auto updatedToken = tokenSerializer->updateToken(privateKeyFile);
    
    //std::cout << "Updated token claims: \n";
    //tokenSerializer->printTokenClaims(updatedToken);

    return updatedToken;
}
