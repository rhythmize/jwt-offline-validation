#include <iostream>
#include <Config.h>
#include <FileIoUtils.h>
#include <JwtTokenSerializer.h>
#include <JwtTokenVerification.h>
#include <Runner.h>

#include <memory>
#include <RsaKeyPairHelper.h>


void Runner::ValidateOriginalToken(std::string& jwtToken)
{
    std::cout << "Original token claims:\n";
    JwtTokenSerializer::printTokenClaims(jwtToken);
    JwtTokenVerification::ValidateWithPublicKey(jwtToken, FileIoUtils::getFileContents(OriginalTokenParams.publicKeyFile));
}

void Runner::ValidateWithInMemoryKeys(std::string& jwtToken)
{
    auto keyPairHelper = std::make_unique<RsaKeyPairHelper>(4096);
    std::string updatedToken = JwtTokenSerializer::updateToken(jwtToken, keyPairHelper->getPrivateKey());
    std::cout << "Updated token claims (checking with in memory keys):\n";
    JwtTokenSerializer::printTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicKey(updatedToken, keyPairHelper->getPublicKey());
}

void Runner::ModifyTokenAndValidateAgainstCustomPublicKey(std::string& jwtToken)
{
    std::string updatedToken = JwtTokenSerializer::updateToken(jwtToken, FileIoUtils::getFileContents(TokenSignedWithCustomKeyPairParams.privateKeyFile));
    std::cout << "Updated token claims (checking with public key):\n";
    JwtTokenSerializer::printTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicKey(updatedToken, FileIoUtils::getFileContents(TokenSignedWithCustomKeyPairParams.publicKeyFile));
}

void Runner::ModifyTokenAndValidateAgainstSelfSignedCertificate(std::string& jwtToken)
{
    std::vector<std::string> caCerts;
    caCerts.clear();
    for(const std::string& file : TokenSignedWithSelfSignedParams.caCertFiles)
        caCerts.push_back(FileIoUtils::getFileContents(file));
    std::string updatedToken = JwtTokenSerializer::updateToken(jwtToken, FileIoUtils::getFileContents(TokenSignedWithSelfSignedParams.privateKeyFile));
    std::cout << "Updated token claims (checking with self signed cert):\n";
    JwtTokenSerializer::printTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicCertificate(updatedToken, caCerts);
}

void Runner::ModifyTokenAndValidateAgainstRootCaSignedCertificate(std::string& jwtToken)
{
    std::vector<std::string> caCerts;
    caCerts.clear();
    for(const std::string& file : TokenSignedWithRootCaParams.caCertFiles)
        caCerts.push_back(FileIoUtils::getFileContents(file));
    
    std::string updatedToken = JwtTokenSerializer::updateToken(jwtToken, FileIoUtils::getFileContents(TokenSignedWithRootCaParams.privateKeyFile));
    std::cout << "Updated token claims (checking with root -> leaf cert):\n";
    JwtTokenSerializer::printTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicCertificate(updatedToken, caCerts);
}

void Runner::ModifyTokenAndValidateAgainstIntermediateCaSignedCertificate(std::string& jwtToken)
{
    std::vector<std::string> caCerts;
    caCerts.clear();
    for(const std::string& file : TokenSignedWithIntermediateCaParams.caCertFiles)
        caCerts.push_back(FileIoUtils::getFileContents(file));
    
    std::string updatedToken = JwtTokenSerializer::updateToken(jwtToken, FileIoUtils::getFileContents(TokenSignedWithIntermediateCaParams.privateKeyFile));
    std::cout << "Updated token claims (checking with root -> intermediate -> leaf certs):\n";
    JwtTokenSerializer::printTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicCertificate(updatedToken, caCerts);
}
