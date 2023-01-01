#include <iostream>
#include <Config.h>
#include <FileIoUtils.h>
#include <JwtTokenSerializer.h>
#include <JwtTokenVerification.h>
#include <Runner.h>
#include <RsaKeyPair.h>
#include <X509Certificate.h>


void Runner::ValidateOriginalToken(std::string& jwtToken)
{
    std::cout << "Original token claims:\n";
    JwtTokenSerializer::printTokenClaims(jwtToken);
    JwtTokenVerification::ValidateWithPublicKey(jwtToken, FileIoUtils::getFileContents(OriginalTokenParams.publicKeyFile));
}

void Runner::ValidateWithInMemoryKeys(std::string& jwtToken)
{
    auto keyPairHelper = std::make_unique<RsaKeyPair>(4096);
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

void Runner::ValidateWithInMemoryCert(std::string& jwtToken) 
{
    std::string rootCname = "root";
    std::shared_ptr<X509Certificate> x509Cert = std::make_shared<X509Certificate>(rootCname);
    x509Cert
        ->createCsr()
        ->setCommonFields()
        ->addExtensions(x509Cert, true)
        ->sign(x509Cert);   // self sign

    std::vector<std::string> caCerts;
    caCerts.push_back(x509Cert->getPublicCert());
    
    std::string updatedToken = JwtTokenSerializer::updateToken(jwtToken, x509Cert->getPrivateKey());
    std::cout << "Updated token claims (checking with in memory cert):\n";
    JwtTokenSerializer::printTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicCertificate(updatedToken, caCerts);
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

void Runner::ValidateWithInMemoryRootCert(std::string& jwtToken) {
    std::string rootCname = "root";
    std::shared_ptr<X509Certificate> rootCert = std::make_shared<X509Certificate>(rootCname);
    rootCert
        ->createCsr()
        ->setCommonFields()
        ->addExtensions(rootCert, true)
        ->sign(rootCert);   // self sign

    std::string leafCname = "leaf";
    std::shared_ptr<X509Certificate> leafCert = std::make_unique<X509Certificate>(leafCname);
    leafCert
        ->createCsr()
        ->setCommonFields()
        ->addExtensions(rootCert, false)
        ->sign(rootCert);

    std::vector<std::string> caCerts;
    caCerts.push_back(leafCert->getPublicCert());
    caCerts.push_back(rootCert->getPublicCert());
    
    std::string updatedToken = JwtTokenSerializer::updateToken(jwtToken, leafCert->getPrivateKey());
    std::cout << "Updated token claims (checking with in memory root cert):\n";
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

void Runner::ValidateWithInMemoryIntermediateCert(std::string& jwtToken) {
    std::string rootCname = "root";
    std::shared_ptr<X509Certificate> rootCert = std::make_shared<X509Certificate>(rootCname);
    rootCert
        ->createCsr()
        ->setCommonFields()
        ->addExtensions(rootCert, true)
        ->sign(rootCert);   // self sign

    std::string intermediateCname = "intermediate";
    std::shared_ptr<X509Certificate> intermediateCert = std::make_shared<X509Certificate>(intermediateCname);
    intermediateCert
        ->createCsr()
        ->setCommonFields()
        ->addExtensions(rootCert, true)
        ->sign(rootCert);

    std::string leafCname = "leaf";
    std::shared_ptr<X509Certificate> leafCert = std::make_unique<X509Certificate>(leafCname);
    leafCert
        ->createCsr()
        ->setCommonFields()
        ->addExtensions(intermediateCert, false)
        ->sign(intermediateCert);

    std::vector<std::string> caCerts;
    caCerts.push_back(leafCert->getPublicCert());
    caCerts.push_back(intermediateCert->getPublicCert());
    caCerts.push_back(rootCert->getPublicCert());
    
    std::string updatedToken = JwtTokenSerializer::updateToken(jwtToken, leafCert->getPrivateKey());
    std::cout << "Updated token claims (checking with in memory intermediate cert):\n";
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
