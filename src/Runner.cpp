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
    JwtTokenSerializer::PrintTokenClaims(jwtToken);
    JwtTokenVerification::ValidateWithPublicKey(jwtToken, FileIoUtils::getFileContents(OriginalTokenParams.publicKeyFile));
}

void Runner::ValidateWithInMemoryKeys(std::string& jwtToken)
{
    auto keyPairHelper = std::make_unique<RsaKeyPair>(4096);
    std::string updatedToken = JwtTokenSerializer::ModifyAndSignToken(jwtToken, keyPairHelper->GetPrivateKey());
    std::cout << "Updated token claims (checking with in memory keys):\n";
    JwtTokenSerializer::PrintTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicKey(updatedToken, keyPairHelper->GetPublicKey());
}

void Runner::ModifyTokenAndValidateAgainstCustomPublicKey(std::string& jwtToken)
{
    std::string updatedToken = JwtTokenSerializer::ModifyAndSignToken(jwtToken, FileIoUtils::getFileContents(TokenSignedWithCustomKeyPairParams.privateKeyFile));
    std::cout << "Updated token claims (checking with public key):\n";
    JwtTokenSerializer::PrintTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicKey(updatedToken, FileIoUtils::getFileContents(TokenSignedWithCustomKeyPairParams.publicKeyFile));
}

void Runner::ValidateWithInMemoryCert(std::string& jwtToken) 
{
    std::string rootCname = "root";
    std::shared_ptr<X509Certificate> x509Cert = std::make_shared<X509Certificate>(rootCname);
    x509Cert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsCaCert(x509Cert);   // self sign

    std::vector<std::string> caCerts;
    caCerts.push_back(x509Cert->GetPublicCert());
    
    std::string updatedToken = JwtTokenSerializer::ModifyAndSignToken(jwtToken, x509Cert->GetPrivateKey());
    std::cout << "Updated token claims (checking with in memory cert):\n";
    JwtTokenSerializer::PrintTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicCertificate(updatedToken, caCerts);
}

void Runner::ModifyTokenAndValidateAgainstSelfSignedCertificate(std::string& jwtToken)
{
    std::vector<std::string> caCerts;
    caCerts.clear();
    for(const std::string& file : TokenSignedWithSelfSignedParams.caCertFiles)
        caCerts.push_back(FileIoUtils::getFileContents(file));
    std::string updatedToken = JwtTokenSerializer::ModifyAndSignToken(jwtToken, FileIoUtils::getFileContents(TokenSignedWithSelfSignedParams.privateKeyFile));
    std::cout << "Updated token claims (checking with self signed cert):\n";
    JwtTokenSerializer::PrintTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicCertificate(updatedToken, caCerts);
}

void Runner::ValidateWithInMemoryRootCert(std::string& jwtToken) {
    std::string rootCname = "root";
    std::shared_ptr<X509Certificate> rootCert = std::make_shared<X509Certificate>(rootCname);
    rootCert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsCaCert(rootCert);   // self sign

    std::string leafCname = "leaf";
    std::shared_ptr<X509Certificate> leafCert = std::make_unique<X509Certificate>(leafCname);
    leafCert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsServerCert(rootCert);

    std::vector<std::string> caCerts;
    caCerts.push_back(leafCert->GetPublicCert());
    caCerts.push_back(rootCert->GetPublicCert());
    
    std::string updatedToken = JwtTokenSerializer::ModifyAndSignToken(jwtToken, leafCert->GetPrivateKey());
    std::cout << "Updated token claims (checking with in memory root cert):\n";
    JwtTokenSerializer::PrintTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicCertificate(updatedToken, caCerts);
}

void Runner::ModifyTokenAndValidateAgainstRootCaSignedCertificate(std::string& jwtToken)
{
    std::vector<std::string> caCerts;
    caCerts.clear();
    for(const std::string& file : TokenSignedWithRootCaParams.caCertFiles)
        caCerts.push_back(FileIoUtils::getFileContents(file));
    
    std::string updatedToken = JwtTokenSerializer::ModifyAndSignToken(jwtToken, FileIoUtils::getFileContents(TokenSignedWithRootCaParams.privateKeyFile));
    std::cout << "Updated token claims (checking with root -> leaf cert):\n";
    JwtTokenSerializer::PrintTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicCertificate(updatedToken, caCerts);
}

void Runner::ValidateWithInMemoryIntermediateCert(std::string& jwtToken) {
    std::string rootCname = "root";
    std::shared_ptr<X509Certificate> rootCert = std::make_shared<X509Certificate>(rootCname);
    rootCert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsCaCert(rootCert);   // self sign

    std::string intermediateCname = "intermediate";
    std::shared_ptr<X509Certificate> intermediateCert = std::make_shared<X509Certificate>(intermediateCname);
    intermediateCert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsCaCert(rootCert);

    std::string leafCname = "leaf";
    std::shared_ptr<X509Certificate> leafCert = std::make_unique<X509Certificate>(leafCname);
    leafCert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsServerCert(intermediateCert);

    std::vector<std::string> caCerts;
    caCerts.push_back(leafCert->GetPublicCert());
    caCerts.push_back(intermediateCert->GetPublicCert());
    caCerts.push_back(rootCert->GetPublicCert());
    
    std::string updatedToken = JwtTokenSerializer::ModifyAndSignToken(jwtToken, leafCert->GetPrivateKey());
    std::cout << "Updated token claims (checking with in memory intermediate cert):\n";
    JwtTokenSerializer::PrintTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicCertificate(updatedToken, caCerts);
}

void Runner::ModifyTokenAndValidateAgainstIntermediateCaSignedCertificate(std::string& jwtToken)
{
    std::vector<std::string> caCerts;
    caCerts.clear();
    for(const std::string& file : TokenSignedWithIntermediateCaParams.caCertFiles)
        caCerts.push_back(FileIoUtils::getFileContents(file));
    
    std::string updatedToken = JwtTokenSerializer::ModifyAndSignToken(jwtToken, FileIoUtils::getFileContents(TokenSignedWithIntermediateCaParams.privateKeyFile));
    std::cout << "Updated token claims (checking with root -> intermediate -> leaf certs):\n";
    JwtTokenSerializer::PrintTokenClaims(updatedToken);
    JwtTokenVerification::ValidateWithPublicCertificate(updatedToken, caCerts);
}
