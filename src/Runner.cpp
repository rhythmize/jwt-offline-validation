#include <iostream>
#include <Config.h>
#include <FileIoUtils.h>
#include <JwtTokenHelper.h>
#include <Runner.h>
#include <RsaKeyPair.h>
#include <X509Certificate.h>


void Runner::ValidateOriginalToken(std::string& jwtToken, std::string& publicKey)
{
    std::cout << "Original token claims:\n";
    JwtTokenHelper::PrintTokenClaims(jwtToken);
    JwtTokenHelper::ValidateTokenAgainstPublicKey(jwtToken, publicKey);
}

void Runner::ValidateWithInMemoryKeys(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder)
{
    auto keyPairHelper = std::make_unique<RsaKeyPair>(4096);
    std::string updatedToken = JwtTokenHelper::SignToken(jwtTokenBuilder, keyPairHelper->GetPrivateKey());
    std::cout << "Updated token claims (checking with in memory keys):\n";
    JwtTokenHelper::PrintTokenClaims(updatedToken);
    JwtTokenHelper::ValidateTokenAgainstPublicKey(updatedToken, keyPairHelper->GetPublicKey());
}

void Runner::SignTokenAndValidateAgainstCustomPublicKey(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder)
{
    std::string updatedToken = JwtTokenHelper::SignToken(jwtTokenBuilder, FileIoUtils::getFileContents(TokenSignedWithCustomKeyPairParams.privateKeyFile));
    std::cout << "Updated token claims (checking with public key):\n";
    JwtTokenHelper::PrintTokenClaims(updatedToken);
    JwtTokenHelper::ValidateTokenAgainstPublicKey(updatedToken, FileIoUtils::getFileContents(TokenSignedWithCustomKeyPairParams.publicKeyFile));
}

void Runner::ValidateWithInMemoryCert(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder) 
{
    std::string rootCname = "root";
    std::shared_ptr<X509Certificate> x509Cert = std::make_shared<X509Certificate>(rootCname);
    x509Cert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsCaCert(x509Cert);   // self sign

    std::vector<std::string> caCerts;
    caCerts.push_back(x509Cert->GetPublicCert());
    
    std::shared_ptr<X509CertificateChainValidator> validator = std::make_shared<X509CertificateChainValidator>(x509Cert->GetPublicCert());
    std::string updatedToken = JwtTokenHelper::SignToken(jwtTokenBuilder, x509Cert->GetPrivateKey());
    std::cout << "Updated token claims (checking with in memory cert):\n";
    JwtTokenHelper::PrintTokenClaims(updatedToken);
    JwtTokenHelper::ValidateTokenAgainstPublicCertificate(updatedToken, caCerts, validator);
}

void Runner::SignTokenAndValidateAgainstSelfSignedCertificate(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder)
{
    std::vector<std::string> caCerts;
    caCerts.clear();
    for(const std::string& file : TokenSignedWithSelfSignedParams.caCertFiles)
        caCerts.push_back(FileIoUtils::getFileContents(file));
    
    std::shared_ptr<X509CertificateChainValidator> validator = std::make_shared<X509CertificateChainValidator>(caCerts.back());
    std::string updatedToken = JwtTokenHelper::SignToken(jwtTokenBuilder, FileIoUtils::getFileContents(TokenSignedWithSelfSignedParams.privateKeyFile));
    std::cout << "Updated token claims (checking with self signed cert):\n";
    JwtTokenHelper::PrintTokenClaims(updatedToken);
    JwtTokenHelper::ValidateTokenAgainstPublicCertificate(updatedToken, caCerts, validator);
}

void Runner::ValidateWithInMemoryRootCert(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder) {
    std::string rootCname = "root";
    std::shared_ptr<X509Certificate> rootCert = std::make_shared<X509Certificate>(rootCname);
    rootCert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsCaCert(rootCert);   // self sign

    std::string leafCname = "leaf";
    std::unique_ptr<X509Certificate> leafCert = std::make_unique<X509Certificate>(leafCname);
    leafCert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsServerCert(rootCert);

    std::vector<std::string> caCerts;
    caCerts.push_back(leafCert->GetPublicCert());
    caCerts.push_back(rootCert->GetPublicCert());
    
    std::shared_ptr<X509CertificateChainValidator> validator = std::make_shared<X509CertificateChainValidator>(rootCert->GetPublicCert());
    std::string updatedToken = JwtTokenHelper::SignToken(jwtTokenBuilder, leafCert->GetPrivateKey());
    std::cout << "Updated token claims (checking with in memory root cert):\n";
    JwtTokenHelper::PrintTokenClaims(updatedToken);
    JwtTokenHelper::ValidateTokenAgainstPublicCertificate(updatedToken, caCerts, validator);
}

void Runner::SignTokenAndValidateAgainstRootCaSignedCertificate(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder)
{
    std::vector<std::string> caCerts;
    caCerts.clear();
    for(const std::string& file : TokenSignedWithRootCaParams.caCertFiles)
        caCerts.push_back(FileIoUtils::getFileContents(file));
    
    std::shared_ptr<X509CertificateChainValidator> validator = std::make_shared<X509CertificateChainValidator>(caCerts.back());
    std::string updatedToken = JwtTokenHelper::SignToken(jwtTokenBuilder, FileIoUtils::getFileContents(TokenSignedWithRootCaParams.privateKeyFile));
    std::cout << "Updated token claims (checking with root -> leaf cert):\n";
    JwtTokenHelper::PrintTokenClaims(updatedToken);
    JwtTokenHelper::ValidateTokenAgainstPublicCertificate(updatedToken, caCerts, validator);
}

void Runner::ValidateWithInMemoryIntermediateCert(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder) {
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
    std::unique_ptr<X509Certificate> leafCert = std::make_unique<X509Certificate>(leafCname);
    leafCert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsServerCert(intermediateCert);
    
    std::vector<std::string> caCerts;
    caCerts.push_back(leafCert->GetPublicCert());
    caCerts.push_back(intermediateCert->GetPublicCert());
    caCerts.push_back(rootCert->GetPublicCert());
    
    std::shared_ptr<X509CertificateChainValidator> validator = std::make_shared<X509CertificateChainValidator>(rootCert->GetPublicCert());
    std::string updatedToken = JwtTokenHelper::SignToken(jwtTokenBuilder, leafCert->GetPrivateKey());
    std::cout << "Updated token claims (checking with in memory intermediate cert):\n";
    JwtTokenHelper::PrintTokenClaims(updatedToken);
    JwtTokenHelper::ValidateTokenAgainstPublicCertificate(updatedToken, caCerts, validator);
}

void Runner::SignTokenAndValidateAgainstIntermediateCaSignedCertificate(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder)
{
    std::vector<std::string> caCerts;
    caCerts.clear();
    for(const std::string& file : TokenSignedWithIntermediateCaParams.caCertFiles)
        caCerts.push_back(FileIoUtils::getFileContents(file));
    
    std::shared_ptr<X509CertificateChainValidator> validator = std::make_shared<X509CertificateChainValidator>(caCerts.back());
    std::string updatedToken = JwtTokenHelper::SignToken(jwtTokenBuilder, FileIoUtils::getFileContents(TokenSignedWithIntermediateCaParams.privateKeyFile));
    std::cout << "Updated token claims (checking with root -> intermediate -> leaf certs):\n";
    JwtTokenHelper::PrintTokenClaims(updatedToken);
    JwtTokenHelper::ValidateTokenAgainstPublicCertificate(updatedToken, caCerts, validator);
}
