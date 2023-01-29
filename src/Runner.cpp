#include <iostream>
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

void Runner::ValidateWithInMemoryCert(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder) 
{
    std::string rootCname = "root";
    std::shared_ptr<X509Certificate> x509Cert = std::make_shared<X509Certificate>(rootCname);
    x509Cert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsCaCert(x509Cert);   // self sign

    std::vector<std::string> derCaCerts;
    derCaCerts.push_back(x509Cert->GetPublicDerCert());

    std::shared_ptr<X509CertificateChainValidator> validator = std::make_shared<X509CertificateChainValidator>(x509Cert->GetPublicDerCert());
    std::string updatedToken = JwtTokenHelper::SignToken(jwtTokenBuilder, x509Cert->GetPrivateKey(), derCaCerts);
    std::cout << "Updated token claims (checking with in memory cert):\n";
    JwtTokenHelper::PrintTokenClaims(updatedToken);
    JwtTokenHelper::ValidateTokenAgainstPublicCertificate(updatedToken, validator);    
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

    std::vector<std::string> derCaCerts;
    derCaCerts.push_back(leafCert->GetPublicDerCert());
    derCaCerts.push_back(rootCert->GetPublicDerCert());
    
    std::shared_ptr<X509CertificateChainValidator> validator = std::make_shared<X509CertificateChainValidator>(rootCert->GetPublicDerCert());
    std::string updatedToken = JwtTokenHelper::SignToken(jwtTokenBuilder, leafCert->GetPrivateKey(), derCaCerts);
    std::cout << "Updated token claims (checking with in memory root cert):\n";
    JwtTokenHelper::PrintTokenClaims(updatedToken);
    JwtTokenHelper::ValidateTokenAgainstPublicCertificate(updatedToken, validator);
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

    std::string intermediateCname2 = "intermediate2";
    std::shared_ptr<X509Certificate> intermediateCert2 = std::make_shared<X509Certificate>(intermediateCname2);
    intermediateCert2
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsCaCert(intermediateCert);

    std::string leafCname = "leaf";
    std::unique_ptr<X509Certificate> leafCert = std::make_unique<X509Certificate>(leafCname);
    leafCert
        ->GenerateCertificateSigningRequest()
        ->ConfigureCertificateParameters()
        ->SignAsServerCert(intermediateCert2);
    
    std::vector<std::string> derCaCerts;
    derCaCerts.push_back(leafCert->GetPublicDerCert());
    derCaCerts.push_back(intermediateCert2->GetPublicDerCert());
    derCaCerts.push_back(intermediateCert->GetPublicDerCert());
    derCaCerts.push_back(rootCert->GetPublicDerCert());

    std::shared_ptr<X509CertificateChainValidator> validator = std::make_shared<X509CertificateChainValidator>(rootCert->GetPublicDerCert());
    std::string updatedToken = JwtTokenHelper::SignToken(jwtTokenBuilder, leafCert->GetPrivateKey(), derCaCerts);
    
    std::cout << "Updated token claims (checking with in memory intermediate cert):\n";
    JwtTokenHelper::PrintTokenClaims(updatedToken);
    JwtTokenHelper::ValidateTokenAgainstPublicCertificate(updatedToken, validator);
}
