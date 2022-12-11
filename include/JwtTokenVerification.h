#ifndef _JwtTokenVerification_H_
#define _JwtTokenVerification_H_

#include <JwtTokenSerializer.h>
#include <X509CertificateChainValidator.h>

class JwtTokenVerification
{
public:
    JwtTokenVerification(const std::string& jwtToken);
    void VerifyWithPublicKey(const std::string& privateKeyFile, const std::string &publicKeyFile);
    void VerifyWithPublicCertificate(const std::string& privateKeyFile, const std::string &x509CertificateFile);
    void VerifyWithPublicCertificateWithSignatureVerification(const std::string& privateKeyFile, const std::string &x509CertificateFile, const std::string& trustedCertificateFile);
    void VerifyWithPublicCertificateWithIntermediateCaSignatureVerification();

private:
    std::string getUpdatedToken(const std::string& privateKeyFile);

    std::unique_ptr<JwtTokenSerializer> tokenSerializer;
    std::unique_ptr<FileIoUtils> fileIoUtils = std::make_unique<FileIoUtils>();
    std::unique_ptr<X509CertificateChainValidator> certificateValidator = std::make_unique<X509CertificateChainValidator>();
};

#endif // _JwtTokenVerification_H_
