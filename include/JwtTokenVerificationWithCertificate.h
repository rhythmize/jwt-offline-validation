#ifndef _JwtTokenVerificationWithCertificate_H_
#define _JwtTokenVerificationWithCertificate_H_


#include <memory>
#include <string>
#include <TokenHelper.h>

class JwtTokenVerificationWithCertificate
{
public:
    void Run(std::string jwtToken);
private:
    std::string private_key_file = "certs/test_signed_cert/private.pem";
    std::string public_cert_file = "certs/test_signed_cert/certificate.crt";
    std::unique_ptr<TokenHelper> tokenHelper = std::make_unique<TokenHelper>();
};

#endif // _JwtTokenVerificationWithCertificate_H_
