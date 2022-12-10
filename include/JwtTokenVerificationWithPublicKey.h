#ifndef _JwtTokenVerificationWithPublicKey_H_
#define _JwtTokenVerificationWithPublicKey_H_

#include <memory>
#include <string>
#include <TokenHelper.h>

class JwtTokenVerificationWithPublicKey
{
public:
    void Run(std::string jwtToken);
private:
    std::string private_key_file = "certs/test_keys/test_private.pem";
    std::string public_key_file = "certs/test_keys/test_public.pem";
    std::unique_ptr<TokenHelper> tokenHelper = std::make_unique<TokenHelper>();
};

#endif // _JwtTokenVerificationWithPublicKey_H_
