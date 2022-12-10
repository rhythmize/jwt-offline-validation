#ifndef _JwtTokenVerificationWithPublicKey_H_
#define _JwtTokenVerificationWithPublicKey_H_

#include <memory>
#include <string>
#include <FileIoUtils.h>

class JwtTokenVerificationWithPublicKey
{
public:
    void Run(std::string jwtToken);
private:
    std::string private_key_file = "certs/test_keys/test_private.pem";
    std::string public_key_file = "certs/test_keys/test_public.pem";
    std::unique_ptr<FileIoUtils> fileIoUtils = std::make_unique<FileIoUtils>();
};

#endif // _JwtTokenVerificationWithPublicKey_H_
