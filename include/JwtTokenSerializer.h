#ifndef _JwtTokenSerializer_H_
#define _JwtTokenSerializer_H_

#include <memory>
#include <string>
#include <FileIoUtils.h>

class JwtTokenSerializer
{
public:
    JwtTokenSerializer(std::string& token) : jwtToken(token) {}
    void updateToken(const std::string& privateKeyFile);
    void checkValidity(const std::string& publicKeyFile);
    void printTokenClaims();

private:
    std::string jwtToken;
    std::unique_ptr<FileIoUtils> fileIoUtils = std::make_unique<FileIoUtils>();
};

#endif // _JwtTokenSerializer_H_
