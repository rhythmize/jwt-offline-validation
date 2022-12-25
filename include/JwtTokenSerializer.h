#ifndef _JwtTokenSerializer_H_
#define _JwtTokenSerializer_H_

#include <memory>
#include <string>
#include <FileIoUtils.h>

class JwtTokenSerializer
{
public:
    JwtTokenSerializer(const std::string& token) : originalToken(token) {}
    std::string updateToken(const std::string& privateKeyFile);
    void checkValidity(const std::string& jwtToken, const std::string& publicKeyFile);
    static void printTokenClaims(const std::string& jwtToken);
    void printOriginalTokenClaims();

private:
    std::string originalToken;
    std::unique_ptr<FileIoUtils> fileIoUtils = std::make_unique<FileIoUtils>();
};

#endif // _JwtTokenSerializer_H_
