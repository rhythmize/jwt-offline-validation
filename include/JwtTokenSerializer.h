#ifndef _JwtTokenSerializer_H_
#define _JwtTokenSerializer_H_

#include <string>
#include <TokenHelper.h>

class JwtTokenSerializer
{
public:
    JwtTokenSerializer(std::string& token) : jwtToken(token) {}
    void updateToken(const std::string& privateKeyFile);
    void checkValidity(const std::string& publicKeyFile);
    void printTokenClaims();

private:
    std::string jwtToken;
    std::unique_ptr<TokenHelper> tokenHelper = std::make_unique<TokenHelper>();
};

#endif // _JwtTokenSerializer_H_
