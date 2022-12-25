#ifndef _JwtTokenSerializer_H_
#define _JwtTokenSerializer_H_

#include <string>

class JwtTokenSerializer
{
public:
    static std::string updateToken(const std::string& jwtToken, const std::string& privateKey);
    static void checkValidity(const std::string& jwtToken, const std::string& publicKey);
    static void printTokenClaims(const std::string& jwtToken);
};

#endif // _JwtTokenSerializer_H_
