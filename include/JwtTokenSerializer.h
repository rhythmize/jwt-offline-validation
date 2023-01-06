#ifndef _JwtTokenSerializer_H_
#define _JwtTokenSerializer_H_

#include <string>

class JwtTokenSerializer
{
public:
    static std::string ModifyAndSignToken(const std::string& jwtToken, const std::string& privateKey);
    static void CheckValidity(const std::string& jwtToken, const std::string& publicKey);
    static void PrintTokenClaims(const std::string& jwtToken);
};

#endif // _JwtTokenSerializer_H_
