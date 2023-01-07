#ifndef _JwtTokenHelper_H_
#define _JwtTokenHelper_H_

#include <string>
#include <jwt-cpp/jwt.h>


class JwtTokenHelper
{
public:
    static jwt::builder<jwt::traits::kazuho_picojson> GetModifiedTokenBuilder(const std::string& jwtToken);
    static void ValidateTokenAgainstPublicKey(const std::string& jwtToken, const std::string& publicKey);
    static void ValidateTokenAgainstPublicCertificate(const std::string& token, const std::vector<std::string>& caCerts);
    static std::string SignToken(const jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder, const std::string& privateKey);
    static void PrintTokenClaims(const std::string& jwtToken);

private:
    static void CheckValidity(const std::string& jwtToken, const std::string& publicKey);
};

#endif // _JwtTokenHelper_H_
