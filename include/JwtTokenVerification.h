#ifndef _JwtTokenVerification_H_
#define _JwtTokenVerification_H_

#include <string>
#include <vector>

class JwtTokenVerification
{
public:
    static void ValidateWithPublicKey(const std::string& token, const std::string& publicKeyFile);
    static void ValidateWithPublicCertificate(const std::string& token, const std::vector<std::string>& caCerts);
};

#endif // _JwtTokenVerification_H_
