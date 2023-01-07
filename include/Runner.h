#ifndef _Runner_H_
#define _Runner_H_

#include <string>
#include <vector>
#include <jwt-cpp/jwt.h>


class Runner
{
public:
    static void ValidateOriginalToken(std::string& jwtToken, std::string& publicKey);
    static void ValidateWithInMemoryKeys(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder);
    static void SignTokenAndValidateAgainstCustomPublicKey(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder);
    static void ValidateWithInMemoryCert(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder);
    static void SignTokenAndValidateAgainstSelfSignedCertificate(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder);
    static void ValidateWithInMemoryRootCert(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder);
    static void SignTokenAndValidateAgainstRootCaSignedCertificate(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder);
    static void ValidateWithInMemoryIntermediateCert(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder);
    static void SignTokenAndValidateAgainstIntermediateCaSignedCertificate(jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder);
};

#endif // _Runner_H_
