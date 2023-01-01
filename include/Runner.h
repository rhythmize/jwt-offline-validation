#ifndef _Runner_H_
#define _Runner_H_

#include <string>
#include <vector>


class Runner
{
public:
    static void ValidateOriginalToken(std::string& jwtToken);
    static void ValidateWithInMemoryKeys(std::string& jwtToken);
    static void ModifyTokenAndValidateAgainstCustomPublicKey(std::string& jwtToken);
    static void ValidateWithInMemoryCert(std::string& jwtToken);
    static void ModifyTokenAndValidateAgainstSelfSignedCertificate(std::string& jwtToken);
    static void ValidateWithInMemoryRootCert(std::string& jwtToken);
    static void ModifyTokenAndValidateAgainstRootCaSignedCertificate(std::string& jwtToken);
    static void ValidateWithInMemoryIntermediateCert(std::string& jwtToken);
    static void ModifyTokenAndValidateAgainstIntermediateCaSignedCertificate(std::string& jwtToken);
};

#endif // _Runner_H_
