#ifndef _Config_H_
#define _Config_H_

#include <string>
#include <vector>

struct KeyPairParams
{
    const std::string privateKeyFile;
    const std::string publicKeyFile;
};

struct X509Params
{
    const std::string privateKeyFile;
    const std::vector<std::string> caCertFiles;
};

KeyPairParams OriginalTokenParams
{
    "",
    "certs/trusted_flight/auth_server_public_key.pem"
};

KeyPairParams TokenSignedWithCustomKeyPairParams
{
    "certs/test_keys/test_private.pem",
    "certs/test_keys/test_public.pem"
};

X509Params TokenSignedWithSelfSignedParams
{
    "certs/test_self_signed/private.pem",
    {
        "certs/test_self_signed/certificate.crt"
    }
};

X509Params TokenSignedWithRootCaParams
{
    "certs/test_signed_with_rootCA/leaf/private.pem",
    {
        "certs/test_signed_with_rootCA/leaf/certificate.crt",
        "certs/test_signed_with_rootCA/root/certificate.crt"
    }
};

X509Params TokenSignedWithIntermediateCaParams
{
    "certs/test_signed_with_intermediateCA/leaf/private.pem",
    {
        "certs/test_signed_with_intermediateCA/leaf/certificate.crt",
        "certs/test_signed_with_intermediateCA/intermediate1/certificate.crt",
        "certs/test_signed_with_intermediateCA/intermediate2/certificate.crt",
        "certs/test_signed_with_intermediateCA/intermediate3/certificate.crt",
        "certs/test_signed_with_intermediateCA/intermediate4/certificate.crt",
        "certs/test_signed_with_intermediateCA/root/certificate.crt"
    }
};

#endif // _Config_H_
