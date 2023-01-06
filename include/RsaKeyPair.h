#ifndef _RsaKeyPair_H_
#define _RsaKeyPair_H_

#include <memory>
#include <string>
#include <openssl/evp.h>

class RsaKeyPair {
public:
    RsaKeyPair(int keySize);
    std::string GetPublicKey();
    std::string GetPrivateKey();
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>& GetKeyPair() { return keypair; }

private:
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> keypair;
};

#endif // _RsaKeyPair_H_
