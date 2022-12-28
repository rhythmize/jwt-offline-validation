#include <cstdio>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <RsaKeyPair.h>

RsaKeyPair::RsaKeyPair(int keySize) : keypair(EVP_PKEY_new(), EVP_PKEY_free) {
    RSA *rsa = RSA_new();   // smart pointer not required, free managed by EVP_PKEY
    std::unique_ptr<BIGNUM, decltype(&BN_free)> e(BN_new(), BN_free);

    if (BN_set_word(e.get(), RSA_F4) != 1) {
        throw new std::runtime_error("Cannot set e for RSA key pair");
    }

    if (RSA_generate_key_ex(rsa, keySize, e.get(), NULL) != 1) {
        throw new std::runtime_error("Cannot generate RSA key pair");
    }

    if (EVP_PKEY_assign_RSA(keypair.get(), rsa) != 1) {
        throw new std::runtime_error("Cannot assign RSA keypair");
    }
}

std::string RsaKeyPair::getPrivateKey() {
    char *data;
    std::string privateKey;

    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (bio == NULL) {
        throw new std::runtime_error("Cannot initialize BIO");
    }

    if (PEM_write_bio_PrivateKey(bio.get(), keypair.get(), 0, 0, 0, 0, 0) != 1) {
        throw new std::runtime_error("Cannot write Private Key");
    }

    int len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0) {
        throw new std::runtime_error("Invalid data location in BIO");
    }

    privateKey.assign(data, len);
    return privateKey;
}

std::string RsaKeyPair::getPublicKey() {
    char *data;
    std::string publicKey;

    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (bio == NULL) {
        throw new std::runtime_error("Cannot initialize BIO");
    }
    
    if (PEM_write_bio_PUBKEY(bio.get(), keypair.get()) != 1) {
        throw new std::runtime_error("Cannot write Public Key");
    }

    int len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0) {
        throw new std::runtime_error("Invalid data location in BIO");
    }
    
    publicKey.assign(data, len);
    return publicKey;
}
