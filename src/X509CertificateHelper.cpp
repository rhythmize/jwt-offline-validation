#include <memory>
#include <openssl/pem.h>
#include <X509CertificateHelper.h>

X509CertificateHelper::X509CertificateHelper(std::string& cname) : x509(X509_new(), X509_free) {
    setVersionAndSerialNumber();

    X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), 3600L);  // expire in 1 hour 

    X509_set_pubkey(x509.get(), keyPair->getKeyPair().get());

    unsigned char *cnamePtr = reinterpret_cast<unsigned char *>(const_cast<char*>(cname.c_str()));
    X509_NAME_add_entry_by_txt(getSubjectName(), "CN", MBSTRING_ASC, cnamePtr, -1, -1, 0);
}

X509_NAME* X509CertificateHelper::getSubjectName() {
    return X509_get_subject_name(x509.get());
}

void X509CertificateHelper::sign(std::shared_ptr<X509CertificateHelper> signingCertificate) {
    X509_set_issuer_name(x509.get(), signingCertificate->getSubjectName());
    X509_sign(x509.get(), signingCertificate->keyPair->getKeyPair().get(), EVP_sha256());
}

std::string X509CertificateHelper::getPublicCert() {
    char *data;
    std::string publicCert;
    
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (bio == NULL) {
        throw new std::runtime_error("Cannot initialize BIO");
    }

    if (PEM_write_bio_X509(bio.get(), x509.get()) != 1) {
        throw new std::runtime_error("Cannot write Private Key");
    }

    int len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0) {
        throw new std::runtime_error("Invalid data location in BIO");
    }

    publicCert.assign(data, len);
    return publicCert;
}

std::string X509CertificateHelper::getPrivateKey() {
    return keyPair->getPrivateKey();
}

void X509CertificateHelper::setVersionAndSerialNumber() {
    X509_set_version(x509.get(), 2);

    ASN1_INTEGER *serialNumber = ASN1_INTEGER_new();
    createRandomSerialNumber(serialNumber);

    X509_set_serialNumber(x509.get(), serialNumber);

    ASN1_INTEGER_free(serialNumber);
}

void X509CertificateHelper::addCaExtensions() {
    X509V3_CTX ctx;
    
    // This sets the 'context' of the extensions. No configuration database
    X509V3_set_ctx_nodb(&ctx);
    
    // Issuer and subject certs: both the target since it is self signed, no request and no CRL
    X509V3_set_ctx(&ctx, x509.get(), x509.get(), NULL, NULL, 0);
    
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    X509_add_ext(x509.get(), ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid:always,issuer");
    X509_add_ext(x509.get(), ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(x509.get(), ex, -1);
    X509_EXTENSION_free(ex);
    
    ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "critical, digitalSignature, cRLSign, keyCertSign");
    X509_add_ext(x509.get(), ex, -1);
    X509_EXTENSION_free(ex);
}

void X509CertificateHelper::createRandomSerialNumber(ASN1_INTEGER *serial) {
    BIGNUM *p_bignum = BN_new();
    
    // 20 bytes serial number
    BN_pseudo_rand(p_bignum, 160, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    
    BN_to_ASN1_INTEGER(p_bignum, serial);

    BN_free(p_bignum);
}

void X509CertificateHelper::dumpToFile(std::string& prefix) {
    std::string keyFileName = prefix + "_private.pem";
    std::string certFileName = prefix + "_certificate.crt";
    
    std::unique_ptr<BIO, decltype(&BIO_free)> bioPrivateKey(BIO_new_file(keyFileName.c_str(), "wb"), BIO_free);
    if (bioPrivateKey == NULL) {
        throw new std::runtime_error("Cannot initialize BIO");
    }

    if (PEM_write_bio_PrivateKey(bioPrivateKey.get(), keyPair->getKeyPair().get(), NULL, NULL, 0, NULL, NULL) != 1) {
        throw new std::runtime_error("Cannot write private key to file");
    }
    

    std::unique_ptr<BIO, decltype(&BIO_free)> bioCertificate(BIO_new_file(certFileName.c_str(), "wb"), BIO_free);
    if (bioCertificate == NULL) {
        throw new std::runtime_error("Cannot initialize BIO");
    }

    if (PEM_write_bio_X509(bioCertificate.get(), x509.get()) != 1) {
        throw new std::runtime_error("Cannot write X509 certificate to file");
    }
}
