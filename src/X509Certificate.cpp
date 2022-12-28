#include <iostream>
#include <memory>
#include <openssl/pem.h>
#include <X509Certificate.h>

X509Certificate::X509Certificate(std::string& cname) : x509(X509_new(), X509_free) {
    setVersionAndSerialNumber();

    if (X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0) == NULL) {
        throw new std::runtime_error("Cannot update not before time for certificate");
    }
    
    // expire in 1 hour 
    if (X509_gmtime_adj(X509_getm_notAfter(x509.get()), 3600L) == NULL) {
        throw new std::runtime_error("Cannot update expiration time for certificate");
    }

    if (X509_set_pubkey(x509.get(), keyPair->getKeyPair().get()) != 1) {
        throw new std::runtime_error("Cannot set public key for certificate");
    }

    unsigned char *cnamePtr = reinterpret_cast<unsigned char *>(const_cast<char*>(cname.c_str()));
    if (X509_NAME_add_entry_by_txt(getSubjectName(), "CN", MBSTRING_ASC, cnamePtr, -1, -1, 0) != 1) {
        throw new std::runtime_error("Cannot set common name for certificate");
    }
}

X509_NAME* X509Certificate::getSubjectName() {
    return X509_get_subject_name(x509.get());
}

std::string X509Certificate::getPublicCert() {
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

std::string X509Certificate::getPrivateKey() {
    return keyPair->getPrivateKey();
}

void X509Certificate::setVersionAndSerialNumber() {
    if (X509_set_version(x509.get(), 2) != 1) {
        throw new std::runtime_error("Cannot set version for certificate");
    }

    std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)> serialNumber(ASN1_INTEGER_new(), ASN1_INTEGER_free);
    if (serialNumber == NULL) {
        throw new std::runtime_error("Cannot initialize ASN1_INTEGER");
    }
    
    createRandomSerialNumber(serialNumber.get());

    if (X509_set_serialNumber(x509.get(), serialNumber.get()) != 1) {
        throw new std::runtime_error("Cannot set certificate serial number");
    } 
}

void X509Certificate::addExtension(int extensionNid, unsigned char *extensionInDerFormat, int extensionLength, int critical) {
    std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> extensionData(
        ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free);
    if (extensionData == NULL) {
        throw new std::runtime_error("Cannot initialize ASN1_OCTET_STRING for extension data");
    }

    if (ASN1_OCTET_STRING_set(extensionData.get(), extensionInDerFormat, extensionLength) != 1) {
        throw std::runtime_error("Cannot set octet string");
    }

    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
        X509_EXTENSION_create_by_NID(NULL, extensionNid, critical, extensionData.get()), X509_EXTENSION_free);
    if (extension == NULL) {
        throw new std::runtime_error("Cannot set data in extension");
    }

    if (X509_add_ext(x509.get(), extension.get(), -1) != 1) {
        throw new std::runtime_error("Cannot add extension to certificate");
    }
}

void X509Certificate::addSubjectKeyIdentifierExtension(X509V3_CTX *ctx) {
    const X509V3_EXT_METHOD *extensionMethod = X509V3_EXT_get_nid(NID_subject_key_identifier);
    if (extensionMethod == NULL) {
        throw new std::runtime_error("Cannot find extension method for Subject Key Identifier");
    }

    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->s2i(extensionMethod, ctx, "hash")), 
        l1
    );
    if (extensionValue == NULL) {
        throw new std::runtime_error("Cannot initialize extension value for Subject Key Identifier");
    }

    unsigned char *extensionFormatDer = NULL; 
    int extensionLength = ASN1_item_i2d(extensionValue.get(), &extensionFormatDer, ASN1_ITEM_ptr(extensionMethod->it));
    if (extensionLength <= 0) {
        throw std::runtime_error("Cannot convert extension value to DER format");
    }

    addExtension(NID_subject_key_identifier, extensionFormatDer, extensionLength, 0);

    OPENSSL_free(extensionFormatDer);
}

void X509Certificate::addAuthorityKeyIdentifierExtension(X509V3_CTX *ctx) {
    const X509V3_EXT_METHOD *extensionMethod = X509V3_EXT_get_nid(NID_authority_key_identifier);
    if (extensionMethod == NULL) {
        throw new std::runtime_error("Cannot find extension method for Authority Key Identifier");
    }
    
    auto l = [&](STACK_OF(CONF_VALUE) *ptr) { sk_CONF_VALUE_pop_free(ptr, X509V3_conf_free); };
    std::unique_ptr<STACK_OF(CONF_VALUE), decltype(l)> confValueStack(sk_CONF_VALUE_new(NULL), l);
    if (confValueStack == NULL) {
        throw std::runtime_error("Cannot parse CONF_VALUE for Authority Key Identifier");
    }
    
    STACK_OF(CONF_VALUE) *stackPtr = confValueStack.get();
    if (X509V3_add_value("keyid", "always", &stackPtr) != 1) {
        throw new std::runtime_error("Cannot add keyid:always Authority Key Identifier to extension");
    }
    
    if (X509V3_add_value("issuer", NULL, &stackPtr) != 1) {
        throw new std::runtime_error("Cannot add issuer  Authority Key Identifier to extension");
    }
    
    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->v2i(extensionMethod, ctx, confValueStack.get())), 
        l1
    );
    if (extensionValue == NULL) {
        throw new std::runtime_error("Cannot initialize extension value for Authority Key Identifier");
    }
    
    unsigned char *extensionFormatDer = NULL; 
    int extensionLength = ASN1_item_i2d(extensionValue.get(), &extensionFormatDer, ASN1_ITEM_ptr(extensionMethod->it));
    if (extensionLength <= 0) {
        throw std::runtime_error("Cannot convert extension value to DER format");
    }

    addExtension(NID_authority_key_identifier, extensionFormatDer, extensionLength, 0);

    OPENSSL_free(extensionFormatDer);
}

void X509Certificate::addBasicConstraintsExtension(X509V3_CTX *ctx) {
    const X509V3_EXT_METHOD *extensionMethod = X509V3_EXT_get_nid(NID_basic_constraints);
    if (extensionMethod == NULL) {
        throw new std::runtime_error("Cannot find extension method for Basic Constraints");
    }
    
    auto l = [&](STACK_OF(CONF_VALUE) *ptr) { sk_CONF_VALUE_pop_free(ptr, X509V3_conf_free); };
    std::unique_ptr<STACK_OF(CONF_VALUE), decltype(l)> confValueStack(sk_CONF_VALUE_new(NULL), l);
    if (confValueStack == NULL) {
        throw std::runtime_error("Cannot parse CONF_VALUE for Basic Constraints");
    }
    
    STACK_OF(CONF_VALUE) *stackPtr = confValueStack.get();
    if (X509V3_add_value("CA", "TRUE", &stackPtr) != 1) {
        throw new std::runtime_error("Cannot add CA:TRUE constraint to extension");
    }

    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->v2i(extensionMethod, ctx, confValueStack.get())),
        l1
    );
    if (extensionValue == NULL) {
        throw new std::runtime_error("Cannot initialize extension value for Basic Constraints");
    }
    
    unsigned char *extensionFormatDer = NULL; 
    int extensionLength = ASN1_item_i2d(extensionValue.get(), &extensionFormatDer, ASN1_ITEM_ptr(extensionMethod->it));
    if (extensionLength <= 0) {
        throw std::runtime_error("Cannot convert extension value to DER format");
    }

    addExtension(NID_basic_constraints, extensionFormatDer, extensionLength, 1);

    OPENSSL_free(extensionFormatDer);
}

void X509Certificate::addKeyUsageExtension(X509V3_CTX *ctx) {
    const X509V3_EXT_METHOD *extensionMethod = X509V3_EXT_get_nid(NID_key_usage);
    if (extensionMethod == NULL) {
        throw new std::runtime_error("Cannot find extension method for Key Usage");
    }

    auto l = [&](STACK_OF(CONF_VALUE) *ptr) { sk_CONF_VALUE_pop_free(ptr, X509V3_conf_free); };
    std::unique_ptr<STACK_OF(CONF_VALUE), decltype(l)> confValueStack(sk_CONF_VALUE_new(NULL), l);
    if (confValueStack == NULL) {
        throw new std::runtime_error("Cannot initialize STACK_OF configuration values for extension");
    }
    
    STACK_OF(CONF_VALUE) *stackPtr = confValueStack.get();
    if (X509V3_add_value("digitalSignature", NULL, &stackPtr) != 1) {
        throw new std::runtime_error("Cannot add digitalSignature Key usage to extension");
    }

    if (X509V3_add_value("cRLSign", NULL, &stackPtr) != 1) {
        throw new std::runtime_error("Cannot add cRLSign Key usage to extension");
    }
    
    if (X509V3_add_value("keyCertSign", NULL, &stackPtr) != 1) {
        throw new std::runtime_error("Cannot add keyCertSign Key usage to extension");
    }

    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->v2i(extensionMethod, ctx, confValueStack.get())),
        l1
    );
    if (extensionValue == NULL) {
        throw new std::runtime_error("Cannot initialize extension value for Key Usage");
    }
    
    unsigned char *extensionFormatDer = NULL; 
    int extensionLength = ASN1_item_i2d(extensionValue.get(), &extensionFormatDer, ASN1_ITEM_ptr(extensionMethod->it));
    if (extensionLength <= 0) {
        throw std::runtime_error("Cannot convert extension value to DER format");
    }

    addExtension(NID_key_usage, extensionFormatDer, extensionLength, 1);

    OPENSSL_free(extensionFormatDer);
}

void X509Certificate::sign(std::shared_ptr<X509Certificate> signingCertificate) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx); // Configure no database for extension context
    // Issuer and subject certs: both the target since it is self signed, no request and no CRL
    X509V3_set_ctx(&ctx, x509.get(), x509.get(), NULL, NULL, 0);

    addSubjectKeyIdentifierExtension(&ctx);
    addAuthorityKeyIdentifierExtension(&ctx);
    addBasicConstraintsExtension(&ctx);
    addKeyUsageExtension(&ctx);

    if (X509_set_issuer_name(x509.get(), signingCertificate->getSubjectName()) != 1) {
        throw new std::runtime_error("Cannot set issuer for certificate");
    }
    
    if (X509_sign(x509.get(), signingCertificate->keyPair->getKeyPair().get(), EVP_sha256()) == 0) {
        throw new std::runtime_error("Cannot sign the certificate using private key");
    }
}

void X509Certificate::createRandomSerialNumber(ASN1_INTEGER *serial) {
    std::unique_ptr<BIGNUM, decltype(&BN_free)> bigNum(BN_new(), BN_free);
    if (bigNum == NULL){
        throw new std::runtime_error("Cannot initialize BIGNUM");
    }
    
    // 20 bytes serial number
    if (BN_pseudo_rand(bigNum.get(), 160, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1) {
        throw new std::runtime_error("Cannot randomize for certificate serial number");
    }
    
    if (BN_to_ASN1_INTEGER(bigNum.get(), serial) == NULL) {
        throw new std::runtime_error("Cannot convert BIGNUM to ASN1_INTEGER");
    }
}

void X509Certificate::dumpToFile(std::string& prefix) {
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
