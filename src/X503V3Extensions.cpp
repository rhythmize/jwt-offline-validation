#include <iostream>
#include <X509V3Extensions.h>


X509V3Extensions::X509V3Extensions(std::shared_ptr<X509> cert) : x509V3Ctx(new X509V3_CTX()), x509Cert(cert) {
    // Configure no database for extension context
    X509V3_set_ctx_nodb(x509V3Ctx.get());
}

X509V3Extensions* X509V3Extensions::SetContext(std::shared_ptr<X509> issuer, std::shared_ptr<X509_REQ> x509Req) {
    X509V3_set_ctx(x509V3Ctx.get(), issuer.get(), NULL, x509Req.get(), NULL, 0);
    return this;
}

void X509V3Extensions::AddCaCertificateExtensions() {
    addSubjectKeyIdentifierExtension();
    addAuthorityKeyIdentifierExtension(true);
    addBasicConstraintsExtension(true);
    addKeyUsageExtension(true);
}

void X509V3Extensions::AddServerCertificateExtensions() {
    addSubjectKeyIdentifierExtension();
    addAuthorityKeyIdentifierExtension(false);
    addBasicConstraintsExtension(false);
    addKeyUsageExtension(false);
    addNsCertTypeExtension();
    addNsCommentExtension();
}

void X509V3Extensions::addSubjectKeyIdentifierExtension() {
    const X509V3_EXT_METHOD *extensionMethod = X509V3_EXT_get_nid(NID_subject_key_identifier);
    if (extensionMethod == NULL) {
        throw new std::runtime_error("Cannot find extension method for Subject Key Identifier");
    }

    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->s2i(extensionMethod, x509V3Ctx.get(), "hash")), 
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

void X509V3Extensions::addAuthorityKeyIdentifierExtension(bool isCaCert) {
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
    if (X509V3_add_value("keyid", isCaCert ? "always" : NULL, &stackPtr) != 1) {
        throw new std::runtime_error("Cannot add keyid:always Authority Key Identifier to extension");
    }
    
    if (X509V3_add_value("issuer", isCaCert ? NULL : "always", &stackPtr) != 1) {
        throw new std::runtime_error("Cannot add issuer  Authority Key Identifier to extension");
    }
    
    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->v2i(extensionMethod, x509V3Ctx.get(), confValueStack.get())), 
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

void X509V3Extensions::addBasicConstraintsExtension(bool isCaCert) {
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
    if (X509V3_add_value("CA", isCaCert ? "TRUE" : "FALSE", &stackPtr) != 1) {
        throw new std::runtime_error("Cannot add CA:TRUE constraint to extension");
    }

    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->v2i(extensionMethod, x509V3Ctx.get(), confValueStack.get())),
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

void X509V3Extensions::addKeyUsageExtension(bool isCaCert) {
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
    if (isCaCert) {
        if (X509V3_add_value("cRLSign", NULL, &stackPtr) != 1) {
            throw new std::runtime_error("Cannot add cRLSign Key usage to extension");
        }
        
        if (X509V3_add_value("keyCertSign", NULL, &stackPtr) != 1) {
            throw new std::runtime_error("Cannot add keyCertSign Key usage to extension");
        }
    } else {
        if (X509V3_add_value("keyEncipherment", NULL, &stackPtr) != 1) {
            throw new std::runtime_error("Cannot add keyEncipherment to extension");
        }
    }

    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->v2i(extensionMethod, x509V3Ctx.get(), confValueStack.get())),
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

void X509V3Extensions::addNsCertTypeExtension() {
    const X509V3_EXT_METHOD *extensionMethod = X509V3_EXT_get_nid(NID_netscape_cert_type);
    if (extensionMethod == NULL) {
        throw new std::runtime_error("Cannot find extension method for NsCertType");
    }

    auto l = [&](STACK_OF(CONF_VALUE) *ptr) { sk_CONF_VALUE_pop_free(ptr, X509V3_conf_free); };
    std::unique_ptr<STACK_OF(CONF_VALUE), decltype(l)> confValueStack(sk_CONF_VALUE_new(NULL), l);
    if (confValueStack == NULL) {
        throw new std::runtime_error("Cannot initialize STACK_OF configuration values for extension");
    }
    
    STACK_OF(CONF_VALUE) *stackPtr = confValueStack.get();
    if (X509V3_add_value("server", NULL, &stackPtr) != 1) {
        throw new std::runtime_error("Cannot add digitalSignature Key usage to extension");
    }

    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->v2i(extensionMethod, x509V3Ctx.get(), confValueStack.get())), 
        l1
    );
    if (extensionValue == NULL) {
        throw new std::runtime_error("Cannot initialize extension value for nsCertType extension");
    }
    unsigned char *extensionFormatDer = NULL; 
    int extensionLength = ASN1_item_i2d(extensionValue.get(), &extensionFormatDer, ASN1_ITEM_ptr(extensionMethod->it));
    if (extensionLength <= 0) {
        throw std::runtime_error("Cannot convert extension value to DER format");
    }

    addExtension(NID_netscape_cert_type, extensionFormatDer, extensionLength, 0);

    OPENSSL_free(extensionFormatDer);
}

void X509V3Extensions::addNsCommentExtension() {
    const X509V3_EXT_METHOD *extensionMethod = X509V3_EXT_get_nid(NID_netscape_comment);
    if (extensionMethod == NULL) {
        throw new std::runtime_error("Cannot find extension method for NsCertType");
    }

    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->s2i(extensionMethod, x509V3Ctx.get(), "OpenSSL Generated Server Certificate")), 
        l1
    );
    if (extensionValue == NULL) {
        throw new std::runtime_error("Cannot initialize extension value for nsCertType extension");
    }
    unsigned char *extensionFormatDer = NULL; 
    int extensionLength = ASN1_item_i2d(extensionValue.get(), &extensionFormatDer, ASN1_ITEM_ptr(extensionMethod->it));
    if (extensionLength <= 0) {
        throw std::runtime_error("Cannot convert extension value to DER format");
    }

    addExtension(NID_netscape_comment, extensionFormatDer, extensionLength, 0);

    OPENSSL_free(extensionFormatDer);
}

void X509V3Extensions::addExtension(int extensionNid, unsigned char *extensionInDerFormat, int extensionLength, int critical) {
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

    if (X509_add_ext(x509Cert.get(), extension.get(), -1) != 1) {
        throw new std::runtime_error("Cannot add extension to certificate");
    }
}
