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
    addStringExtension(NID_subject_key_identifier, "hash", 0);
    addMultiValueExtension(NID_authority_key_identifier, std::map<std::string, std::string> {
        { "keyid", "always" },
        { "issuer" , ""}
    }, 0);
    addMultiValueExtension(NID_basic_constraints, std::map<std::string, std::string> {
        { "CA", "TRUE" }
    }, 1);
    addMultiValueExtension(NID_key_usage, std::map<std::string, std::string> {
        { "digitalSignature", "" },
        { "cRLSign" , "" },
        { "keyCertSign", "" }
    }, 1);
}

void X509V3Extensions::AddServerCertificateExtensions() {
    addStringExtension(NID_subject_key_identifier, "hash", 0);
    addMultiValueExtension(NID_authority_key_identifier, std::map<std::string, std::string> {
        { "keyid", "" },
        { "issuer" , "always"}
    }, 0);
    addMultiValueExtension(NID_basic_constraints, std::map<std::string, std::string> {
        { "CA", "FALSE" }
    }, 1);
    addMultiValueExtension(NID_key_usage, std::map<std::string, std::string> {
        { "digitalSignature", "" },
        { "keyEncipherment" , "" }
    }, 1);
    addMultiValueExtension(NID_netscape_cert_type, std::map<std::string, std::string> {
        { "server", "" }
    }, 0);
    addStringExtension(NID_netscape_comment, "OpenSSL Generated Server Certificate", 0);
}

void X509V3Extensions::addStringExtension(int extensionNid, std::string value, int critical) {
    const X509V3_EXT_METHOD *extensionMethod = X509V3_EXT_get_nid(extensionNid);
    if (extensionMethod == NULL) {
        throw new std::runtime_error("Cannot find extension method for id: " + std::to_string(extensionNid));
    }

    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->s2i(extensionMethod, x509V3Ctx.get(), value.c_str())), 
        l1
    );
    if (extensionValue == NULL) {
        throw new std::runtime_error("Cannot initialize extension value for id: " + std::to_string(extensionNid));
    }

    unsigned char *extensionFormatDer = NULL; 
    int extensionLength = ASN1_item_i2d(extensionValue.get(), &extensionFormatDer, ASN1_ITEM_ptr(extensionMethod->it));
    if (extensionLength <= 0) {
        throw std::runtime_error("Cannot convert extension value to DER format for id: " + std::to_string(extensionNid));
    }

    addExtension(extensionNid, extensionFormatDer, extensionLength, critical);

    OPENSSL_free(extensionFormatDer);
}

void X509V3Extensions::addMultiValueExtension(int extensionNid, std::map<std::string, std::string> values, int critical) {
    const X509V3_EXT_METHOD *extensionMethod = X509V3_EXT_get_nid(extensionNid);
    if (extensionMethod == NULL) {
        throw new std::runtime_error("Cannot find extension method for id: " + std::to_string(extensionNid));
    }
    
    auto l = [&](STACK_OF(CONF_VALUE) *ptr) { sk_CONF_VALUE_pop_free(ptr, X509V3_conf_free); };
    std::unique_ptr<STACK_OF(CONF_VALUE), decltype(l)> confValueStack(sk_CONF_VALUE_new(NULL), l);
    if (confValueStack == NULL) {
        throw std::runtime_error("Cannot parse CONF_VALUE for id: " + std::to_string(extensionNid));
    }
    
    STACK_OF(CONF_VALUE) *stackPtr = confValueStack.get();
    for (auto it = values.begin(); it != values.end(); ++it) {
        const char *value = it->second.length() > 0 ? it->second.c_str() : NULL;
        if (X509V3_add_value(it->first.c_str(), value, &stackPtr) != 1) {
            throw new std::runtime_error("Cannot add " + it->first + " for id: " + std::to_string(extensionNid));
        }
    }
    
    auto l1 = [&](ASN1_VALUE *ptr) { ASN1_item_free(ptr, ASN1_ITEM_ptr(extensionMethod->it)); };
    std::unique_ptr<ASN1_VALUE, decltype(l1)> extensionValue(
        reinterpret_cast<ASN1_VALUE *>(extensionMethod->v2i(extensionMethod, x509V3Ctx.get(), confValueStack.get())), 
        l1
    );
    if (extensionValue == NULL) {
        throw new std::runtime_error("Cannot initialize extension value for id: " + std::to_string(extensionNid));
    }

    unsigned char *extensionFormatDer = NULL;
    int extensionLength = ASN1_item_i2d(extensionValue.get(), &extensionFormatDer, ASN1_ITEM_ptr(extensionMethod->it));
    if (extensionLength <= 0) {
        throw std::runtime_error("Cannot convert extension value to DER format for id: " + std::to_string(extensionNid));
    }

    addExtension(extensionNid, extensionFormatDer, extensionLength, critical);

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
