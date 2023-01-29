#include <X509Certificate.h>
#include <X509CertificateChainValidator.h>


X509CertificateChainValidator::X509CertificateChainValidator(std::string trustedCertificate) :
    trustStore(X509_STORE_new(), X509_STORE_free) {
    // add trustedCertificate to trust store
    if (X509_STORE_add_cert(trustStore.get(), X509Certificate::GetX509FromDerString(trustedCertificate).get()) != 1) {
        throw new std::runtime_error("Cannot add trusted certificate to trust store");
    }
}

bool X509CertificateChainValidator::ValidateCertificateChain(picojson::array caCertificates) {
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> storeCtx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (storeCtx == NULL) {
        throw new std::runtime_error("Cannot initialize X509_STORE_CTX");
    }

    auto deleter = [&](STACK_OF(X509) *ptr) { sk_X509_pop_free(ptr, X509_free); };
    std::unique_ptr<STACK_OF(X509), decltype(deleter)> untrustedChain(sk_X509_new_null(), deleter);
    if (untrustedChain == NULL) {
        throw new std::runtime_error("Cannot initialize STACK_OF(X509)");
    }

    // create untrusted chain
    for(size_t i=1; i < caCertificates.size(); i++)
    {
        auto cert = X509Certificate::GetX509FromDerString(caCertificates[i].get<std::string>());
        if (sk_X509_push(untrustedChain.get(), X509_dup(cert.get())) <= 0) {
            throw new std::runtime_error("Cannot write trusted certificate to BIO");
        }
    }

    auto cert = X509Certificate::GetX509FromDerString(caCertificates[0].get<std::string>());
    if (X509_STORE_CTX_init(storeCtx.get(), trustStore.get(), cert.get(), untrustedChain.get()) != 1) {
        throw new std::runtime_error("Cannot initialize X509_STORE_CTX");
    }

    return X509_verify_cert(storeCtx.get()) == 1;
}
