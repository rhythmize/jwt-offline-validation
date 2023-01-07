#include <openssl/pem.h>
#include <X509CertificateChainValidator.h>


X509CertificateChainValidator::X509CertificateChainValidator(std::string trustedCertificate) :
    trustStore(X509_STORE_new(), X509_STORE_free) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bioCert(BIO_new(BIO_s_mem()), BIO_free);
    if (bioCert == NULL) {
        throw new std::runtime_error("Cannot initialize BIO");
    }
    
    if (BIO_puts(bioCert.get(), trustedCertificate.c_str()) < 0) {
        throw new std::runtime_error("Cannot write trusted certificate to BIO");
    }
    
    std::unique_ptr<X509, decltype(&X509_free)> trustedX509(PEM_read_bio_X509(bioCert.get(), NULL, NULL, NULL), X509_free);
    if (trustedX509 == NULL) {
        throw new std::runtime_error("Cannot initialize X509 for trusted cert");
    }
    
    // add trustedCertificate to trust store
    if (X509_STORE_add_cert(trustStore.get(), trustedX509.get()) != 1) {
        throw new std::runtime_error("Cannot add trusted certificate to trust store");
    }
}

bool X509CertificateChainValidator::ValidateCertificateChain(const std::vector<std::string>& caCertificates) {
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> storeCtx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (storeCtx == NULL) {
        throw new std::runtime_error("Cannot initialize X509_STORE_CTX");
    }

    auto deleter = [&](STACK_OF(X509) *ptr) { sk_X509_pop_free(ptr, X509_free); };
    std::unique_ptr<STACK_OF(X509), decltype(deleter)> untrustedChain(sk_X509_new_null(), deleter);
    if (untrustedChain == NULL) {
        throw new std::runtime_error("Cannot initialize STACK_OF(X509)");
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> bioCert(BIO_new(BIO_s_mem()), BIO_free);
    if (bioCert == NULL) {
        throw new std::runtime_error("Cannot initialize BIO for ceritificate");
    }

    // create untrusted chain
    for(size_t i=1; i < caCertificates.size(); i++)
    {
        bioCert.reset(BIO_new(BIO_s_mem()));
        if (BIO_puts(bioCert.get(), caCertificates[i].c_str()) < 0) {
            throw new std::runtime_error("Cannot write trusted certificate to BIO");
        }

        if (sk_X509_push(untrustedChain.get(), PEM_read_bio_X509(bioCert.get(), NULL, NULL, NULL)) <= 0) {
            throw new std::runtime_error("Cannot write trusted certificate to BIO");
        }
    }
    
    bioCert.reset(BIO_new(BIO_s_mem()));
    if (BIO_puts(bioCert.get(), caCertificates[0].c_str()) < 0) {
        throw new std::runtime_error("Cannot write trusted certificate to BIO");
    }

    std::unique_ptr<X509, decltype(&X509_free)> cert(PEM_read_bio_X509(bioCert.get(), NULL, NULL, NULL), X509_free);
    if (cert == NULL) {
        throw new std::runtime_error("Cannot initialize X509");
    }

    if (X509_STORE_CTX_init(storeCtx.get(), trustStore.get(), cert.get(), untrustedChain.get()) != 1) {
        throw new std::runtime_error("Cannot initialize X509_STORE_CTX");
    }

    return X509_verify_cert(storeCtx.get()) == 1;
}
