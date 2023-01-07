#include <memory>
#include <openssl/pem.h>
#include <X509CertificateChainValidator.h>


bool X509CertificateChainValidator::ValidateCertificateChain(const std::vector<std::string>& caCertificates) {
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> storeCtx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> trustStore(X509_STORE_new(), X509_STORE_free);

    auto deleter = [&](STACK_OF(X509) *ptr) { sk_X509_pop_free(ptr, X509_free); };
    std::unique_ptr<STACK_OF(X509), decltype(deleter)> untrustedChain(sk_X509_new_null(), deleter);

    std::unique_ptr<BIO, decltype(&BIO_free)> bioCert(BIO_new(BIO_s_mem()), BIO_free);
    
    // create untrusted chain
    for(size_t i=1; i < caCertificates.size(); i++)
    {
        bioCert.reset(BIO_new(BIO_s_mem()));
        BIO_puts(bioCert.get(), caCertificates[i].c_str());
        sk_X509_push(untrustedChain.get(), PEM_read_bio_X509(bioCert.get(), NULL, NULL, NULL));
    }
    
    // add trusted ca to store 
    // !!! SHOULD BE DONE OUTSIDE THIS METHOD INDEPENDENTLY !!!
    bioCert.reset(BIO_new(BIO_s_mem()));
    BIO_puts(bioCert.get(), caCertificates[caCertificates.size() - 1].c_str());

    std::unique_ptr<X509, decltype(&X509_free)> trustedCert(PEM_read_bio_X509(bioCert.get(), NULL, NULL, NULL), X509_free);
    X509_STORE_add_cert(trustStore.get(), trustedCert.get());
    
    bioCert.reset(BIO_new(BIO_s_mem()));
    BIO_puts(bioCert.get(), caCertificates[0].c_str());

    std::unique_ptr<X509, decltype(&X509_free)> cert(PEM_read_bio_X509(bioCert.get(), NULL, NULL, NULL), X509_free);

    X509_STORE_CTX_init(storeCtx.get(), trustStore.get(), cert.get(), untrustedChain.get());

    int result = X509_verify_cert(storeCtx.get());
    return result;
}
