#include <openssl/pem.h>
#include <X509CertificateChainValidator.h>


bool X509CertificateChainValidator::VerifyUsingX509Store(const std::vector<std::string>& caCertificates)
{
    X509_STORE_CTX* storeCtx = X509_STORE_CTX_new();
    X509_STORE *trustStore = X509_STORE_new();

    STACK_OF(X509) *chain = sk_X509_new_null();
    BIO *b = BIO_new(BIO_s_mem());
    X509* caCert;
    std::string data;

    for(size_t i=1; i < caCertificates.size() - 1; i++)
    {
        // create untrusted chain
        BIO_puts(b, caCertificates[i].c_str());
        caCert = PEM_read_bio_X509(b, NULL, NULL, NULL);
        sk_X509_push(chain, caCert);
        BIO_reset(b);
    }
    
    // add trusted ca to store
    BIO_puts(b, caCertificates[caCertificates.size() - 1].c_str());
    caCert = PEM_read_bio_X509(b, NULL, NULL, NULL);
    X509_STORE_add_cert(trustStore, caCert);
    
    BIO_reset(b);
    BIO_puts(b, caCertificates[0].c_str());
    X509* cert = PEM_read_bio_X509(b, NULL, NULL, NULL);

    X509_STORE_CTX_init(storeCtx, trustStore, cert, chain);

    int result = X509_verify_cert(storeCtx);

    BIO_free(b);
    X509_free(cert);
    X509_free(caCert);
    X509_STORE_CTX_free(storeCtx);
    X509_STORE_free(trustStore);
    sk_X509_pop_free(chain, X509_free);
    return result;
}

void X509CertificateChainValidator::PrintCertificateInfo(const std::string& cert_pem)
{
    BIO *b = BIO_new(BIO_s_mem());
    BIO_puts(b, cert_pem.c_str());
    X509 * x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);
 
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
 
    BIO_printf(bio_out, "Subject: ");
    X509_NAME_print(bio_out, X509_get_subject_name(x509), 0);
    BIO_printf(bio_out, "\n");
 
    BIO_printf(bio_out, "Issuer: ");
    X509_NAME_print(bio_out, X509_get_issuer_name(x509), 0);
    BIO_printf(bio_out, "\n");
 
    EVP_PKEY *pkey=X509_get_pubkey(x509);
    EVP_PKEY_print_public(bio_out, pkey, 0, NULL);
    EVP_PKEY_free(pkey);

    const ASN1_BIT_STRING *signature;
    const X509_ALGOR *alg;

    X509_get0_signature(&signature, &alg, x509);

    X509_signature_print(bio_out, alg, signature);
    BIO_printf(bio_out,"\n");
 
    BIO_free(bio_out);
    BIO_free(b);
    X509_free(x509);
}
