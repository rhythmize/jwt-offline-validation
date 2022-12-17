#include <iostream>
#include <openssl/pem.h>
#include <openssl/err.h>
//#include <openssl/x509.h>
//#include <openssl/x509v3.h>
#include <X509CertificateChainValidator.h>

bool X509CertificateChainValidator::Verify(const std::string& certificate_file) 
{
    return Verify(certificate_file, defaultTrustedCaFile);
}

bool X509CertificateChainValidator::Verify(const std::vector<std::string>& certificates)
{
    bool final = true;
    for(size_t i=1; i < certificates.size(); i++) {
        bool res = Verify(certificates[i-1], certificates[i]);
        final &= res;
        //std::cout << "result of " << i-1 << " cert: " << res << "\n";
    }
    return final;
}

bool X509CertificateChainValidator::Verify(const std::string& certificate_file, const std::string& trustedCertificateFile) 
{
    std::string cert = fileIoUtils->getFileContents(certificate_file);
    std::string issuer = fileIoUtils->getFileContents(trustedCertificateFile);
    
    //OpenSSL_add_all_algorithms(); 
    //OpenSSL_add_all_ciphers(); 
    //OpenSSL_add_all_digests(); 

    return VerifySignature(cert, issuer) == 1;
}

bool X509CertificateChainValidator::VerifyUsingX509Store(const std::string& certificate_file/*, const std::string& intermediateCaFile*/, const std::string& rootCaFile)
{
    std::string certificate = fileIoUtils->getFileContents(certificate_file);
    std::string rootCaContent = fileIoUtils->getFileContents(rootCaFile);

    BIO *r = BIO_new(BIO_s_mem());
    BIO_puts(r, rootCaContent.c_str());
    X509* rootCa = PEM_read_bio_X509(r, NULL, NULL, NULL);

    /*BIO *i = BIO_new(BIO_s_mem());
    BIO_puts(i, intermediateCaFile.c_str());
    X509* intermediateCa = PEM_read_bio_X509(i, NULL, NULL, NULL);
    EVP_PKEY *intermediate_key=X509_get_pubkey(intermediateCa);*/
    
    BIO *t = BIO_new(BIO_s_mem());
    BIO_puts(t, fileIoUtils->getFileContents(defaultTrustedCaFile.c_str()).c_str());
    X509* trustedCa = PEM_read_bio_X509(t, NULL, NULL, NULL);
    
    BIO *c = BIO_new(BIO_s_mem());
    BIO_puts(c, certificate.c_str());
    X509* cert = PEM_read_bio_X509(c, NULL, NULL, NULL);
 
    STACK_OF(X509) *chain = sk_X509_new_null();
    //sk_X509_push(chain, trustedCa);

    X509_STORE_CTX* storeCtx = X509_STORE_CTX_new();
    X509_STORE *trust_store = X509_STORE_new();
    
    X509_STORE_add_cert(trust_store, rootCa);

    X509_STORE_CTX_init(storeCtx, trust_store, cert, chain);

    int result = X509_verify_cert(storeCtx);
    
    //EVP_PKEY_free(intermediate_key);
    BIO_free(r);
    //BIO_free(i);
    BIO_free(t);
    BIO_free(c);
    X509_free(rootCa);
    X509_free(cert);
    X509_free(trustedCa);
    //X509_free(intermediateCa);
    X509_STORE_CTX_free(storeCtx);
    sk_X509_free(chain);
    X509_STORE_free(trust_store);
 
    return result;
}

bool X509CertificateChainValidator::VerifyUsingX509Store(const std::vector<std::string>& certificateFiles)
{
    X509_STORE_CTX* storeCtx = X509_STORE_CTX_new();
    X509_STORE *trustStore = X509_STORE_new();

    STACK_OF(X509) *chain = sk_X509_new_null();
    BIO *b = BIO_new(BIO_s_mem());
    X509* caCert;
    std::string data;

    for(size_t i=1; i < certificateFiles.size() - 1; i++)
    {
        // create untrusted chain
        data = fileIoUtils->getFileContents(certificateFiles[i]);
        BIO_puts(b, data.c_str());
        caCert = PEM_read_bio_X509(b, NULL, NULL, NULL);
        sk_X509_push(chain, caCert);
        BIO_reset(b);
    }
    
    // add trusted ca to store
    data = fileIoUtils->getFileContents(certificateFiles[certificateFiles.size() - 1]);
    //data = fileIoUtils->getFileContents(defaultTrustedCaFile);
    BIO_puts(b, data.c_str());
    caCert = PEM_read_bio_X509(b, NULL, NULL, NULL);
    X509_STORE_add_cert(trustStore, caCert);
    
    data = fileIoUtils->getFileContents(certificateFiles[0]);
    BIO_reset(b);
    BIO_puts(b, data.c_str());
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

int X509CertificateChainValidator::VerifySignature(const std::string& certificate, const std::string& trustedCertificate)
{
    BIO *b = BIO_new(BIO_s_mem());
    BIO_puts(b, trustedCertificate.c_str());
    X509 * issuer = PEM_read_bio_X509(b, NULL, NULL, NULL);
    EVP_PKEY *signing_key=X509_get_pubkey(issuer);
 
    BIO *c = BIO_new(BIO_s_mem());
    BIO_puts(c, certificate.c_str());
    X509 * x509 = PEM_read_bio_X509(c, NULL, NULL, NULL);
 
    int result = X509_verify(x509, signing_key);
    
    EVP_PKEY_free(signing_key);
    BIO_free(b);
    BIO_free(c);
    X509_free(x509);
    X509_free(issuer);
 
    return result;
}

void X509CertificateChainValidator::printCertificateInfo(const std::string& cert_pem)
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
