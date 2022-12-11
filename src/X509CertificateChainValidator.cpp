#include <iostream>
#include <openssl/pem.h>
//#include <openssl/x509.h>
//#include <openssl/x509v3.h>
#include <X509CertificateChainValidator.h>

bool X509CertificateChainValidator::Verify(const std::string& certificate_file) 
{
    return Verify(certificate_file, defaultTrustedCaFile);
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
