#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <X509Certificate.h>
#include <jwt-cpp/jwt.h>


X509Certificate::X509Certificate(std::string& cname) : certCname(cname), x509(X509_new(), X509_free), 
    x509Req(X509_REQ_new(), X509_REQ_free), keyPair(new RsaKeyPair(4096)), x509V3Extensions(new X509V3Extensions(x509)) { }

std::unique_ptr<X509, decltype(&X509_free)> X509Certificate::GetX509FromDerString(std::string& derCert) {
    std::unique_ptr<unsigned char[]> base64Decoded(new unsigned char[2000]());
    
    int decodedLen = EVP_DecodeBlock(base64Decoded.get(), reinterpret_cast<unsigned char *>(const_cast<char *>(derCert.data())), derCert.length());
    if (decodedLen == -1) {
        throw new std::runtime_error("Cannot decode base 64 DER certificate\n");
    }

    const unsigned char *decodedPtr = base64Decoded.get();
    std::unique_ptr<X509, decltype(&X509_free)> x509(d2i_X509(NULL, &decodedPtr, decodedLen), X509_free);
    if (x509 == NULL) {
        throw new std::runtime_error("Cannot create X509 from DER certificate\n");
    }
    
    return x509;
}

X509Certificate* X509Certificate::GenerateCertificateSigningRequest() {
    if (X509_REQ_set_pubkey(x509Req.get(), keyPair->GetKeyPair().get()) != 1) {
        throw new std::runtime_error("Cannot set public key for CSR");
    }

    unsigned char *cnamePtr = reinterpret_cast<unsigned char *>(const_cast<char*>(certCname.c_str()));
    if (X509_NAME_add_entry_by_txt(X509_REQ_get_subject_name(x509Req.get()), "CN", MBSTRING_ASC, cnamePtr, -1, -1, 0) != 1) {
        throw new std::runtime_error("Cannot set common name for CSR");
    }

    if (X509_REQ_sign(x509Req.get(), keyPair->GetKeyPair().get(), EVP_sha256()) == 0) {
        throw new std::runtime_error("Cannot self-sign CSR");
    }
    return this;
}

std::string X509Certificate::GetPublicDerCert() {
    std::unique_ptr<BIO, decltype(&BIO_free)> bioDer(BIO_new(BIO_s_mem()), BIO_free);
    
    unsigned char *derCert = NULL;
    int derLen = i2d_X509(x509.get(), &derCert);
    if (derLen < 0)
        throw new std::runtime_error("Cannot convert X509 to DER format");

    // base64 encoding generate 4 bytes of output for every 3 bytes of input
    int encodedLen = derLen % 3 ? ((derLen / 3) + 1) * 4 : derLen / 3 * 4 ;
    
    std::unique_ptr<unsigned char[]> base64Der(new unsigned char[encodedLen + 1]());
    if (EVP_EncodeBlock(base64Der.get(), derCert, derLen) <= 0)
        throw new std::runtime_error("Cannot encode DER certificate");
    
    OPENSSL_free(derCert);
    return std::string((char *)base64Der.get());
}

std::string X509Certificate::GetPrivateKey() {
    return keyPair->GetPrivateKey();
}

X509Certificate* X509Certificate::ConfigureCertificateParameters() {
    setVersionAndSerialNumber();

    if (X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0) == NULL) {
        throw new std::runtime_error("Cannot update not before time for certificate");
    }
    
    // expire in 1 hour 
    if (X509_gmtime_adj(X509_getm_notAfter(x509.get()), 3600L) == NULL) {
        throw new std::runtime_error("Cannot update expiration time for certificate");
    }

    if (X509_set_subject_name(x509.get(), X509_REQ_get_subject_name(x509Req.get())) != 1) {
        throw new std::runtime_error("Cannot set subject name for Certificate");
    }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> csrPubKey(X509_REQ_get_pubkey(x509Req.get()), EVP_PKEY_free);
    if (csrPubKey == NULL) {
        throw new std::runtime_error("Cannot get public key from CSR");
    }

	if (X509_set_pubkey(x509.get(), csrPubKey.get()) != 1) {
        throw new std::runtime_error("Cannot set publick key for certificate");
    }
    return this;
}

void X509Certificate::SignAsCaCert(std::shared_ptr<X509Certificate> signingCertificate) {
    x509V3Extensions
        ->SetContext(signingCertificate->x509, x509Req)
        ->AddCaCertificateExtensions();
    sign(signingCertificate);
}

void X509Certificate::SignAsServerCert(std::shared_ptr<X509Certificate> signingCertificate) {
    x509V3Extensions
        ->SetContext(signingCertificate->x509, x509Req)
        ->AddServerCertificateExtensions();
    sign(signingCertificate);
}

void X509Certificate::PrintCertificateInfo() {
    std::unique_ptr<BIO, decltype(&BIO_free)> bioConsole(BIO_new_fp(stdout, BIO_NOCLOSE), BIO_free);
    if (bioConsole == NULL) {
        throw new std::runtime_error("Cannot initialize BIO");
    }

    if (BIO_printf(bioConsole.get(), "Subject: ") < 0) {
        throw new std::runtime_error("Cannot write to console");
    }
    if (X509_NAME_print(bioConsole.get(), X509_get_subject_name(x509.get()), 0) != 1) {
        throw new std::runtime_error("Cannot write to console");
    }
    if (BIO_printf(bioConsole.get(), "\n") < 0) {
        throw new std::runtime_error("Cannot write to console");
    }
 
    if (BIO_printf(bioConsole.get(), "Issuer: ") < 0) {
        throw new std::runtime_error("Cannot write to console");
    }
    if (X509_NAME_print(bioConsole.get(), X509_get_issuer_name(x509.get()), 0) != 1) {
        throw new std::runtime_error("Cannot write to console");
    }
    if (BIO_printf(bioConsole.get(), "\n") < 0) {
        throw new std::runtime_error("Cannot write to console");
    }

    if (EVP_PKEY_print_public(bioConsole.get(), keyPair->GetKeyPair().get(), 0, NULL) != 1) {
        throw new std::runtime_error("Cannot write to console");
    }

    const ASN1_BIT_STRING *signature;
    const X509_ALGOR *alg;
    X509_get0_signature(&signature, &alg, x509.get());

    if (X509_signature_print(bioConsole.get(), alg, signature) != 1) {
        throw new std::runtime_error("Cannot write to console");
    }
    if (BIO_printf(bioConsole.get(),"\n") < 0) {
        throw new std::runtime_error("Cannot write to console");
    }
}

void X509Certificate::DumpToFile() {
    std::string keyFileName = certCname + "_private.pem";
    std::string certFileName = certCname + "_certificate.crt";
    std::string csrFileName = certCname + "_certificate.csr";
    
    std::unique_ptr<BIO, decltype(&BIO_free)> bioPrivateKey(BIO_new_file(keyFileName.c_str(), "wb"), BIO_free);
    if (bioPrivateKey == NULL) {
        throw new std::runtime_error("Cannot initialize BIO");
    }

    if (PEM_write_bio_PrivateKey(bioPrivateKey.get(), keyPair->GetKeyPair().get(), NULL, NULL, 0, NULL, NULL) != 1) {
        throw new std::runtime_error("Cannot write private key to file");
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> bioCertificate(BIO_new_file(certFileName.c_str(), "wb"), BIO_free);
    if (bioCertificate == NULL) {
        throw new std::runtime_error("Cannot initialize BIO");
    }

    if (PEM_write_bio_X509(bioCertificate.get(), x509.get()) != 1) {
        throw new std::runtime_error("Cannot write X509 certificate to file");
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> bioCertificateSigningRequest(BIO_new_file(csrFileName.c_str(), "wb"), BIO_free);
    if (bioCertificate == NULL) {
        throw new std::runtime_error("Cannot initialize BIO");
    }

    if (PEM_write_bio_X509_REQ(bioCertificateSigningRequest.get(), x509Req.get()) != 1) {
        throw new std::runtime_error("Cannot write X509 certificate to file");
    }
}

X509_NAME* X509Certificate::getSubjectName() {
    return X509_get_subject_name(x509.get());
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

void X509Certificate::sign(std::shared_ptr<X509Certificate> signingCertificate) {
    if (X509_set_issuer_name(x509.get(), signingCertificate->getSubjectName()) != 1) {
        throw new std::runtime_error("Cannot set issuer for certificate");
    }

    if (X509_sign(x509.get(), signingCertificate->keyPair->GetKeyPair().get(), EVP_sha256()) == 0) {
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
