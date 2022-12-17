#ifndef _X509CertificateChainValidator_H_
#define _X509CertificateChainValidator_H_

#include <memory>
#include <vector>
#include <FileIoUtils.h>

class X509CertificateChainValidator
{
public:
    bool Verify(const std::string& certificate_file);
    bool Verify(const std::string& certificate_file, const std::string& trustedCertificateFile);
    bool Verify(const std::vector<std::string>& caFiles);
    bool VerifyUsingX509Store(const std::string& certificate_file/*, const std::string& intermediateCaFile*/, const std::string& rootCaFile);
    bool VerifyUsingX509Store(const std::vector<std::string>& certificateFiles);
    void printCertificateInfo(const std::string& certificate);
private:
    int VerifySignature(const std::string& certificate, const std::string& trustedCertificate);
    std::string defaultTrustedCaFile = "/etc/ssl/certs/ca-certificates.crt";
    std::unique_ptr<FileIoUtils> fileIoUtils = std::make_unique<FileIoUtils>();
};

#endif // _X509CertificateChainValidator_H_
