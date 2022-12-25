#ifndef _X509CertificateChainValidator_H_
#define _X509CertificateChainValidator_H_

#include <memory>
#include <vector>
#include <FileIoUtils.h>

class X509CertificateChainValidator
{
public:
    bool VerifyUsingX509Store(const std::vector<std::string>& certificateFiles);
    void printCertificateInfo(const std::string& certificate);
private:
    std::unique_ptr<FileIoUtils> fileIoUtils = std::make_unique<FileIoUtils>();
};

#endif // _X509CertificateChainValidator_H_
