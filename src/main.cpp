#include <iostream>
#include <FileIoUtils.h>
#include <Runner.h>

int main(int argc, char *argv[])
{
    std::string jwtToken = FileIoUtils::getFileContents("certs/trusted_flight/aerobridge_trusted_flight.jwt.json");
    
    Runner::ValidateOriginalToken(jwtToken);
    std::cout << "=========================================================\n\n";
 
    Runner::ModifyTokenAndValidateAgainstCustomPublicKey(jwtToken);
    std::cout << "=========================================================\n\n";
    
    Runner::ValidateWithInMemoryKeys(jwtToken);
    std::cout << "=========================================================\n\n";

    Runner::ModifyTokenAndValidateAgainstSelfSignedCertificate(jwtToken);
    std::cout << "=========================================================\n\n";

    Runner::ValidateWithInMemoryCert(jwtToken);
    std::cout << "=========================================================\n\n";

    Runner::ModifyTokenAndValidateAgainstRootCaSignedCertificate(jwtToken);
    std::cout << "=========================================================\n\n";

    Runner::ValidateWithInMemoryRootCert(jwtToken);
    std::cout << "=========================================================\n\n";
    
    Runner::ModifyTokenAndValidateAgainstIntermediateCaSignedCertificate(jwtToken);
    std::cout << "=========================================================\n\n";

    Runner::ValidateWithInMemoryIntermediateCert(jwtToken);
    std::cout << "=========================================================\n\n";
}
