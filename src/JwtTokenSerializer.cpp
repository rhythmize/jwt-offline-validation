#include <jwt-cpp/jwt.h>
#include <JwtTokenSerializer.h>

std::string JwtTokenSerializer::updateToken(const std::string& privateKeyFile) 
{
    std::string privateKey =  fileIoUtils->getFileContents(privateKeyFile);

    auto newToken = jwt::create();
    auto decodedOriginalToken = jwt::decode(originalToken);

    for(auto &e: decodedOriginalToken.get_header_json()) {
        newToken.set_header_claim(e.first, e.second);
    }
    for(auto &e: decodedOriginalToken.get_payload_json()) {
        newToken.set_payload_claim(e.first, e.second);
    }

    // modify issued at & expiration date.
    std::string updatedToken = newToken
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
        .sign(jwt::algorithm::rs256("", privateKey, "", ""));
    
    std::cout << "Token updated successfully\n";
    return updatedToken;
}

void JwtTokenSerializer::checkValidity(const std::string& jwtToken, const std::string& publicKeyFile)
{
    std::string publicKey = fileIoUtils->getFileContents(publicKeyFile);
    
    auto decodedForgedToken = jwt::decode(jwtToken);
    auto forgedVerifier = jwt::verify()
        .allow_algorithm(jwt::algorithm::rs256(publicKey, "", "", ""))
        .with_issuer(decodedForgedToken.get_issuer());

    try {
        forgedVerifier.verify(decodedForgedToken);
        std::cout << "Token is valid !!!\n";
    } catch (jwt::error::token_verification_exception &e) {
        std::cout << "Token verification exception: " << e.code() << "\n" << e.what() << "\n";
    }
}

void JwtTokenSerializer::printTokenClaims(const std::string& jwtToken) 
{
    auto decodedToken = jwt::decode(jwtToken);
    std::cout << "Header Claims: \n";
    for(auto &e: decodedToken.get_header_json()) {
        std::cout << "\t" << e.first << ": " << e.second << "\n";
    }
    std::cout << "Payload Claims: \n";
    for(auto &e: decodedToken.get_payload_json()) {
        std::cout << "\t" << e.first << ": " << e.second << "\n";
    }
}

void JwtTokenSerializer::printOriginalTokenClaims()
{
    printTokenClaims(originalToken);
}