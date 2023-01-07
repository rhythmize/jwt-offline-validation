#include <jwt-cpp/jwt.h>
#include <JwtTokenHelper.h>


jwt::builder<jwt::traits::kazuho_picojson> JwtTokenHelper::GetModifiedTokenBuilder(const std::string& jwtToken) {
    jwt::builder<jwt::traits::kazuho_picojson> newTokenBuilder = jwt::create();
    auto decodedOriginalToken = jwt::decode(jwtToken);

    for(auto &e: decodedOriginalToken.get_header_json()) {
        newTokenBuilder.set_header_claim(e.first, e.second);
    }
    for(auto &e: decodedOriginalToken.get_payload_json()) {
        newTokenBuilder.set_payload_claim(e.first, e.second);
    }

    // modify iat & exp claims
    return newTokenBuilder
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{120});  // expire token after 2 mins
}

void JwtTokenHelper::ValidateTokenAgainstPublicKey(const std::string& jwtToken, const std::string& publicKey) {
    CheckValidity(jwtToken, publicKey);
}

void JwtTokenHelper::ValidateTokenAgainstPublicCertificate(const std::string& token, const std::vector<std::string>& caCerts,
    std::shared_ptr<X509CertificateChainValidator> validator) {
    std::cout << "Cert Validation: " << validator->ValidateCertificateChain(caCerts) << "\n";
    // validate token against first certificate
    CheckValidity(token, caCerts[0]);
}

void JwtTokenHelper::CheckValidity(const std::string& jwtToken, const std::string& publicKey) {
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

std::string JwtTokenHelper::SignToken(const jwt::builder<jwt::traits::kazuho_picojson>& jwtTokenBuilder, const std::string& privateKey) {
    return jwtTokenBuilder.sign(jwt::algorithm::rs256("", privateKey, "", ""));
}

void JwtTokenHelper::PrintTokenClaims(const std::string& jwtToken) {
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
