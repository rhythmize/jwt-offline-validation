# Evaluate JWT Offline Validation

This repository is an attempt to explore the security aspect of JWT verification, especially while performing token validation on an offline device. 

I have attempted to implement the certificate generation and JWT token verification via C/C++ APIs and bash scripts.

## Disclaimer
The implementations for managing certificates and validating JWT in this repository are for demonstration purpose only. These implementations are not intended for production systems.

#### For C++ implementation
* `OpenSSL C APIs` are used for creating RSA Key Pair, X509 Certificates & CSR and validating certificate chain. 
* `jwt-cpp` is used for tampering and handling JWT tokens.

#### For bash
* `openssl command line utility` is used for creating Key Pair, Certificates and validating certificate chain.
* `jq` is used for tampering and handling JWT tokens.


# Dependencies
For running `scripts/verify_jwt.sh`, install these dependencies
```
sudo apt install jq basez
```

## Problem statement 
To figure out a way to implement JWT verification for an offline system which receives the token and verification keys over an insecure channel. Thus there's always a possibility of tampering with token in an attempt to bypass authentication.

This repository tries to implement and validate the poc for below scenarios for JWT validation using OpenSSL and jwt-cpp.

## Scenarios

#### Token Verification using RSA public key
1. System doesn't know which public key to trust
2. Attacker can sign the token his own key pair and provide the tampered token along with the public key and system will identify the token as valid.

#### Token Verification using X509 Public Certificate
1. System doesn't know which public certificate to trust
2. Attacker an sign the token using his own certificate pair and send it along the tampered token for validation and system will identify the token as valid.

#### Trust public certificate ahead of time 
1. Put public certificate in the trust store ahead of time
2. If attacker send his own public certificate with tampered token, system will identify the token invalid since the public certificate is not trusted.
3. System will render unusable once key pair is rotated by issuing server

#### Trust root certificate ahead of time  
1. Put public part of root certificate into the trust store ahead of time
1. Server will issue new certificate pair signed by root certificate. And use this end certificate to sign the token.
2. System will only trust the public certificate signed by the root certificate available in the trust store.
3. Even if the certificate/ key pair is rotated, system will still trust it as long as it's signed by the same root certificate.
4. There can be any number of intermediate certificates between root and signing certificate.
5. On the validation side, system will validate the certificate issuer chain (received over insecure channel) and if it's valid and trusted, only then the token will be validated against the received public key.

## Conclusion
Given the constrains, [Trust root certificate ahead of time](#trust-root-certificate-ahead-of-time) seems like the best option to appropriately implement JWT verification for an offline system so far.

## Usage
#### For C++ implementation
```
make clean
make run
```

#### For bash
```
cd scripts/
chmod +x verify_token.sh
./verify_jwt.sh <number-of-intermediate-certificates-in-CA-chain>
```