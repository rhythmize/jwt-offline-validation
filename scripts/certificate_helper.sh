#!/bin/bash
opensslConfigFile=$(dirname $0)/openssl_ca.cnf

create_certificate() {
    local certCname=$1
    local signerCname=$2

    # prepare directory for certificate
    dirpath=$(getDirectoryPath $certCname)
    mkdir -p $dirpath
    # Generate new RSA private key and CSR for public certificate
    echo -e "\t[*] Generating new RSA private key and CSR for '${certCname}' in '${dirpath}' ..."
    openssl req -nodes -newkey rsa:4096 -sha256 -keyout "${dirpath}/private.pem" -out "${dirpath}/certificate.csr" -subj "/CN=${certCname}" 2>/dev/null
    
    # Sign CSR and generate public X509 certificate
    # This should ideally happen on the CA side. Doing it here only for demonstration purposes
    echo -e "\t[*] Signing CSR for '${certCname}' using '${signerCname}' ..."
    signerPath=$(getDirectoryPath $signerCname)
    openssl x509 -req -days 1 -CA "${signerPath}/certificate.crt" -CAkey "${signerPath}/private.pem" -CAcreateserial -extfile $opensslConfigFile -extensions ca_cert -in "${dirpath}/certificate.csr" -out "${dirpath}/certificate.crt" 2>/dev/null
}

create_certificate_chain() {
    local intermediateCaCount=$1

    rootCname='root'
    leafCname='leaf'

    # create self signed root CA
    dirpath=$(getDirectoryPath $rootCname)
    mkdir -p $dirpath
    # generate RSA private key and self signed public X509 certificate 
    echo -e "\t[*] Generating new RSA private key and public certificate for '${rootCname}' in '${dirpath}' ..."
    openssl req -x509 -nodes -newkey rsa:4096 -days 1 -config $opensslConfigFile -extensions ca_cert -sha256 -keyout "${dirpath}/private.pem" -out "${dirpath}/certificate.crt" -subj "/CN=root" 2>/dev/null

    # create recursive intermediate CAs where next one is siged by previous one 
    signerCname=${rootCname}
    for i in $(seq 1 $intermediateCaCount)
    do
        certCname="intermediate${i}"
        create_certificate $certCname $signerCname
        signerCname=${certCname}
    done

    # create leaf certificate
    create_certificate $leafCname $signerCname
    
    leafPath=$(getDirectoryPath $leafCname)
    # create CA chain of intermediate certificates
    echo -e "\t[*] Creating certificate chain in '${leafPath}' ..."
    touch "${leafPath}/ca-chain.crt"
    for i in $(seq $intermediateCaCount -1 1)
    do
        certDirPath=$(getDirectoryPath intermediate${i})
        cat "${certDirPath}/certificate.crt" >> "${leafPath}/ca-chain.crt"
    done
    # append self signed root CA into the chain
    cat "$(getDirectoryPath $rootCname)/certificate.crt" >> "${leafPath}/ca-chain.crt"
}

validate_certificate() {
    local cert=$1
    local caChain=$2

    # verify X509 certificate against CA certificate chain
    openssl verify -CAfile $caChain $cert
}
