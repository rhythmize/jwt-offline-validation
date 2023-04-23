#!/bin/bash

opensslConfigFile=$(dirname $0)/openssl_ca.cnf

getDirectoryPath() {
	if [[ -z $1 ]]; then
		echo -e "No directory name provided."
		return 1
	fi
    echo "scenarios/${1}"
}

create_certificate() {
    local certCname=$1
    local certPath=$2
    local signerCname=$3
    local signerPath=$4

    # prepare directory for certificate
    mkdir -p $certPath
    # Generate new RSA private key and CSR for public certificate
    echo -e "\t[*] Generating new RSA private key and CSR for '${certCname}' in '${certPath}' ..."
    openssl req -nodes -newkey rsa:4096 -sha256 -keyout "${certPath}/private.pem" -out "${certPath}/certificate.csr" -subj "/CN=${certCname}" 2>/dev/null
    
    # Sign CSR and generate public X509 certificate
    # This should ideally happen on the CA side. Doing it here only for demonstration purposes
    echo -e "\t[*] Signing CSR for '${certCname}' using '${signerCname}' ..."
    openssl x509 -req -days 1 -CA "${signerPath}/certificate.crt" -CAkey "${signerPath}/private.pem" -CAcreateserial -extfile $opensslConfigFile -extensions ca_cert -in "${certPath}/certificate.csr" -out "${certPath}/certificate.crt" 2>/dev/null
}

create_certificate_chain() {
    local intermediateCaCount=$1
    local rootCname=$2
    local intermediateCnamePrefix=$3
    local leafCname=$4

    # create self signed root CA
    rootPath=$(getDirectoryPath root)
    mkdir -p $rootPath
    # generate RSA private key and self signed public X509 certificate 
    echo -e "\t[*] Generating new RSA private key and public certificate for '${rootCname}' in '${rootPath}' ..."
    openssl req -x509 -nodes -newkey rsa:4096 -days 1 -config $opensslConfigFile -extensions ca_cert -sha256 -keyout "${rootPath}/private.pem" -out "${rootPath}/certificate.crt" -subj "/CN=${rootCname}" 2>/dev/null

    # create recursive intermediate CAs where next one is siged by previous one 
    signerCname=${rootCname}
    signerPath=${rootPath}
    for i in $(seq 1 $intermediateCaCount)
    do
        certPath=$(getDirectoryPath "intermediate${i}")
        certCname="${intermediateCnamePrefix}${i}"
        create_certificate $certCname $certPath $signerCname $signerPath
        signerCname=${certCname}
        signerPath=${certPath}
    done

    # create leaf certificate
    leafPath=$(getDirectoryPath leaf)
    create_certificate $leafCname $leafPath $signerCname $signerPath
    
    # create CA chain of intermediate certificates
    echo -e "\t[*] Creating certificate chain in '${leafPath}' ..."
    # prepare ca-chain
    cp "${leafPath}/certificate.crt" "${leafPath}/ca-chain.crt"
    for i in $(seq $intermediateCaCount -1 1)
    do
        certDirPath=$(getDirectoryPath intermediate${i})
        cat "${certDirPath}/certificate.crt" >> "${leafPath}/ca-chain.crt"
    done
    # copy self signed root CA to leaf directory
    cp "${rootPath}/certificate.crt" "${leafPath}/root_certificate.crt"
}

validate_certificate() {
    local trustedCert=$1
    local caChain=$2
    local cert=$3

    echo -ne "\033[0;34mCertificate chain validation: \033[0m"
    if [ -s $caChain ];then
    	# verify X509 certificate chain
        openssl verify -CAfile $trustedCert -untrusted $caChain $cert &> /dev/null
    else
        # empty ca-chain
        openssl verify -CAfile $trustedCert $cert &> /dev/null
    fi

    if [ $? -eq 0 ]; then
        echo -e "\033[0;32mCertificate chain is valid\033[0m"

    else
        echo -e "\033[0;31mCertificate chain is invalid\033[0m"
    fi
}
