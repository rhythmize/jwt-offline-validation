#!/bin/bash

if [[ -z $1 ]] || ! [ $1 -eq $1 ]; then
	echo -e "Usage:\tcreate_certs.sh <number of intermediate CAs>"
	exit 1
fi

intermediateCaCount=$1
configFile=$(dirname $0)/openssl_ca.cnf
rootDir='root'
leafDir='leaf'

# create self signed root CA
mkdir -p ${rootDir}
openssl req -x509 -nodes -newkey rsa:4096 -sha256 -keyout ${rootDir}/private.pem -out ${rootDir}/certificate.crt -subj "/CN=root"

# create recursive intermediate CAs where next one is siged by previous one 
signerDir=${rootDir}
for i in $(seq 1 $intermediateCaCount)
do
	signeeDir="intermediate${i}"
	mkdir -p ${signeeDir}
	openssl req -nodes -newkey rsa:4096 -sha256 -keyout ${signeeDir}/private.pem -out ${signeeDir}/certificate.csr -subj "/CN=${signeeDir}"
	openssl x509 -req -CA ${signerDir}/certificate.crt -CAkey ${signerDir}/private.pem -CAcreateserial -extfile $configFile -extensions v3_intermediate_ca -in ${signeeDir}/certificate.csr -out ${signeeDir}/certificate.crt
	signerDir=${signeeDir}
done

# create leaf certificate
mkdir -p ${leafDir}
openssl req -nodes -newkey rsa:4096 -sha256 -keyout leaf/private.pem -out leaf/certificate.csr -subj "/CN=test"
openssl x509 -req -CA ${signerDir}/certificate.crt -CAkey ${signerDir}/private.pem -CAcreateserial -extfile $configFile -extensions server_cert -in ${leafDir}/certificate.csr -out ${leafDir}/certificate.crt


# create CA chain for leaf certificate
touch ${leafDir}/ca-chain.crt
for i in $(seq $intermediateCaCount -1 1)
do
	certDir="intermediate${i}"
	cat ${certDir}/certificate.crt >> ${leafDir}/ca-chain.crt
done
cat ${rootDir}/certificate.crt >> ${leafDir}/ca-chain.crt
