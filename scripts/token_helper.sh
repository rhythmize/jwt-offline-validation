#!/bin/bash

base64_complaint()  {
    local string=$1
    local mod=$((${#string}%4))

	if [ $mod -eq 1 ]; then
       string="${string}==="
    elif [ $mod -eq 2 ]; then
       string="${string}=="
    elif [ $mod -eq 3 ]; then
		string="${string}="
	fi
    echo $string
}

print_token() {
	local token=$1

	# print only header and payload part of decoded JWT
	jq -R 'split(".") | .[0,1] | @base64d | fromjson' <<< $token
}

validate_token() {
	local token=$1 # jwt token to validate
	local publicKey=$2 # public key or X509 certificate file

	# extract header, payload and signature from JWT token
	IFS='.' read -r header payload signature <<< $token
	dataToVerify="${header}.${payload}"
	signature=$(base64_complaint $signature)

	set +e # do not exit if openssl commands fail
	# extract RSA public key from X509 certificate
	pubkey=$(openssl x509 -pubkey -noout -in $publicKey 2>/dev/null)
	if [ $? -ne 0 ]; then
		# if unable to extract public, use as is 
		echo -ne "pubkey fail using direct key\n\t"
		pubkey=$(cat $publicKey)
	fi

	# verify header+payload signature using public key
    openssl dgst -sha256 -verify <(echo "$pubkey") -signature <(echo -n $signature | base64url -d) <(echo -n $dataToVerify)
    if [ $? -eq 0 ]; then
        # check token for expiration
        exp=$(jq -r -R '@base64d | fromjson | .exp ' <<< $payload)
        if [ $(date +%s) -ge $exp ]; then
            echo -e "\tToken is expired."
            return
        fi    
    else
        echo -e "\tToken signature not valid"
        return
    fi
    set -e
    echo -e "\tToken is valid"
}

modify_token() {
	local token=$1
	local key=$2

	# extract header, payload and signature from JWT token
    IFS='.' read -r header payload signature <<< $token

	iat=$(date +%s)	
	exp=$(date -d '+120 sec' +%s)	# expire token after 2 mins

    # modify iat and exp claims of JWT payload
	updpayload=$(jq -r --arg iat $iat --arg exp $exp  -R '@base64d | fromjson | (.iat) |= ($iat | tonumber) | (.exp) |= ($exp | tonumber) | @base64' <<< $payload)
	# remove base64 padding from payload
	updpayload=$(tr -d = <<< $updpayload)

	dataToSign="$header.$updpayload"
	# sign header+payload using private key
    newsign=$(openssl dgst -sha256 -sign $key <(echo -n $dataToSign) | base64url -w 0)
	# remove base64 padding from signature
	newsign=$(tr -d = <<< $newsign)

	newToken="$header.$updpayload.$newsign"
	echo -n $newToken > $(getDirectoryPath "updated_token")
	echo $newToken
}
