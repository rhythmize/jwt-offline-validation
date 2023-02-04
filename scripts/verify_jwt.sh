#!/bin/bash

source ./token_helper.sh
source ./certificate_helper.sh

if [[ -z $1 ]] || ! [ $1 -eq $1 ]; then
	echo -e "Usage:\tmodify_token.sh <number of intermediate CAs in certificate chain>"
	exit 1
fi

set -euo pipefail

intermediateCaCount=$1

getDirectoryPath() {
	if [[ -z $1 ]]; then
		echo -e "No directory name provided."
		return 1
	fi
    echo "certs/${1}"
}

originalToken="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkE3NHBUeDlIMDdMd1kyaGFrZVdPS0ZOZTNtaDhaNjZ3ZlFnQUhyME5\
OLUEifQ.eyJpc3MiOiJodHRwczovL2lkLm9wZW5za2llcy5zaC8iLCJleHAiOjE2NDAwMjQzMjIsImlhdCI6MTY0MDAyMDcyMiwic3ViIjoiZzM3bFhpZk\
FRb0JmVnVRWnhUM1ZKRmpYSU1nZGZYSU9wYTJMZFdCUUBjbGllbnRzIiwic2NvcGUiOiIiLCJ0eXAiOiJCZWFyZXIiLCJmbGlnaHRfcGxhbl9pZCI6IjEy\
ODE4ZTg3LTRjOTYtNGU0Yy04YzYzLTgyYjhlMTJjM2I3MyIsImZsaWdodF9vcGVyYXRpb25faWQiOiIzNDA4YmNlOS1kYmFiLTQ2NjUtYWJmYy04ZWEwM2\
IwYWQ4NzEiLCJwbGFuX2ZpbGVfaGFzaCI6ImEyYTIwMWVmYTExMWRkZTVhYWE4ZjQyYjdiNDZkMTdiNTk1ZTM5ZDg1MDUwMGRiYWNkOWY3OWFlZjBiYmY2\
OGUifQ.N9I9aPtlvuv8zYiNWEJwfZF8cR0mxh3vP7hda0Q8jbntfaQtM_hOPoAoywGGH9mAGDUZYpVk1BfC_HxwHEVolqtVFemLqKw_NpmA-nciw5ovmJZ\
9ermfzuDvLFSSSkf-9H2RQm30a8UFsq_K7q8HZjuda325-AhmzHgKk2QSPUdEiHN0Nm-XhtsZ5KxJzekTT0j7HmR7Siynrc5hi_iYBxWRufSop-1hlMjpr\
LcdVZsvVOoIjrby7Wjl0lA0vdl_-AovLnYaAKfOU-UoQoUvTUsRrkpFEYjwc5wHyGzXB63HSKBx0e31w4NXMHHoWueYs2C0lObvj6V2wxOPX8oBz-ks2yk\
hzLadkFnbaea6tr2Sv46UCsLrXVoDDn60M9eqAW1USCOQJD5ClUDmpZ097CznYbiQu9ErbJLTsB40L5WfEimyrLTynW9_PsWK2KAh5nUTvcCbBX21y3noo\
IQOghceGKK9EjwyN2MSs_9blxnrcgDOuGBjg04r7CsMy0rV3iTGpGBJRtB78nwov28InMlpReoTXSwHAEW1nuGccU1L2mVprkj33PMnjSBlhkljhH_1fvL\
Xw-rE12fu9L5x6XhR_laoaTF-Ncb0bwtxIzixgaFDdMYzJpgEr03POtQZYWaCRiQvIZYHt51uFbvWKbFm1OXifSe0G-Un9HnMHLg"

echo -e "[+] Cleaning up old certs, if any ..."
rm -rf certs/*

echo -e "[+] Create new RSA keys and certificates ..."
create_certificate_chain $intermediateCaCount

echo -e "[+] Modifying the original token ..."
newToken=$(modify_token $originalToken $(getDirectoryPath leaf)/private.pem)

echo -ne "[+] Original Token: "
print_token $originalToken
echo -ne "[+] Modified Token: "
print_token $newToken

echo -e "==========="

echo -ne "[+] Validating certificate against certificate chain ...\n\t"
validate_certificate "$(getDirectoryPath leaf)/certificate.crt" "$(getDirectoryPath leaf)/ca-chain.crt"
echo -ne "[+] Validating original token against new certificate ...\n\t"
validate_token $originalToken "$(getDirectoryPath leaf)/certificate.crt"
echo -ne "[+] Validating modified token against new certificate ...\n\t"
validate_token $newToken "$(getDirectoryPath leaf)/certificate.crt"
echo -ne "[+] Validating modified token against new intermediate certificate ...\n\t"
validate_token $newToken "$(getDirectoryPath intermediate1)/certificate.crt"
