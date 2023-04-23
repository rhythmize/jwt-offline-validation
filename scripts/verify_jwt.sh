#!/bin/bash

rootCname="root"
intermediateCnamePrefix="intermediate"
leafCname="leaf"
intermediateCaCount=-1

parse_args() {
	echo -ne "\033[0;31m"
	local options=$(getopt -u -l "root-cname::,intermediate-cname-prefix::,leaf-cname::,intermediate-ca-count:,help" -o '' -- "$@")
	echo -ne "\033[0m"

	set -- $options
	while true ; do
		case "$1" in
			--root-cname)
				rootCname="$2"; shift 2;;
			--intermediate-cname-prefix)
				intermediateCnamePrefix=$2; shift 2;;
			--leaf-cname)
				leafCname=$2; shift 2;;
			--intermediate-ca-count)
				intermediateCaCount=$2;
				shift 2;;
			--help)
				print_usage;
				exit 0;;
			--) 
				shift; break ;;
		esac
	done
}

print_usage() {
	echo -e "Usage:"
	echo -e "    verify_jwt.sh --intermediate-ca-count=<intermediate-ca-count> [--root-cname=<root-cname>] [--intermediate-cname-prefix=<intermediate-cname-prefix>] [--leaf-cname=<leaf-cname>"]
	echo -e "Options:"
	echo -e "    --help \t\t\t\tprint this usage"
	echo -e "    --intermediate-ca-count \t\tNumber of intermediate CAs in CA chain"
	echo -e "    --root-cname \t\t\tcname for root certificate [default: root]"
	echo -e "    --intermediate-cname-prefix \tcname prefix for intermediate certificate [default: intermediate]"
	echo -e "    --leaf-cname \t\t\tcname for leaf certificate [default: leaf]"
}

parse_args $@

if [ $intermediateCaCount -lt 0 ]; then
	print_usage
	echo -e '\n'
	exit "Invalid number of --intermediate-ca-count. Must be greater than 0"
fi

source ./token_helper.sh
source ./certificate_helper.sh

set -euo pipefail

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

publicKey="-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt7RHafy7vKDaHmeP83f4
W4npHfdwD9Y59pBbPxn3uX0vrTS8eBYkRI1tQqcsCfMa+KIz6aLoGPhL0IYFRsj0
4882pv2MQTKdBWICGsTyzXws554RF/MLoGc5HFdqvhtXAsnSQRMk5/4sn4XcvRTt
rt0klrKgfFQ0dpTTz9wTBYVmw5Ln4ccw5szHPeQHJOBpxY/0zoLqFxjVpgfOmEks
LzX+uxMgUIj6A5iAW9St5ioHHIlrrU6PlcRKx/Z9FpD4rsXXH14FADq05x9RC7II
GGeoAM6qNK8CiuCgnMaPbTw9Lpqs6oOT2/OzkLE+ksiZuxNfh50qBrhrl5JnWkTH
rhkh5GsQmr3YEYIQxUi8H3Q7Q5qkxpmLp5I/MfUGGhfyeHqdMKdn0mPD9QQbVI9C
PEOR/KnD7U/LiEktEgTcBLeuWz+T+tih9zK+Fvc5sgC8QmpSVRMyWPOu9O+yCopQ
+T5ggrCVidDbMaLAW2uFH3BgiNWbgGKSli71SVJr40kPkN7EVhZX8jeNtirGFhDX
0V9n90qtcEIEIEXZnW/LSgImKWnaDjXlkCQajdXjBwXNli6lto+if1Wz9T0ueZfH
rkKWk/mIeTQ6vg1RmgTcEcJgYLbUb+vHBWlUxxQ9tgDfjv5/4+M76j0HXy1q7d/u
nuPEa5QVdyk85YJFN2THfqUCAwEAAQ==
-----END PUBLIC KEY-----"


echo -e "[+] Cleaning up old certs, if any ..."
rm -rf scenarios/*
mkdir -p scenarios
# push public key to a file
echo "$publicKey" > $(getDirectoryPath original_public_key.pem)

echo -e "[+] Create new RSA keys and certificates ..."
create_certificate_chain $intermediateCaCount $rootCname $intermediateCnamePrefix $leafCname

echo -e "[+] Modifying the original token ..."
newToken=$(modify_token $originalToken $(getDirectoryPath leaf)/private.pem)
# Write modified token to file
echo -n $newToken > $(getDirectoryPath "updated_token")

echo -ne "[+] Original Token: "
print_token $originalToken
echo -ne "[+] Modified Token: "
print_token $newToken

echo -e "==========="

echo -e "\n[+] Validating original token against original public key ..."
validate_token $originalToken "$(getDirectoryPath original_public_key.pem)"
echo -e "\n[+] Validating original token against new certificate ..."
validate_token $originalToken "$(getDirectoryPath leaf)/certificate.crt"
echo -e "\n[+] Validating certificate against certificate chain ..."
validate_certificate "$(getDirectoryPath leaf)/root_certificate.crt" "$(getDirectoryPath leaf)/ca-chain.crt" "$(getDirectoryPath leaf)/certificate.crt"
echo -e "\n[+] Validating modified token against original public key ..."
validate_token $newToken "$(getDirectoryPath original_public_key.pem)"
echo -e "\n[+] Validating modified token against new certificate ..."
validate_token $newToken "$(getDirectoryPath leaf)/certificate.crt"
echo -e "\n[+] Validating modified token against new intermediate certificate ..."
validate_token $newToken "$(getDirectoryPath intermediate1)/certificate.crt"
