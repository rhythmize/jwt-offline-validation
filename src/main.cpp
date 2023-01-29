#include <iostream>
#include <JwtTokenHelper.h>
#include <Runner.h>

int main(int argc, char *argv[])
{
    std::string jwtToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkE3NHBUeDlIMDdMd1kyaGFrZVdPS0ZOZTNtaDhaNjZ3ZlFnQUhyME5"
        "OLUEifQ.eyJpc3MiOiJodHRwczovL2lkLm9wZW5za2llcy5zaC8iLCJleHAiOjE2NDAwMjQzMjIsImlhdCI6MTY0MDAyMDcyMiwic3ViIjoiZzM3bFhpZk"
        "FRb0JmVnVRWnhUM1ZKRmpYSU1nZGZYSU9wYTJMZFdCUUBjbGllbnRzIiwic2NvcGUiOiIiLCJ0eXAiOiJCZWFyZXIiLCJmbGlnaHRfcGxhbl9pZCI6IjEy"
        "ODE4ZTg3LTRjOTYtNGU0Yy04YzYzLTgyYjhlMTJjM2I3MyIsImZsaWdodF9vcGVyYXRpb25faWQiOiIzNDA4YmNlOS1kYmFiLTQ2NjUtYWJmYy04ZWEwM2"
        "IwYWQ4NzEiLCJwbGFuX2ZpbGVfaGFzaCI6ImEyYTIwMWVmYTExMWRkZTVhYWE4ZjQyYjdiNDZkMTdiNTk1ZTM5ZDg1MDUwMGRiYWNkOWY3OWFlZjBiYmY2"
        "OGUifQ.N9I9aPtlvuv8zYiNWEJwfZF8cR0mxh3vP7hda0Q8jbntfaQtM_hOPoAoywGGH9mAGDUZYpVk1BfC_HxwHEVolqtVFemLqKw_NpmA-nciw5ovmJZ"
        "9ermfzuDvLFSSSkf-9H2RQm30a8UFsq_K7q8HZjuda325-AhmzHgKk2QSPUdEiHN0Nm-XhtsZ5KxJzekTT0j7HmR7Siynrc5hi_iYBxWRufSop-1hlMjpr"
        "LcdVZsvVOoIjrby7Wjl0lA0vdl_-AovLnYaAKfOU-UoQoUvTUsRrkpFEYjwc5wHyGzXB63HSKBx0e31w4NXMHHoWueYs2C0lObvj6V2wxOPX8oBz-ks2yk"
        "hzLadkFnbaea6tr2Sv46UCsLrXVoDDn60M9eqAW1USCOQJD5ClUDmpZ097CznYbiQu9ErbJLTsB40L5WfEimyrLTynW9_PsWK2KAh5nUTvcCbBX21y3noo"
        "IQOghceGKK9EjwyN2MSs_9blxnrcgDOuGBjg04r7CsMy0rV3iTGpGBJRtB78nwov28InMlpReoTXSwHAEW1nuGccU1L2mVprkj33PMnjSBlhkljhH_1fvL"
        "Xw-rE12fu9L5x6XhR_laoaTF-Ncb0bwtxIzixgaFDdMYzJpgEr03POtQZYWaCRiQvIZYHt51uFbvWKbFm1OXifSe0G-Un9HnMHLg";
    
    std::string publicKey = "-----BEGIN PUBLIC KEY-----\n"
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt7RHafy7vKDaHmeP83f4\n"
        "W4npHfdwD9Y59pBbPxn3uX0vrTS8eBYkRI1tQqcsCfMa+KIz6aLoGPhL0IYFRsj0\n"
        "4882pv2MQTKdBWICGsTyzXws554RF/MLoGc5HFdqvhtXAsnSQRMk5/4sn4XcvRTt\n"
        "rt0klrKgfFQ0dpTTz9wTBYVmw5Ln4ccw5szHPeQHJOBpxY/0zoLqFxjVpgfOmEks\n"
        "LzX+uxMgUIj6A5iAW9St5ioHHIlrrU6PlcRKx/Z9FpD4rsXXH14FADq05x9RC7II\n"
        "GGeoAM6qNK8CiuCgnMaPbTw9Lpqs6oOT2/OzkLE+ksiZuxNfh50qBrhrl5JnWkTH\n"
        "rhkh5GsQmr3YEYIQxUi8H3Q7Q5qkxpmLp5I/MfUGGhfyeHqdMKdn0mPD9QQbVI9C\n"
        "PEOR/KnD7U/LiEktEgTcBLeuWz+T+tih9zK+Fvc5sgC8QmpSVRMyWPOu9O+yCopQ\n"
        "+T5ggrCVidDbMaLAW2uFH3BgiNWbgGKSli71SVJr40kPkN7EVhZX8jeNtirGFhDX\n"
        "0V9n90qtcEIEIEXZnW/LSgImKWnaDjXlkCQajdXjBwXNli6lto+if1Wz9T0ueZfH\n"
        "rkKWk/mIeTQ6vg1RmgTcEcJgYLbUb+vHBWlUxxQ9tgDfjv5/4+M76j0HXy1q7d/u\n"
        "nuPEa5QVdyk85YJFN2THfqUCAwEAAQ==\n"
        "-----END PUBLIC KEY-----";

    Runner::ValidateOriginalToken(jwtToken, publicKey);
    std::cout << "=========================================================\n\n";
 
    auto newTokenBuilder = JwtTokenHelper::GetModifiedTokenBuilder(jwtToken);
    
    Runner::ValidateWithInMemoryKeys(newTokenBuilder);
    std::cout << "=========================================================\n\n";

    Runner::ValidateWithInMemoryCert(newTokenBuilder);
    std::cout << "=========================================================\n\n";

    Runner::ValidateWithInMemoryRootCert(newTokenBuilder);
    std::cout << "=========================================================\n\n";

    Runner::ValidateWithInMemoryIntermediateCert(newTokenBuilder);
    std::cout << "=========================================================\n\n";
}
