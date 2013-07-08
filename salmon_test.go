package gosalmon

import "testing"

func TestEncodeToXml(t *testing.T) {
  salmon := Salmon{
    Payload: "onaboatasdfihadsofa8afoihafdaeoihafkhasdfpojadfg09ygraouhsdfoasf8awer90uafr!#qeriohafklafilarf90u4r902asdofha89248hf8haoijafuhasfdasdfoasdfonaboat",
    Datatype: "application/atom+xml",
    Algorithm: "RSA-SHA256",
    Encoding: "base64url",
    RSAKey: `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQChn85X/ysbMlnnuQaXHDwfWTmA0CMs5LJdzYVtRgT4Ua9djNGb
gIS3xoVrw0XCjDyKy+3/sOzYFnADxrPSSJYhT159OiEbBA0y8XHNygkdt/e3o32J
BOAnRWjQqBgcwzrTCCPvm6Wne9PzHRnm53mMZqu9p20UsuOoSAZa/QBfMwIDAQAB
AoGARaYqM72gg93U5IjVkDT4q8G1iA8puWTsgIPapdZwudnpqnTOtyZRCykfweqq
m0X3qRBsha1mw1AYAWiVgV8KYq0O+cXUlWu0QnLvPJbty83OdPfcM69FVmOx6hj4
NFo19KeibdMMubiJOdmNEukS1r6VpmP9xt01eHDAMo7q5uECQQDOEAuZor4agRcO
I8Y6phdEHOmxob9y8+wkc3hUcaC9feNXWCz8OYLvxr18TpAQ0akdZ8YkT9iEN1+h
rRw+fmUZAkEAyMrWdAm6QYxqbh8iUSocjjGeC4TFrVMZIKEZ78+gGG0f3PdwH0yz
Ngn1/PjWwW3SfF4eQdR+YW5k+8RNotkEKwJAD0i3Y4zjptmeWSkkIeOB5EZ0uv0x
UxhukoGSEklfT87PlwHuTEMDyD8ofNji7Kxwa8Lvum/FsoDc8gQCDUyYuQJAekqn
wHaoPQHzVGyb7wkR6TypAGT2LHE/DZNxA5DV9eqIjIEbhcSmJZR9gHxh998WYm7E
SN3NtzOQR5Kwoi1AjwJAeb7rA4deTmr1yjLSQcMqCRgGV1ywOAlIJ6LdoOh31FMN
M0giz6s+HWVKgB3jmmXbvNqfvViYNqtK8XVibOL5fQ==
-----END RSA PRIVATE KEY-----`,
  }
  xml := salmon.EncodeToXml(false)
  if len(xml) == 0 {
    t.Errorf("could not generate xml")
  }
}

func TestDecode(t *testing.T) {
  salmon := Salmon{
    EncodedPayload: "b25hYm9hdGFzZGZpaGFkc29mYThhZm9paGFmZGFlb2loYWZraGFzZGZwb2phZGZnMDl5Z3Jhb3Voc2Rmb2FzZjhhd2VyOTB1YWZyISNxZXJpb2hhZmtsYWZpbGFyZjkwdTRyOTAyYXNkb2ZoYTg5MjQ4aGY4aGFvaWphZnVoYXNmZGFzZGZvYXNkZm9uYWJvYXQ=",
    Signature: "O4CxIjOL4RtKsm2N5OxnHJu8Z9akGdvyhMrhkZpQyfNkRGqE0Ol90n6a0LsYHk6gVTX4f2C_vAxteifUpxFXxGLeXEspHx34JdubdThOrweB7qxVlOzzZyoz4dCYpPXwhfCT1el7QqoiBnhxOqvItcXEowszm9wNHpZWIRQKFYk=",
    Datatype: "application/atom+xml",
    Algorithm: "RSA-SHA256",
    Encoding: "base64url",
    RSAPubKey: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChn85X/ysbMlnnuQaXHDwfWTmA
0CMs5LJdzYVtRgT4Ua9djNGbgIS3xoVrw0XCjDyKy+3/sOzYFnADxrPSSJYhT159
OiEbBA0y8XHNygkdt/e3o32JBOAnRWjQqBgcwzrTCCPvm6Wne9PzHRnm53mMZqu9
p20UsuOoSAZa/QBfMwIDAQAB
-----END PUBLIC KEY-----`,
  }
  salmon.Decode()

  if salmon.IsValid() == false {
    t.Errorf("salmon was not verified")
  }

  if salmon.Payload != "onaboatasdfihadsofa8afoihafdaeoihafkhasdfpojadfg09ygraouhsdfoasf8awer90uafr!#qeriohafklafilarf90u4r902asdofha89248hf8haoijafuhasfdasdfoasdfonaboat" {
    t.Errorf("salmon payload was wrong")
  }

}
