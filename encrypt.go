package gosalmon

import "strings"
import "crypto"
import "encoding/base64"
import "crypto/rand"
import "crypto/rsa"
import "crypto/sha1"
import "crypto/x509"
import "encoding/pem"


type Salmon struct {
  Payload string
  EncodedPayload string
  Datatype string
  Algorithm string
  Encoding string
  Signature string
  KeyId string
  RSAKey string
  MessageString string
}

func (self *Salmon) generateMessageString() {
  data_type := []byte(self.Datatype)
  encoding  := []byte(self.Encoding)
  algorithm := []byte(self.Algorithm)
  self.MessageString = self.EncodedPayload + 
                       "." + base64.URLEncoding.EncodeToString(data_type) +
                       "." + base64.URLEncoding.EncodeToString(encoding) +
                       "." + base64.URLEncoding.EncodeToString(algorithm)
}

// populate variables post initialize
func (self *Salmon) Encrypt() {
  // we expect to have:
  // Payload
  // Datatype
  // Algorithm
  // Encoding
  // RSAKey
  // 
  // we need to generate:
  // EncodedPayload
  // Signature

  data := []byte(self.Payload)
  self.EncodedPayload = base64.URLEncoding.EncodeToString(data)
  self.generateMessageString()

  p, _ := pem.Decode([]byte(self.RSAKey))
  if p == nil {
      panic("could not parse private key")
  }
  key, err := x509.ParsePKCS1PrivateKey(p.Bytes)
  h := sha1.New()
  sum := h.Sum(nil)
  sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum)
  if err != nil {
        panic("could not sign")
  }
  self.Signature = base64.URLEncoding.EncodeToString(sig)
}


// returns string of xml
func (self *Salmon) EncryptToXml() string {

  self.Encrypt()

  template := `<?xml version='1.0' encoding='UTF-8'?>
  <entry xmlns='http://www.w3.org/2005/Atom'>
   $encryption_header
    <me:env xmlns:me="http://salmon-protocol.org/ns/magic-env">
    <me:encoding>$encoding</me:encoding>
    <me:alg>$algo</me:alg>
    <me:data type="$datatype">$data</me:data>
    <me:sig>$sig</me:sig>
    </me:env>
  </entry>`

  template = strings.Replace(template, "$encryption_header", "", 1)
  template = strings.Replace(template, "$encoding", self.Encoding, 1)
  template = strings.Replace(template, "$algo", self.Algorithm, 1)
  template = strings.Replace(template, "$datatype", self.Datatype, 1)
  template = strings.Replace(template, "$data", self.EncodedPayload, 1)
  template = strings.Replace(template, "$sig", self.Signature, 1)

  return template
}

// populates self from xml
func (self *Salmon) DecryptFromXml(xml string) {
}
