package gosalmon

import "strings"
import "crypto"
import "encoding/base64"
import "crypto/rand"
import "crypto/rsa"
import "crypto/sha1"
import "crypto/x509"
import "encoding/pem"
import "io"


type Salmon struct {
  Payload string
  EncodedPayload string
  Datatype string
  Algorithm string
  Encoding string
  Signature string
  KeyId string
  RSAKey string
  RSAPub string
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
func (self *Salmon) Encode() {
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
  io.WriteString(h, self.MessageString)
  sum := h.Sum(nil)

  sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum)
  if err != nil {
    panic("could not sign")
  }
  self.Signature = base64.URLEncoding.EncodeToString(sig)
}

// return xml representation of self
func (self *Salmon) EncodeToXml() string {
  self.Encode()

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

  // XXX: is there a more efficient way?
  // XXX: encryption header is for diaspora
  template = strings.Replace(template, "$encryption_header", "", 1)
  template = strings.Replace(template, "$encoding", self.Encoding, 1)
  template = strings.Replace(template, "$algo", self.Algorithm, 1)
  template = strings.Replace(template, "$datatype", self.Datatype, 1)
  template = strings.Replace(template, "$data", self.EncodedPayload, 1)
  template = strings.Replace(template, "$sig", self.Signature, 1)

  return template
}

// returns json representation of self
func (self *Salmon) EncodeToJson() string {
  // XXX: todo
  return "{'todo':true}"
}

func (self *Salmon) Decode() {
  res, err := base64.URLEncoding.DecodeString(self.EncodedPayload)
  if(err != nil) {
    panic(err)
  }
  self.Payload = string(res)
}

// populates self from xml
func (self *Salmon) DecodeFromXml(xml string) {
  // XXX: todo
}

// populates self from json
func (self *Salmon) DecodeFromJson(xml string) {
  // XXX: todo
}

// is this salmon envelope valid?
// this assumes you have populated
// RSAPub with the pubkey
func (self *Salmon) IsValid() bool {
  self.generateMessageString()

  p, _ := pem.Decode([]byte(self.RSAPub))
  if p == nil {
    panic("could not parse public key")
  }
  key, err := x509.ParsePKIXPublicKey(p.Bytes)
  if(err != nil) {
    panic("could not parse public key")
  }

  res, erra := base64.URLEncoding.DecodeString(self.Signature)
  if(erra != nil) {
    panic(erra)
  }

  h := sha1.New()
  io.WriteString(h, self.MessageString)
  sum := h.Sum(nil)

  errb := rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA1, sum, res) 
  if(errb == nil) {
    return true
  }

  return false
}
