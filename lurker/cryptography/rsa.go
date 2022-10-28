package cryptography

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"lurker/lurker/constants"
)

func RsaEncrypt(origData []byte) ([]byte, error) {

	block, _ := pem.Decode(constants.RsaPublicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

func RsaDecrypt(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(constants.RsaPublicKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv := privInterface.(*rsa.PrivateKey)
	return rsa.DecryptPKCS1v15(rand.Reader, priv, origData)
}
