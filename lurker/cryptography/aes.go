package cryptography

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"lurker/lurker/constants"
)

const HmacHashLen = 16

func PKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padBytes := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padBytes...)
}

func PKCS7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding < 1 || padding > 16 || padding > len(data) {
		return data
	}
	for i := 0; i < padding; i++ {
		if data[len(data)-1-i] != byte(padding) {
			return data
		}
	}
	return data[:len(data)-padding]
}

func AesCBCEncrypt(rawData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	rawData = PKCS7Pad(rawData, blockSize)
	cipherText := make([]byte, blockSize+len(rawData))
	mode := cipher.NewCBCEncrypter(block, constants.IV)
	mode.CryptBlocks(cipherText[blockSize:], rawData)
	return cipherText, nil
}

func AesCBCDecrypt(encryptData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(encryptData) < blockSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(encryptData))
	}
	if len(encryptData)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext not a multiple of block size: %d bytes", len(encryptData))
	}
	mode := cipher.NewCBCDecrypter(block, constants.IV)
	mode.CryptBlocks(encryptData, encryptData)
	encryptData = PKCS7Unpad(encryptData)
	return encryptData, nil
}

func HmacHash(encrytedBytes []byte) []byte {
	hmacEntry := hmac.New(sha256.New, constants.HmacKey)
	hmacEntry.Write(encrytedBytes)
	return hmacEntry.Sum(nil)[:16]
}
