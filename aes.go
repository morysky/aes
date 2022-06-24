package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Sha256Key sha256 加密
func Sha256Key(key string) []byte {
	h := sha256.New()
	h.Write([]byte(key))
	newKey := h.Sum(nil)
	return newKey
}

// PKCS7Padding 填充数据
func PKCS7Padding(ciphertext []byte) []byte {
	bs := aes.BlockSize
	padding := bs - len(ciphertext)%bs
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, paddingText...)
}

// PKCS5Padding ...
func PKCS5Padding(ciphertext []byte) []byte {
	bs := 8
	padding := bs - len(ciphertext)%bs
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, paddingText...)
}

// PKCS7UnPadding 放出数据
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}

// Encrypt 加密
func Encrypt(origData, key string) (string, error) {
	newKey := Sha256Key(key)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return "", err
	}
	newOrigData := []byte(origData)
	newOrigData = PKCS7Padding(newOrigData)
	blockMode := cipher.NewCBCEncrypter(block, newKey[:16])
	crypted := make([]byte, len(newOrigData))
	blockMode.CryptBlocks(crypted, newOrigData)
	return base64.StdEncoding.EncodeToString(crypted), nil
}

// EncryptWithPKCS5Padding ...
func EncryptWithPKCS5Padding(origData, key string) (string, error) {
	newKey := Sha256Key(key)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return "", err
	}
	newOrigData := []byte(origData)
	newOrigData = PKCS5Padding(newOrigData)
	blockMode := cipher.NewCBCEncrypter(block, newKey[:8])
	crypted := make([]byte, len(newOrigData))
	blockMode.CryptBlocks(crypted, newOrigData)
	return base64.StdEncoding.EncodeToString(crypted), nil
}

// Decrypt 解密
func Decrypt(crypted, key string) (string, error) {
	newKey := Sha256Key(key)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return "", err
	}
	newCrypted, _ := base64.StdEncoding.DecodeString(crypted)
	blockMode := cipher.NewCBCDecrypter(block, newKey[:16])
	origData := make([]byte, len(newCrypted))

	err = checkBlocks(origData, newCrypted, block.BlockSize())
	if err != nil {
		return "", err
	}

	blockMode.CryptBlocks(origData, newCrypted)
	origData = PKCS7UnPadding(origData)
	return string(origData), nil
}

func checkBlocks(dst, src []byte, blockSize int) error {
	if len(src)%blockSize != 0 {
		return fmt.Errorf("crypto/cipher: input not full blocks")
	}

	if len(dst) < len(src) {
		return fmt.Errorf("crypto/cipher: output smaller than input")
	}

	// @FIXME
	/*
		if subtle.InexactOverlap(dst[:len(src)], src) {
			return fmt.Errorf("crypto/cipher: invalid buffer overlap")
		}
	*/

	return nil
}
