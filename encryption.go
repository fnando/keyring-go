package keyring

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func pkcs5Padding(message []byte, blockSize int) []byte {
	padding := blockSize - len(message)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(message, padtext...)
}

func pkcs5Trimming(encrypted []byte) []byte {
	padding := encrypted[len(encrypted)-1]
	return encrypted[:len(encrypted)-int(padding)]
}

func encrypt(key Key, message string) (string, error) {
	block, err := aes.NewCipher(key.EncryptionKey)

	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)

	if err != nil {
		return "", err
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)
	content := pkcs5Padding([]byte(message), block.BlockSize())

	encrypted := make([]byte, len(content))
	encrypter.CryptBlocks(encrypted, content)

	mac := hmac.New(sha256.New, key.SigningKey)
	mac.Write(append(iv, encrypted...))
	macBytes := mac.Sum(nil)

	envelope := append([]byte{}, macBytes...)
	envelope = append(envelope, iv...)
	envelope = append(envelope, encrypted...)

	return base64.StdEncoding.EncodeToString(envelope), nil
}

func decrypt(key Key, encryptedMessage string) (string, error) {
	block, err := aes.NewCipher(key.EncryptionKey)

	if err != nil {
		return "", err
	}

	envelope, err := base64.StdEncoding.DecodeString(encryptedMessage)

	if err != nil {
		return "", err
	}

	informedMac := envelope[:32]
	informedIV := envelope[32 : 32+aes.BlockSize]
	encrypted := envelope[32+aes.BlockSize:]

	mac := hmac.New(sha256.New, key.SigningKey)
	mac.Write(append(informedIV, encrypted...))
	macBytes := mac.Sum(nil)

	if !hmac.Equal(macBytes, informedMac) {
		return "", fmt.Errorf("HMAC couldn't be verified")
	}

	decrypted := make([]byte, len(encrypted))
	decrypter := cipher.NewCBCDecrypter(block, informedIV)
	decrypter.CryptBlocks(decrypted, encrypted)

	return string(pkcs5Trimming(decrypted)), nil
}
