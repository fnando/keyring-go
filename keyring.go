package keyring

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type Keyring struct {
	DigestSalt string
	Keys       Keys
}

type EncryptedMessage struct {
	Encrypted string
	Digest    string
	KeyId     int
}

type Encryptor struct {
	KeySize     int
	Algorithm   string
	HasAuthData bool
}

var AES128CBC = Encryptor{
	KeySize:     16,
	Algorithm:   "AES-128-CBC",
	HasAuthData: false,
}

var AES192CBC = Encryptor{
	KeySize:     24,
	Algorithm:   "AES-192-CBC",
	HasAuthData: false,
}

var AES256CBC = Encryptor{
	KeySize:     32,
	Algorithm:   "AES-256-CBC",
	HasAuthData: false,
}

func sha1hex(message string) string {
	hash := sha1.New()
	hash.Write([]byte(message))

	return hex.EncodeToString(hash.Sum(nil))
}

func (keyring Keyring) Digest(message string) string {
	return sha1hex(message + keyring.DigestSalt)
}

func (keyring Keyring) Encrypt(message string) (EncryptedMessage, error) {
	currentKey, err := keyring.Keys.Current()

	if err != nil {
		return EncryptedMessage{}, err
	}

	encrypted, err := encrypt(currentKey, message)

	return EncryptedMessage{
		Digest:    keyring.Digest(message),
		KeyId:     currentKey.Id,
		Encrypted: encrypted,
	}, err
}

func (keyring Keyring) Decrypt(message string, keyId int) (string, error) {
	key, err := keyring.Keys.Get(keyId)

	if err != nil {
		return "", err
	}

	return decrypt(key, message)
}

func ParseKeys(jsonString string) (map[string]string, error) {
	keys := map[string]string{}
	err := json.Unmarshal([]byte(jsonString), &keys)
	return keys, err
}

func CreateKeyring(keyMap map[string]string, digestSalt string, encryptor Encryptor) (Keyring, error) {
	if len(keyMap) == 0 {
		return Keyring{}, fmt.Errorf("You must provide at least 1 key")
	}

	keys, err := PrepareKeys(keyMap, encryptor)

	if err != nil {
		return Keyring{}, err
	}

	return Keyring{DigestSalt: digestSalt, Keys: keys}, nil
}
