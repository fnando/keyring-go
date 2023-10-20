package keyring

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type Keys struct {
	Encryptor Encryptor
	all       map[int]Key
}

type Key struct {
	Id            int
	Encoded       string
	SigningKey    []byte
	EncryptionKey []byte
	Size          int
}

func (keys Keys) Current() (Key, error) {
	id := slices.Max(maps.Keys(keys.all))

	return keys.Get(id)
}

func (keys Keys) Get(id int) (Key, error) {
	key, exists := keys.all[id]

	if exists {
		return key, nil
	}

	return key, fmt.Errorf("Key with id=%d doesn't exist", id)
}

func (keys Keys) Add(id int, encodedKey string) error {
	secret := make([]byte, keys.Encryptor.KeySize*2)
	_, err := base64.StdEncoding.Decode(secret, []byte(encodedKey))

	if err != nil {
		return err
	}

	secret = bytes.Trim(secret, "\x00")
	actualLen := len(secret)
	expectedLen := keys.Encryptor.KeySize * 2

	if actualLen != expectedLen {
		return fmt.Errorf(
			"Expected key with %d bytes, got %d bytes",
			expectedLen,
			actualLen,
		)
	}

	key := Key{
		Id:            id,
		Encoded:       encodedKey,
		SigningKey:    secret[0:keys.Encryptor.KeySize],
		EncryptionKey: secret[keys.Encryptor.KeySize:],
		Size:          keys.Encryptor.KeySize,
	}

	keys.all[id] = key

	return nil
}

func PrepareKeys(keyMap map[string]string, encryptor Encryptor) (Keys, error) {
	keys := Keys{Encryptor: encryptor, all: make(map[int]Key)}

	for id, encodedKey := range keyMap {
		idInt, _ := strconv.Atoi(id)
		err := keys.Add(idInt, encodedKey)

		if err != nil {
			return keys, err
		}
	}

	return keys, nil
}
