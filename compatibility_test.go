package keyring

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Values used in this example are taken from
// https://github.com/fnando/attr_keyring/blob/main/test/data.json

func TestCaseAES128CBC(t *testing.T) {
	keys := map[string]string{"1": "7K0xBRrumkPm03UKS3g4MFm2gGCrFCa3eXnBWigOdlM="}
	keyring, err := CreateKeyring(keys, "", AES128CBC)

	assert.Nil(t, err)

	encrypted, err := keyring.Encrypt("42")
	assert.Nil(t, err)
	assert.Equal(t, 1, encrypted.KeyId)
	assert.Equal(t, "92cfceb39d57d914ed8b14d0e37643de0797ae56", encrypted.Digest)

	decrypted, err := keyring.Decrypt("UUXMN2NmF8703gNMawcecwgdfQRPUpXBWyGnlklwmGCU/oMKKQa9C41CyXiF6jT806GmZrM+Zql5QSYBy5H18A==", encrypted.KeyId)
	assert.Nil(t, err)
	assert.Equal(t, "42", decrypted)
}

func TestCaseAES192CBC(t *testing.T) {
	keys := map[string]string{"1": "GTZL7ZjUG/PQ8kzF/8BardfieeYaWOVaiXvOagLA2LLvWqlkuK7H03eJ1OTFhfX6"}
	keyring, err := CreateKeyring(keys, "", AES192CBC)

	assert.Nil(t, err)

	encrypted, err := keyring.Encrypt("42")
	assert.Nil(t, err)
	assert.Equal(t, 1, encrypted.KeyId)
	assert.Equal(t, "92cfceb39d57d914ed8b14d0e37643de0797ae56", encrypted.Digest)

	decrypted, err := keyring.Decrypt("AqX3KKkD3dXOAFcyFHX5FQkFIZnwiuX/Cf3WbOH4t86vyxvxJ2pEGCuy6QKZtyESifPV8NxljEfWkUVT4c+94g==", encrypted.KeyId)
	assert.Nil(t, err)
	assert.Equal(t, "42", decrypted)
}

func TestCaseAES256CBC(t *testing.T) {
	keys := map[string]string{"1": "QTCR5qqiKPouS10H9W7Vhv+nfgM5OHSW20XRga7NrOpEZb32mTNU/4u1753m0eEmQQR+a4xL6/kv6c5DitcUnA=="}
	keyring, err := CreateKeyring(keys, "", AES256CBC)

	assert.Nil(t, err)

	encrypted, err := keyring.Encrypt("42")
	assert.Nil(t, err)
	assert.Equal(t, 1, encrypted.KeyId)
	assert.Equal(t, "92cfceb39d57d914ed8b14d0e37643de0797ae56", encrypted.Digest)

	decrypted, err := keyring.Decrypt("ozcXFOTy2NFLtnfEjXsvcOSJ+1+bXHM/ZOI8aK4tBL0mjnme5FoHn1pKInCaoDRyKvs6uZ3j7aq8fbSsV62v1w==", encrypted.KeyId)
	assert.Nil(t, err)
	assert.Equal(t, "42", decrypted)
}
