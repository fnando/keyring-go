package keyring

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRejectEmptyKeys(t *testing.T) {
	keys := map[string]string{}
	_, err := CreateKeyring(keys, "", AES128CBC)

	assert.Error(t, err)
	assert.Equal(t, "You must provide at least 1 key", err.Error())
}

func TestRejectKeysWithInvalidSize(t *testing.T) {
	keys := map[string]string{"0": "ud3UH9tBzHKTaQ=="}
	_, err := CreateKeyring(keys, "", AES128CBC)

	assert.Error(t, err)
	assert.Equal(t, "Expected key with 32 bytes, got 10 bytes", err.Error())
}

func TestReturnDigestWhenEncrypting(t *testing.T) {
	keys := map[string]string{"0": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M="}
	keyring, err := CreateKeyring(keys, "", AES128CBC)

	assert.NoError(t, err)

	encrypted, err := keyring.Encrypt("42")

	assert.NoError(t, err)
	assert.Equal(t, "92cfceb39d57d914ed8b14d0e37643de0797ae56", encrypted.Digest)

	keyring.Keys.Add(1, "VN8UXRVMNbIh9FWEFVde0q7GUA1SGOie1+FgAKlNYHc=")

	encrypted, err = keyring.Encrypt("37")

	assert.NoError(t, err)
	assert.Equal(t, "cb7a1d775e800fd1ee4049f7dca9e041eb9ba083", encrypted.Digest)
}

func TestReturnDigestWithCustomSalt(t *testing.T) {
	keys := map[string]string{"0": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M="}
	keyring, err := CreateKeyring(keys, "a", AES128CBC)

	assert.NoError(t, err)

	encrypted, err := keyring.Encrypt("42")

	assert.NoError(t, err)
	assert.Equal(t, "118c884d37dde5fb6816daba052d94e82f1dc41f", encrypted.Digest)

	keyring.Keys.Add(1, "VN8UXRVMNbIh9FWEFVde0q7GUA1SGOie1+FgAKlNYHc=")

	encrypted, err = keyring.Encrypt("37")

	assert.NoError(t, err)
	assert.Equal(t, "339306c56026a22fdd522116973cde9a8205370e", encrypted.Digest)
}

func TestReturnDigest(t *testing.T) {
	keys := map[string]string{"0": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M="}
	keyring, err := CreateKeyring(keys, "a", AES128CBC)

	assert.NoError(t, err)
	assert.Equal(t, "118c884d37dde5fb6816daba052d94e82f1dc41f", keyring.Digest("42"))

	assert.NoError(t, err)
	assert.Equal(t, "339306c56026a22fdd522116973cde9a8205370e", keyring.Digest("37"))
}

func TestReturnKeyringIdWhenEncrypting(t *testing.T) {
	keys := map[string]string{"0": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M="}
	keyring, err := CreateKeyring(keys, "a", AES128CBC)

	assert.NoError(t, err)

	encrypted, err := keyring.Encrypt("42")

	assert.NoError(t, err)
	assert.Equal(t, 0, encrypted.KeyId)

	keyring.Keys.Add(1, "VN8UXRVMNbIh9FWEFVde0q7GUA1SGOie1+FgAKlNYHc=")

	encrypted, err = keyring.Encrypt("42")

	assert.NoError(t, err)
	assert.Equal(t, 1, encrypted.KeyId)
}

func TestRotateKey(t *testing.T) {
	keys := map[string]string{"0": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M="}
	keyring, err := CreateKeyring(keys, "", AES128CBC)

	assert.NoError(t, err)

	encrypted, err := keyring.Encrypt("42")
	assert.NoError(t, err)

	decrypted, err := keyring.Decrypt(encrypted.Encrypted, encrypted.KeyId)
	assert.NoError(t, err)

	assert.Equal(t, 0, encrypted.KeyId)
	assert.Equal(t, "42", decrypted)

	keyring.Keys.Add(1, "VN8UXRVMNbIh9FWEFVde0q7GUA1SGOie1+FgAKlNYHc=")

	encrypted, err = keyring.Encrypt("42")
	assert.NoError(t, err)

	decrypted, err = keyring.Decrypt(encrypted.Encrypted, encrypted.KeyId)
	assert.NoError(t, err)

	assert.Equal(t, 1, encrypted.KeyId)
	assert.Equal(t, "42", decrypted)
}

func TestWithJSONKeyring(t *testing.T) {
	keys, err := ParseKeys(`
		{
		  "1": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M=",
		  "2": "VN8UXRVMNbIh9FWEFVde0q7GUA1SGOie1+FgAKlNYHc="
		}
	`)
	assert.NoError(t, err)

	keyring, err := CreateKeyring(keys, "", AES128CBC)
	assert.NoError(t, err)

	encrypted, err := keyring.Encrypt("42")
	assert.NoError(t, err)
	assert.Equal(t, 2, encrypted.KeyId)

	decrypted, err := keyring.Decrypt(encrypted.Encrypted, encrypted.KeyId)

	assert.NoError(t, err)
	assert.Equal(t, "42", decrypted)
}

func TestEncryptUsingAES128CBC(t *testing.T) {
	keys := map[string]string{"0": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M="}
	keyring, err := CreateKeyring(keys, "", AES128CBC)

	assert.NoError(t, err)

	encrypted, err := keyring.Encrypt("42")
	decrypted, err := keyring.Decrypt(encrypted.Encrypted, encrypted.KeyId)

	assert.NoError(t, err)
	assert.Equal(t, "42", decrypted)
}

func TestEncryptUsingAES192CBC(t *testing.T) {
	keys := map[string]string{"0": "wtnnoK+5an+FPtxnkdUDrNw6fAq8yMkvCvzWpriLL9TQTR2WC/k+XPahYFPvCemG"}
	keyring, err := CreateKeyring(keys, "", AES192CBC)

	assert.NoError(t, err)

	encrypted, err := keyring.Encrypt("42")
	decrypted, err := keyring.Decrypt(encrypted.Encrypted, encrypted.KeyId)

	assert.NoError(t, err)
	assert.Equal(t, "42", decrypted)
}

func TestEncryptUsingAES256CBC(t *testing.T) {
	keys := map[string]string{"0": "XZXC+c7VUVGpyAceSUCOBbrp2fjJeeHwoaMQefgSCfp0/HABY5yJ7zRiLZbDlDZ7HytCRsvP4CxXt5hUqtx9Uw=="}
	keyring, err := CreateKeyring(keys, "", AES256CBC)

	assert.NoError(t, err)

	encrypted, err := keyring.Encrypt("42")
	decrypted, err := keyring.Decrypt(encrypted.Encrypted, encrypted.KeyId)

	assert.NoError(t, err)
	assert.Equal(t, "42", decrypted)
}
