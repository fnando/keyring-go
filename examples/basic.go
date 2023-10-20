package main

import (
	"fmt"

	k "github.com/fnando/keyring-go"
)

func main() {
	keyring, err := k.CreateKeyring(
		map[string]string{"1": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M="},
		"<custom salt>",
		k.AES128CBC,
	)

	if err != nil {
		panic(err)
	}

	// STEP 1: Encrypt message using latest encryption key.
	encrypted, err := keyring.Encrypt("super secret")

	if err != nil {
		panic(err)
	}

	fmt.Println("🔒", encrypted.Encrypted)
	fmt.Println("🔑", encrypted.KeyId)
	fmt.Println("🔎", encrypted.Digest)

	// STEP 2: Decrypted message using encryption key defined by keyring id.
	decrypted, err := keyring.Decrypt(encrypted.Encrypted, encrypted.KeyId)

	if err != nil {
		panic(err)
	}

	fmt.Println("✉️ ", decrypted)
}
