<p align="center">
  <img src="https://raw.githubusercontent.com/fnando/keyring/main/keyring.svg" alt="keyring: Simple encryption-at-rest with key rotation support for golang.">
</p>

<p align="center">
  <a href="https://github.com/fnando/keyring-go/actions?query=workflow%3ATests"><img src="https://github.com/fnando/keyring-go/workflows/Tests/badge.svg" alt="Tests"></a>
</p>

N.B.: keyring is not for encrypting passwords--for that, you should use
something like [bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt). It's
meant for encrypting sensitive data you will need to access in plain text (e.g.
storing OAuth token from users). Passwords do not fall in that category.

This library is heavily inspired by
[attr_vault](https://github.com/uhoh-itsmaciek/attr_vault), and can read
encrypted messages if you encode them in base64 (e.g.
`Base64.strict_encode64(encrypted_by_attr_vault)`).

## Installation

Add this line to your application:

```bash
go get github.com/fnando/keyring-go
```

## Usage

### Basic usage

```go
package main

import (
  "fmt"

  k "github.com/fnando/keyring-go"
)

func main() {
  keyring, err := k.CreateKeyring(
    map[string]string{"1": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M="},
    "<custom digest salt>",
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
```

#### Change encryption algorithm

You can choose between `AES-128-CBC`, `AES-192-CBC` and `AES-256-CBC`. By
default, `AES-128-CBC` will be used.

To specify the encryption algorithm, set the `encryption` option. The following
example uses `AES-256-CBC`.

```go
keyring := k.Create(
  map[string]string{"1": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M="},
  k.AES256CBC,
  "<custom digest salt>",
)
```

### Configuration

As far as database schema goes:

1. You'll need a column to track the key that was used for encryption, like
   `keyring_id`.
2. Every encrypted column can be named `encrypted_<column name>`.
3. Optionally, you can also have a `<column name>_digest` to help with searching
   (see Lookup section below).

### Encryption

By default, AES-128-CBC is the algorithm used for encryption. This algorithm
uses 16 bytes keys, but you're required to use a key that's double the size
because half of that keys will be used to generate the HMAC. The first 16 bytes
will be used as the encryption key, and the last 16 bytes will be used to
generate the HMAC.

Using random data base64-encoded is the recommended way. You can easily generate
keys by using the following command:

```console
$ dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64 -A
qUjOJFgZsZbTICsN0TMkKqUvSgObYxnkHDsazTqE5tM=
```

Include the result of this command in the `value` section of the key description
in the keyring. Half this key is used for encryption, and half for the HMAC.

#### Key size

The key size depends on the algorithm being used. The key size should be double
the size as half of it is used for HMAC computation.

- `aes-128-cbc`: 16 bytes (encryption) + 16 bytes (HMAC).
- `aes-192-cbc`: 24 bytes (encryption) + 24 bytes (HMAC).
- `aes-256-cbc`: 32 bytes (encryption) + 32 bytes (HMAC).

#### About the encrypted message

Initialization vectors (IV) should be unpredictable and unique; ideally, they
will be cryptographically random. They do not have to be secret: IVs are
typically just added to ciphertext messages unencrypted. It may sound
contradictory that something has to be unpredictable and unique, but does not
have to be secret; it is important to remember that an attacker must not be able
to predict ahead of time what a given IV will be.

With that in mind, keyring uses
`base64(hmac(unencrypted iv + encrypted message) + unencrypted iv + encrypted message)`
as the final message. If you're planning to migrate from other encryption
mechanisms or read encrypted values from the database without using keyring,
make sure you account for this. The HMAC is 32-bytes long and the IV is 16-bytes
long.

### Keyring

Keys are managed through a keyring--a short JSON document describing your
encryption keys. The keyring must be a JSON object mapping numeric ids of the
keys to the key values. A keyring must have at least one key. For example:

```json
{
  "1": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M=",
  "2": "VN8UXRVMNbIh9FWEFVde0q7GUA1SGOie1+FgAKlNYHc="
}
```

The `id` is used to track which key encrypted which piece of data; a key with a
larger id is assumed to be newer. The value is the actual bytes of the
encryption key.

You can use `keyring.ParseKeys(jsonString)` to load the keys before creating the
keyring:

```go
keys, err := k.ParseKeys(`
  {
    "1": "uDiMcWVNTuz//naQ88sOcN+E40CyBRGzGTT7OkoBS6M=",
    "2": "VN8UXRVMNbIh9FWEFVde0q7GUA1SGOie1+FgAKlNYHc="
  }
`)

keyring := k.CreateKeyring(keys, "<custom digest salt>", k.AES128CBC)
```

### Lookup

One tricky aspect of encryption is looking up records by a known secret. Doing a
`select * from users where email = $1` is trivial with plain text fields, but
impossible with encrypted attributes.

If you create a column `<attribute>_digest`, then you can use the SHA1 digest to
lookup by that value instead and add unique indexes. You don't have to use a
hashing salt, but it's highly recommended; this way you can avoid leaking your
users' info via rainbow tables.

### Exchange data with Ruby

If you use Ruby, you may be interested in
<https://github.com/fnando/attr_keyring>, which is able to read and write
messages using the same format.

### Exchange data with Node.js

If you use Node.js, you may be interested in
<https://github.com/fnando/keyring-node>, which is able to read and write
messages using the same format.

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/fnando/keyring-go. This project is intended to be a safe,
welcoming space for collaboration, and contributors are expected to adhere to
the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the
[MIT License](https://opensource.org/licenses/MIT).

## Icon

Icon made by [Icongeek26](https://www.flaticon.com/authors/icongeek26) from
[Flaticon](https://www.flaticon.com/) is licensed by Creative Commons BY 3.0.

## Code of Conduct

Everyone interacting in the keyring-go project’s codebases, issue trackers, chat
rooms and mailing lists is expected to follow the
[code of conduct](https://github.com/fnando/keyring-go/blob/main/CODE_OF_CONDUCT.md).
