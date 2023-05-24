# pass [![Go Reference](https://pkg.go.dev/badge/github.com/pchchv/pass.svg)](https://pkg.go.dev/github.com/pchchv/pass) [![No modules](https://www.devever.net/~hl/f/no-modules2.svg)](https://www.devever.net/~hl/gomod)

A password checking package based on [Python's passlib](https://pypi.org/project/passlib/), an amazing library. There is no password library with more thought put into it, or with more support for obscure password formats.

Currently, it supports:

  - Argon2i
  - scrypt-sha256
  - sha512-crypt
  - sha256-crypt
  - bcrypt
  - passlib's bcrypt-sha256 variant
  - pbkdf2-sha512 (in passlib format)
  - pbkdf2-sha256 (in passlib format)
  - pbkdf2-sha1 (in passlib format)

By default, it will hash using scrypt-sha256 and verify existing hashes using any of these schemes.

### Example Usage

There is a default context for ease of use.
Most people only need to use the `Hash` and `Verify` functions:

```go
// Hash gets the password in UTF-8 format and hashes it.
func Hash(password string) (hash string, err error)

// Verify verifies password in UTF-8 format using previously obtained hash.
// Returns an error if verification fails.
// Also returns updated password hash, if the provided hash is out of date.
func Verify(password string, hash string) (newHash string, err error)
```

```go
import "gopkg.in/pchchv/pass"

func Register() {
    (...)
  
    var password string // get a (UTF-8, plaintext) password from somewhere
  
    hash, err := pass.Hash(password)
    if err != nil {
        // error handling...
    }
    
    (store hash in database, etc.)
}

func CheckPassword(password string, hash string) bool {
    newHash, err := pass.Verify(password, hash)
    if err != nil {
        // incorrect password, malformed hash, etc.
        // error handling...
    }
    if newHash != "" {
        // According to its policy,
        // the context decided that the hash that was used
        // to validate the password should be changed.
        // It updated the hash using the verified password.
        
        (store newHash in database, replacing old hash)
    }
    
    return true
}
```

### scrypt Modular Crypt Format

Scrypt does not have an existing modular crypto-format standard. The format used in this library is as follows:

    $s2$N$r$p$salt$hash

`N`, `r` and `p` are the corresponding complexity parameters for encryption in the form of positive decimal integers.