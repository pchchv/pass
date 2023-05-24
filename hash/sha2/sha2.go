// Package sha2crypt implements sha256-crypt and sha512-crypt.
package sha2crypt

type sha2Crypter struct {
	sha512 bool
	rounds int
}
