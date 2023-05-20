// The bcrypt package implements the bcrypt password hashing mechanism.
//
// Note that bcrypt truncates passwords to 72 characters in length.
// Consider using a more modern hashing scheme, such as scrypt or sha-crypt.
// If you must use bcrypt, use bcrypt-sha256 instead.
package bcrypt

type bcryptScheme struct {
	Cost int
}
