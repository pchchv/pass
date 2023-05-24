// The pass package provides a simple
// password hashing and verification interface,
// abstracting several password hashing schemes.

// In most cases only the Hash and Verify functions
// can be used after initialization,
// using default contexts and reasonable default values.
package pass

import (
	"github.com/pchchv/pass/scheme"
)

// The default context, which uses sensible defaults.
// Most users should not reconfigure this.
var DefaultContext Context

// Context is a password hashing context that uses a
// given set of schemes to hash and validate passwords.
type Context struct {
	// Slices the schemes to use, the most preferred ones first.
	// If uninitialized, the default schema set will be used.
	// A hash update will be issued every time a password is
	// validated using a scheme that is not the first in this slice.
	Schemes []scheme.Scheme
}

// Hashes a UTF-8 plaintext password using the context and produces a password hash.
// If stub is "", one is generated automaticaly for the preferred password hashing
// scheme; you should specify stub as "" in almost all cases.
// The provided or randomly generated stub is used to deterministically hash the password.
// The returned hash is in modular crypt format.
// If the context has not been specifically configured, a sensible default policy is used.
// See the fields of Context.
func (ctx *Context) Hash(password string) (hash string, err error) {
	return ctx.schemes()[0].Hash(password)
}

// Verifies a UTF-8 plaintext password using a previously derived password hash and the default context.
// Returns nil err only if the password is valid.
// If the hash is determined to be deprecated based on the context policy,
// and the password is valid,
// the password is hashed using the preferred password hashing scheme and returned in newHash.
// You should use this to upgrade any stored password hash in your database.
// newHash is empty if the password was not valid or if no upgrade is required.
// You should treat any non-nil err as a password verification error.
func (ctx *Context) Verify(password, hash string) (newHash string, err error) {
	return ctx.verify(password, hash, true)
}

// Like Verify, but does not hash an upgrade password when upgrade is required.
func (ctx *Context) VerifyNoUpgrade(password, hash string) (err error) {
	_, err = ctx.verify(password, hash, false)
	return
}

// Determines whether a stub or hash needs updating
// according to the policy of the context.
func (ctx *Context) NeedsUpdate(stub string) bool {
	for i, scheme := range ctx.schemes() {
		if scheme.SupportsStub(stub) {
			return i != 0 || scheme.NeedsUpdate(stub)
		}
	}

	return false
}

func (ctx *Context) schemes() []scheme.Scheme {
	if ctx.Schemes == nil {
		return DefaultSchemes
	}

	return ctx.Schemes
}

func (ctx *Context) verify(password, hash string, canUpgrade bool) (newHash string, err error) {
	for i, scheme := range ctx.schemes() {
		if !scheme.SupportsStub(hash) {
			continue
		}

		err = scheme.Verify(password, hash)
		if err != nil {
			return "", err
		}

		if i != 0 || scheme.NeedsUpdate(hash) {
			if canUpgrade {
				// If the scheme is not the first scheme, try and rehash with the
				// preferred scheme.
				if newHash, err2 := ctx.Hash(password); err2 == nil {
					return newHash, nil
				}
			}
		}

		return "", nil
	}

	return "", scheme.ErrUnsupportedScheme
}

// Hashes a UTF-8 plaintext password using the
// default context and produces a password hash.
// Chooses the preferred password hashing scheme
// based on the configured policy.
// The default policy is sensible.
func Hash(password string) (hash string, err error) {
	return DefaultContext.Hash(password)
}

// Verifies a UTF-8 plaintext password using a previously derived password hash and the default context.
// Returns nil err only if the password is valid.
// If the hash is determined to be deprecated based on policy, and the password is valid,
// the password is hashed using the preferred password hashing scheme and returned in newHash.
// You should use this to upgrade any stored password hash in your database.
// newHash is empty if the password was invalid or no upgrade is required.
// You should treat any non-nil err as a password verification error.
func Verify(password, hash string) (newHash string, err error) {
	return DefaultContext.Verify(password, hash)
}

// Verify, but never upgrades.
func VerifyNoUpgrade(password, hash string) error {
	return DefaultContext.VerifyNoUpgrade(password, hash)
}
