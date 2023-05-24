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

// Context is a password hashing context that uses a
// given set of schemes to hash and validate passwords.
type Context struct {
	// Slices the schemes to use, the most preferred ones first.
	// If uninitialized, the default schema set will be used.
	// A hash update will be issued every time a password is
	// validated using a scheme that is not the first in this slice.
	Schemes []scheme.Scheme
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
