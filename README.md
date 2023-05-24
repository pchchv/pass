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
