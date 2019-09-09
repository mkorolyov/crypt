package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"

	"github.com/pkg/errors"
)

// Encoder encrypts and decrypts data
type Encoder interface {
	// Encrypts encrypts given plain data
	Encrypt(plain []byte) []byte
	// Decrypt decrypts given encrypted  data
	Decrypt(encrypted []byte) ([]byte, error)
}

// RSAEncoder implements Encoder with RSA algorithm for encoding.
// SHA512 used as hash function
type RSAEncoder struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// Encrypts encrypts given plain data
func (e *RSAEncoder) Encrypt(plain []byte) ([]byte, error) {
	hash := sha512.New()
	encrypted, err := rsa.EncryptOAEP(hash, rand.Reader, e.publicKey, plain, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt with public key")
	}
	return encrypted, nil
}

// Decrypt decrypts given encrypted  data
func (e *RSAEncoder) Decrypt(encrypted []byte) ([]byte, error) {
	hash := sha512.New()
	plain, err := rsa.DecryptOAEP(hash, rand.Reader, e.privateKey, encrypted, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt with private key")
	}
	return plain, nil
}

func NewRSAEncoder(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *RSAEncoder {
	return &RSAEncoder{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}
