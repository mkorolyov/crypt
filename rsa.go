package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"

	"github.com/pkg/errors"
)

type RSADecrypter struct {
	privateKey *rsa.PrivateKey
}

// Decrypt decrypts given encrypted  data
func (d *RSADecrypter) Decrypt(encrypted []byte) ([]byte, error) {
	raw, err := base64Decode(encrypted)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base64")
	}
	hash := sha512.New()
	plain, err := rsa.DecryptOAEP(hash, rand.Reader, d.privateKey, raw, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt with private Key")
	}
	return plain, nil
}

// RSAEncoder implements Encoder with RSA algorithm for encoding.
// SHA512 used as hash function
type RSAEncoder struct {
	RSADecrypter
	publicKey *rsa.PublicKey
}

// Encrypts encrypts given plain data
func (e *RSAEncoder) Encrypt(plain []byte) ([]byte, error) {
	hash := sha512.New()
	encrypted, err := rsa.EncryptOAEP(hash, rand.Reader, e.publicKey, plain, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt with public Key")
	}
	return base64Encode(encrypted), nil
}

func NewRSADecrypter(privateKey *rsa.PrivateKey) *RSADecrypter {
	return &RSADecrypter{privateKey: privateKey}
}

func NewRSAEncoder(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *RSAEncoder {
	return &RSAEncoder{
		RSADecrypter: RSADecrypter{privateKey: privateKey},
		publicKey:    publicKey,
	}
}
