package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/pkg/errors"
)

type HybridDecrypter struct {
	privateKey *rsa.PrivateKey
}

// Decrypt decrypts given encrypted  data
func (d *HybridDecrypter) Decrypt(encrypted []byte) ([]byte, error) {
	cipherText, err := base64Decode(encrypted)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base64")
	}

	aesKeyLength := d.privateKey.PublicKey.Size()
	if len(cipherText) <= aesKeyLength {
		return nil, errors.Errorf("encrypted data length too low")
	}

	hash := sha256.New()
	aesKey, err := rsa.DecryptOAEP(hash, rand.Reader, d.privateKey, cipherText[:aesKeyLength], nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt aes key with private Key")
	}

	gcm, err := aesGCM(aesKey)
	if err != nil {
		return nil, err
	}

	textStart := aesKeyLength + gcm.NonceSize()
	// cipherText[:0] reuses allocated slice
	plainText, err := gcm.Open(cipherText[:0], cipherText[aesKeyLength:textStart], cipherText[textStart:], nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decrypt aes data")
	}

	return plainText, nil
}

var _ Encrypter = &HybridEncrypter{}

// HybridEncrypter implements Encrypter with RSA for encrypting AES key and AES-256 for encrypting raw data.
// SHA256 used as hash function
type HybridEncrypter struct {
	HybridDecrypter
	publicKey *rsa.PublicKey
}

// Encrypts encrypts given plain data
func (e *HybridEncrypter) Encrypt(plain []byte) ([]byte, error) {
	hash := sha256.New()

	// 32 bytes for AES-256 encryption
	aesKey := make([]byte, 32)
	n, err := rand.Read(aesKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read 32 bytes from crypto/Rand")
	}
	if n != 32 {
		return nil, fmt.Errorf("read only %d of 32 bytes from crypto/Rand", n)
	}

	gcm, err := aesGCM(aesKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	n, err = rand.Read(nonce)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read %d bytes from crypto/Rand for gcm nonce", gcm.NonceSize())
	}
	if n != gcm.NonceSize() {
		return nil, fmt.Errorf("read only %d of %d bytes from crypto/Rand for gcm nonce", n, gcm.NonceSize())
	}

	ciphed := gcm.Seal(nonce, nonce, plain, nil)

	encryptedAes, err := rsa.EncryptOAEP(hash, rand.Reader, e.publicKey, aesKey, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt aes key with public Key")
	}
	return base64Encode(append(encryptedAes, ciphed...)), nil
}

func NewHybridDecrypter(privateKey *rsa.PrivateKey) *HybridDecrypter {
	return &HybridDecrypter{privateKey: privateKey}
}

func NewHybridEncrypter(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *HybridEncrypter {
	return &HybridEncrypter{
		HybridDecrypter: HybridDecrypter{privateKey: privateKey},
		publicKey:       publicKey,
	}
}

func aesGCM(aesKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build new aes cipher from key %s", string(aesKey))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build new gcm from aes cipher %+v", block)
	}
	return gcm, nil
}