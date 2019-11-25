package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// hashLength should be 32 bytes for sha256
	hashLength = 32
	// saltLength should be at least 8 bytes per RFC-2898 (https://www.ietf.org/rfc/rfc2898.txt)
	saltLength = 8
	// 2 ^ 16, gives ~64millis for pbkdf2Encode on local machine.
	iterations = 65536
)

// Hasher provides API for hash data and than check if hashed data equal to new passed one.
// Commonly used for passwords storing.
type Hasher interface {
	// Hash hashes plain data with salt
	Hash(plain string, globalSalt []byte) (string, error)
	// Verify checks if auditee is the same data as was previously hashed with salt
	Verify(hashed, auditee string, globalSalt []byte) (bool, error)
}

type PBKDF2Hasher struct {
}

var DefaultHasher Hasher = &PBKDF2Hasher{}

// Hash hashes data with slow hash function pbkdf2 via base64.Encode(hashFn(globalSalt + randomSalt + plain))
// Random salt with 8 bytes length appended to resulted encoded hash.
func (PBKDF2Hasher) Hash(plain string, globalSalt []byte) (string, error) {
	randomSalt, err := salt()
	if err != nil {
		return "", errors.Wrap(err, "failed to hash password")
	}

	hash := pbkdf2Hash(plain, globalSalt, randomSalt)
	hashBase64 := base64Encode(hash)
	return string(append(randomSalt, hashBase64...)), nil
}

// VerifyHash verifies that passed auditee is the same as was hashed.
func (PBKDF2Hasher) Verify(hashed, auditee string, globalSalt []byte) (bool, error) {
	hashedBytes := []byte(hashed)
	decodedHash, err := base64Decode(hashedBytes[saltLength:])
	if err != nil {
		return false, errors.Wrapf(err, "failed to base64 decode original salt from %s", hashed[:saltLength])
	}
	randomSalt := hashedBytes[:saltLength]
	hashedAuditee := pbkdf2Hash(auditee, globalSalt, randomSalt)

	return bytes.Equal(decodedHash, hashedAuditee), nil
}

// pbkdf2Hash encodes plain string
func pbkdf2Hash(plain string, globalSalt []byte, randomSalt []byte) []byte {
	return pbkdf2.Key([]byte(plain), append(globalSalt, randomSalt...), iterations, hashLength, sha256.New)
}

// salt generates a cryptographically secure nonce salt in ASCII.
func salt() ([]byte, error) {
	b, err := generateRandomBytes(saltLength)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate salt")
	}

	saltBase64 := base64Encode(b)
	return saltBase64[:saltLength], nil
}

// generateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return b, nil
}

func base64Encode(src []byte) []byte {
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(buf, src)
	return buf
}

func base64Decode(src []byte) ([]byte, error) {
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(buf, src)
	if err != nil {
		return nil, errors.Wrapf(err, "succeed only %d bytes, failed to decode base64 string %s", n, string(src))
	}
	return buf[:n], nil
}
