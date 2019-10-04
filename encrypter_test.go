package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRSAEncoder(t *testing.T) {
	enc := NewRSAEncoder(testGenerateKeyPair(t, 2048))
	plain := []byte("sensitive plain")
	encoded, err := enc.Encrypt(plain)
	require.NoError(t, err, "failed to encrypt")
	decrypted, err := enc.Decrypt(encoded)
	require.NoError(t, err, "failed to decrypt")
	require.True(t, bytes.Equal(plain, decrypted), "encrypted data not equal to plain")
}

func testGenerateKeyPair(t *testing.T, bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()

	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate rsa Key pair: %v", err)
	}
	return privkey, &privkey.PublicKey
}

func Test_KeyConversion(t *testing.T) {
	privateKey, publicKey := testGenerateKeyPair(t, 4096)

	privateKeyBytes := PrivateKeyToBytes(privateKey)
	pk, err := BytesToPrivateKey(privateKeyBytes)
	require.NoError(t, err, "failed to parse private key from bytes")
	require.Equal(t, privateKey, pk)

	publicKeyBytes, err := PublicKeyToBytes(publicKey)
	require.NoError(t, err, "failed to convert public key to bytes")
	pubK, err := BytesToPublicKey(publicKeyBytes)
	require.NoError(t, err, "failed to parse public key from bytes")
	require.Equal(t, publicKey, pubK)
}

func PublicKeyFrom(key []byte) (*rsa.PublicKey, error) {
	pubInterface, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key")
	}
	return pub, nil
}

func Test_test(t *testing.T) {
	privateKey, publicKey := testGenerateKeyPair(t, 4096)
	t.Logf("\n%s\n", string(PrivateKeyToBytes(privateKey)))
	toBytes, _ := PublicKeyToBytes(publicKey)
	t.Logf("\n%s\n", string(toBytes))
}
