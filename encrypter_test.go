package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"github.com/stretchr/testify/require"
	"testing"
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
		t.Fatalf("failed to generate rsa key pair: %v", err)
	}
	return privkey, &privkey.PublicKey
}