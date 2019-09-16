package crypt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPBKDF2Hasher_Hash(t *testing.T) {
	globalSalt, err := salt()
	require.NoError(t, err, "failed to get random salt")
	testHash(t, globalSalt)
}

func TestPBKDF2Hasher_Hash_nil_salt(t *testing.T) {
	testHash(t, nil)
}

func testHash(t *testing.T, globalSalt []byte) {
	password := "password"
	hashed, err := DefaultHasher.Hash(password, globalSalt)
	require.NoError(t, err, "failed to hash password")
	equal, err := DefaultHasher.Verify(hashed, password, globalSalt)
	require.NoError(t, err, "verification error")
	require.True(t, equal)
}
