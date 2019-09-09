package crypt

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPBKDF2Hasher_Hash(t *testing.T) {
	globalSalt, err := salt()
	require.NoError(t, err, "failed to get random salt")
	password := "password"
	hashed, err := DefaultHasher.Hash(password, globalSalt)
	require.NoError(t, err, "failed to hash password")
	equal, err := DefaultHasher.Verify(hashed, password, globalSalt)
	require.NoError(t, err, "verification error")
	require.True(t, equal)
}
