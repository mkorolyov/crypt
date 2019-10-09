package crypt

// Encrypter encrypts and decrypts data
type Encrypter interface {
	Decrypter
	// Encrypts encrypts given plain data
	Encrypt(plain []byte) ([]byte, error)
}

type Decrypter interface {
	// Decrypt decrypts given encrypted  data
	Decrypt(encrypted []byte) ([]byte, error)
}
