package crypt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

type PrivateKey struct {
	key *rsa.PrivateKey
}

func (p *PrivateKey) Decode(data interface{}) error {
	var key []byte
	switch k := data.(type) {
	case []byte:
		key = k
	case string:
		key = []byte(k)
	default:
		return errors.Errorf("invalid rsa key type: %T", data)
	}

	k, err := bytesToPrivateKey(key)
	if err != nil {
		return errors.Wrap(err, "failed to parse rsa key")
	}
	p.key = k
	return nil
}

// bytesToPrivateKey parses rsa private key from pem bytes
func bytesToPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, err := getPemBlock(pemBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pem block for rsa private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pkcs1 private key")
	}

	return key, nil
}

type PublicKey struct {
	key *rsa.PublicKey
}

func (p *PublicKey) Decode(data interface{}) error {
	var key []byte
	switch k := data.(type) {
	case []byte:
		key = k
	case string:
		key = []byte(k)
	default:
		return errors.Errorf("invalid rsa key type: %T", data)
	}

	k, err := bytesToPublicKey(key)
	if err != nil {
		return errors.Wrap(err, "failed to parse rsa key")
	}
	p.key = k
	return nil
}

// bytesToPrivateKey parses rsa private key from pem bytes
func bytesToPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, err := getPemBlock(pemBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pem block for rsa public key")
	}
	key, err := x509.ParsePKCS1PublicKey(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pkcs1 public key")
	}
	return key, nil
}

func getPemBlock(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to find pem block in key")
	}

	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	// if encrypted pem block
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decrypt pem block")
		}
	}
	return b, nil
}
