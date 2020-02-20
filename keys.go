package crypt

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
)

type RSAPrivateKey struct {
	Key *rsa.PrivateKey
}

func (p *RSAPrivateKey) Decode(data interface{}) error {
	var key []byte
	switch k := data.(type) {
	case []byte:
		key = k
	case string:
		key = []byte(k)
	default:
		return errors.Errorf("invalid rsa Key type: %T", data)
	}

	k, err := BytesToPrivateKey(key)
	if err != nil {
		return errors.Wrap(err, "failed to parse rsa Key")
	}
	p.Key = k
	return nil
}

// BytesToPrivateKey parses rsa private Key from pem bytes
func BytesToPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, err := getPemBlock(pemBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pem block for rsa private Key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pkcs1 private Key")
	}

	return key, nil
}

type RSAPublicKey struct {
	Key *rsa.PublicKey
}

func (p *RSAPublicKey) Decode(data interface{}) error {
	var key []byte
	switch k := data.(type) {
	case []byte:
		key = k
	case string:
		key = []byte(k)
	default:
		return errors.Errorf("invalid rsa Key type: %T", data)
	}

	k, err := BytesToPublicKey(key)
	if err != nil {
		return errors.Wrap(err, "failed to parse rsa Key")
	}
	p.Key = k
	return nil
}

// BytesToPrivateKey parses rsa private Key from pem bytes
func BytesToPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, err := getPemBlock(pemBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pem block for rsa public Key")
	}

	// var pk rsa.PublicKey
	// if _, err := asn1.Unmarshal(block, &pk); err != nil {
	// 	return nil, err
	// }
	// return &pk, nil
	key, err := x509.ParsePKIXPublicKey(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pkcs1 public Key")
	}

	if pk, ok := key.(*rsa.PublicKey); ok {
		return pk, nil
	}
	return nil, fmt.Errorf("unknown key type %T", key)
}

func getPemBlock(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to find pem block in Key")
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

// PrivateKeyToBytes private Key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// PublicKeyToBytes public Key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil


	tls.X509KeyPair()
}
