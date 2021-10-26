package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
)

type EcdsaSshKey struct {
	key *ecdsa.PrivateKey
}

func NewEcdsaSshKey() (*EcdsaSshKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &EcdsaSshKey{key: key}, nil
}

func ParseEcdsaSshKey(privatePem []byte) (*EcdsaSshKey, error) {
	block, _ := pem.Decode(privatePem)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &EcdsaSshKey{key: key}, nil
}

func (k *EcdsaSshKey) PrivatePem() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k.key)
	if err != nil {
		return nil, err
	}
	block := pem.Block{
		Type:    "OPENSSH PRIVATE KEY",
		Headers: nil,
		Bytes:   der,
	}
	return pem.EncodeToMemory(&block), nil
}

func (k *EcdsaSshKey) PublicAuthorized() ([]byte, error) {
	pub, err := ssh.NewPublicKey(k.key.Public())
	if err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(pub), nil
}

func (k *EcdsaSshKey) PublicFingerprint() ([]byte, error) {
	pub, err := ssh.NewPublicKey(k.key.Public())
	if err != nil {
		return nil, err
	}
	return []byte(ssh.FingerprintSHA256(pub)), nil
}
