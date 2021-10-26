package auth

import (
	"strings"
	"testing"
)

func TestNewEcdsaSshKey(t *testing.T) {
	_, err := NewEcdsaSshKey()
	if err != nil {
		t.FailNow()
	}
}

func TestEcdsaSshKey_PrivatePem(t *testing.T) {
	key, err := NewEcdsaSshKey()
	if err != nil {
		t.FailNow()
	}
	pem, err := key.PrivatePem()
	if err != nil || !strings.Contains(string(pem), "OPENSSH PRIVATE KEY") {
		t.FailNow()
	}
}

func TestEcdsaSshKey_PublicAuthorized(t *testing.T) {
	key, err := NewEcdsaSshKey()
	if err != nil {
		t.FailNow()
	}
	auth, err := key.PublicAuthorized()
	if err != nil {
		t.FailNow()
	}
	if err != nil || !strings.Contains(string(auth), "ecdsa-sha2-nistp521") {
		t.FailNow()
	}
}

func TestEcdsaSshKey_PublicFingerprint(t *testing.T) {
	key, err := NewEcdsaSshKey()
	if err != nil {
		t.FailNow()
	}
	fingerprint, err := key.PublicFingerprint()
	if err != nil || !strings.Contains(string(fingerprint), "SHA256") {
		t.FailNow()
	}
}

func TestParseEcdsaSshKey(t *testing.T) {
	key1, err := NewEcdsaSshKey()
	if err != nil {
		t.FailNow()
	}
	pem, err := key1.PrivatePem()
	if err != nil {
		t.FailNow()
	}
	key2, err := ParseEcdsaSshKey(pem)
	if err != nil {
		t.FailNow()
	}
	if !key1.key.Equal(key2.key) {
		t.FailNow()
	}
}
