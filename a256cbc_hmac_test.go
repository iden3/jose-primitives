package joseprimitives

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func privateKeyresolver(priv *ecdh.PrivateKey, kidclosure string) func(string) (*ecdh.PrivateKey, error) {
	return func(kid string) (*ecdh.PrivateKey, error) {
		if kid != kidclosure {
			return nil, fmt.Errorf("kid '%s' not found", kid)
		}
		return priv, nil
	}
}

func publicKeyResolver(pub *ecdh.PublicKey, kidclosure string) func(string) (*ecdh.PublicKey, error) {
	return func(kid string) (*ecdh.PublicKey, error) {
		if kid != kidclosure {
			return nil, fmt.Errorf("kid '%s' not found", kid)
		}
		return pub, nil
	}
}

func mustGenerateKey(t *testing.T, c ecdh.Curve) *ecdh.PrivateKey {
	var (
		priv *ecdh.PrivateKey
		err  error
	)

	switch c {
	case ecdh.P256():
		priv, err = ecdh.P256().GenerateKey(rand.Reader)
	case ecdh.P384():
		priv, err = ecdh.P384().GenerateKey(rand.Reader)
	case ecdh.P521():
		priv, err = ecdh.P521().GenerateKey(rand.Reader)
	case ecdh.X25519():
		priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	default:
		require.Fail(t, "unsupported curve")
	}
	require.NoError(t, err)
	return priv
}

func TestEncryptDecryptPxx(t *testing.T) {
	tests := []struct {
		name             string
		recipient        *ecdh.PrivateKey
		sender           *ecdh.PrivateKey
		plaintext        string
		encryptExpectErr bool
		decryptExpectErr bool
	}{
		{
			name:             "Valid encryption and decryption: P-384",
			recipient:        mustGenerateKey(t, ecdh.P384()),
			sender:           mustGenerateKey(t, ecdh.P384()),
			plaintext:        "plaintext",
			encryptExpectErr: false,
			decryptExpectErr: false,
		},
		{
			name:             "Valid encryption and decryption: x25519",
			recipient:        mustGenerateKey(t, ecdh.X25519()),
			sender:           mustGenerateKey(t, ecdh.X25519()),
			plaintext:        "plaintext",
			encryptExpectErr: false,
			decryptExpectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypter := NewEncrypter(
				publicKeyResolver(tt.recipient.PublicKey(), "did:recipient"),
				privateKeyresolver(tt.sender, "did:sender"),
			)
			jweToken, err := encrypter.Encrypt("did:recipient", "did:sender", []byte(tt.plaintext))
			if tt.encryptExpectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			decrypter := NewDecrypter(
				privateKeyresolver(tt.recipient, "did:recipient"),
				publicKeyResolver(tt.sender.PublicKey(), "did:sender"),
			)
			raw, err := decrypter.Decrypt(jweToken)
			require.NoError(t, err)
			require.Equal(t, tt.plaintext, string(raw))
		})
	}
}
