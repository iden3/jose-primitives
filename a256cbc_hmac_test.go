package joseprimitives

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

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
	//nolint:govet // ignore struct size
	tests := []struct {
		name              string
		recipient         *ecdh.PrivateKey
		sender            *ecdh.PrivateKey
		plaintext         string
		encriptionOptions []encryptionOption
		expectedHeaders   map[string]interface{}
	}{
		{
			name:      "Valid encryption and decryption: P-384",
			recipient: mustGenerateKey(t, ecdh.P384()),
			sender:    mustGenerateKey(t, ecdh.P384()),
			plaintext: "plaintext",
			encriptionOptions: []encryptionOption{
				WithKid("kid"),
				WithSkid("skid"),
			},
			expectedHeaders: map[string]interface{}{
				HeaderKeyKid:  "kid",
				HeaderKeySkid: "skid",
			},
		},
		{
			name:      "Valid encryption and decryption: x25519",
			recipient: mustGenerateKey(t, ecdh.X25519()),
			sender:    mustGenerateKey(t, ecdh.X25519()),
			plaintext: "plaintext",
		},
		{
			name:      "Valid encryption and decryption: With custom headers",
			recipient: mustGenerateKey(t, ecdh.P384()),
			sender:    mustGenerateKey(t, ecdh.P384()),
			plaintext: "plaintext",
			encriptionOptions: []encryptionOption{
				WithCustomHeaders(map[string]string{
					"custom-header": "custom-value",
				}),
				WithKid("kid"),
				WithSkid("skid"),
			},
			expectedHeaders: map[string]interface{}{
				"custom-header": "custom-value",
				HeaderKeyKid:    "kid",
				HeaderKeySkid:   "skid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jweToken, err := Encrypt(
				tt.recipient.PublicKey(), tt.sender, []byte(tt.plaintext), tt.encriptionOptions...)
			require.NoError(t, err)

			h := decodeHeaders(t, jweToken)
			for k, v := range tt.expectedHeaders {
				require.Equal(t, v, h[k])
			}

			raw, err := Decrypt(tt.recipient, tt.sender.PublicKey(), jweToken)
			require.NoError(t, err)
			require.Equal(t, tt.plaintext, string(raw))
		})
	}
}

func decodeHeaders(t *testing.T, token string) map[string]interface{} {
	var h map[string]interface{}
	parts := strings.Split(token, ".")
	require.Len(t, parts, 5)
	headersBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(headersBytes, &h))
	return h
}
