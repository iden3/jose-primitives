package joseprimitives

import (
	"crypto/ecdh"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewECDHPU1Key(t *testing.T) {
	type testCase struct {
		name          string
		senderSide    [2]ZxKeyPair
		recipientSide [2]ZxKeyPair
		cek           []byte
	}

	senderStaticKeyNist := mustGenerateKey(t, ecdh.P384())
	recipientStaticKeyNist := mustGenerateKey(t, ecdh.P384())
	ephemeralKeyNist := mustGenerateKey(t, ecdh.P384())

	senderStaticKeyX25519 := mustGenerateKey(t, ecdh.X25519())
	recipientStaticKeyX25519 := mustGenerateKey(t, ecdh.X25519())
	ephemeralKeyX25519 := mustGenerateKey(t, ecdh.X25519())

	testCases := []testCase{
		{
			name: "Valid keys, should encrypt and decrypt correctly. Nist curves",
			senderSide: [2]ZxKeyPair{
				{
					p:   ephemeralKeyNist,
					pub: recipientStaticKeyNist.PublicKey(),
				},
				{
					p:   senderStaticKeyNist,
					pub: recipientStaticKeyNist.PublicKey(),
				},
			},
			recipientSide: [2]ZxKeyPair{
				{
					p:   recipientStaticKeyNist,
					pub: ephemeralKeyNist.PublicKey(),
				},
				{
					p:   recipientStaticKeyNist,
					pub: senderStaticKeyNist.PublicKey(),
				},
			},
			cek: []byte("1234567890123456"),
		},
		{
			name: "Valid keys, should encrypt and decrypt correctly. X25519 curves",
			senderSide: [2]ZxKeyPair{
				{
					p:   ephemeralKeyX25519,
					pub: recipientStaticKeyX25519.PublicKey(),
				},
				{
					p:   senderStaticKeyX25519,
					pub: recipientStaticKeyX25519.PublicKey(),
				},
			},
			recipientSide: [2]ZxKeyPair{
				{
					p:   recipientStaticKeyX25519,
					pub: ephemeralKeyX25519.PublicKey(),
				},
				{
					p:   recipientStaticKeyX25519,
					pub: senderStaticKeyX25519.PublicKey(),
				},
			},
			cek: []byte("1234567890123456"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			senderSideKek, err := NewECDHPU1Key(tc.senderSide[0], tc.senderSide[1])
			require.NoError(t, err)
			encryptedCek, err := senderSideKek.Wrap(tc.cek)
			require.NoError(t, err)

			userSideKek, err := NewECDHPU1Key(tc.recipientSide[0], tc.recipientSide[1])
			require.NoError(t, err)
			decryptedCek, err := userSideKek.Unwrap(encryptedCek)
			require.NoError(t, err)

			require.Equal(t, tc.cek, decryptedCek)
		})
	}
}
