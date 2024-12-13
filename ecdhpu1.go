package joseprimitives

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdh"
	"fmt"

	josecipher "github.com/go-jose/go-jose/v4/cipher"
)

type ZxKeyPair struct {
	p   *ecdh.PrivateKey
	pub *ecdh.PublicKey
}

func NewZxKeyPair(p *ecdh.PrivateKey, pub *ecdh.PublicKey) ZxKeyPair {
	return ZxKeyPair{p: p, pub: pub}
}

func (z ZxKeyPair) ECDH() ([]byte, error) {
	zx, err := z.p.ECDH(z.pub)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared secret: %w", err)
	}
	return zx, nil
}

type ECDHPU1Key struct {
	kek []byte
}

func (k *ECDHPU1Key) Wrap(cek []byte) ([]byte, error) {
	b, err := aes.NewCipher(k.kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher: %w", err)
	}
	return josecipher.KeyWrap(b, cek)
}

func (k *ECDHPU1Key) Unwrap(cek []byte) ([]byte, error) {
	b, err := aes.NewCipher(k.kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher: %w", err)
	}
	return josecipher.KeyUnwrap(b, cek)
}

func NewECDHPU1Key(zeKeyPair, zsKeyPair ZxKeyPair) (*ECDHPU1Key, error) {
	ze, err := zeKeyPair.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared ze secret: %w", err)
	}
	zs, err := zsKeyPair.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared zs secret: %w", err)
	}
	z := append(ze, zs...)

	empty := make([]byte, 0)
	r := josecipher.NewConcatKDF(crypto.SHA256, z, empty, empty, empty, empty, empty)
	kek := make([]byte, 32)
	_, err = r.Read(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to generate kek: %w", err)
	}
	return &ECDHPU1Key{kek}, nil
}
