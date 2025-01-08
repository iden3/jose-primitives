// Description: This file contains the JWK struct and the Import function.
// We need this custom package because the go-jose and lestrrat-go/jwx/v3/jwk packages don't support ecdh.PublicKey
// in proper way.

package joseprimitives

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
}

// Import converts an ecdh.PublicKey to a JWK.
func Import(key *ecdh.PublicKey) (*JWK, error) {
	switch key.Curve() {
	case ecdh.X25519():
		return &JWK{
			Kty: "OKP",
			Crv: fmt.Sprintf("%s", ecdh.X25519()),
			X:   base64.RawURLEncoding.EncodeToString(key.Bytes()),
		}, nil
	case ecdh.P256(), ecdh.P384(), ecdh.P521():
		c, err := convertCurve(key.Curve())
		if err != nil {
			return nil, fmt.Errorf("failed to convert curve: %w", err)
		}
		//nolint:staticcheck // there is no another way to extract x and y from ecdh.PublicKey
		x, y := elliptic.Unmarshal(c, key.Bytes())
		if x == nil || y == nil {
			return nil, errors.New("invalid public key")
		}
		return &JWK{
			Kty: "EC",
			Crv: c.Params().Name,
			X:   base64.RawURLEncoding.EncodeToString(x.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(y.Bytes()),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported curve: '%s'", key.Curve())
	}
}

// Export converts a JWK to an ecdh.PublicKey.
func Export(jwk *JWK) (*ecdh.PublicKey, error) {
	switch jwk.Kty {
	case "OKP":
		switch jwk.Crv {
		case "X25519":
			x, err := base64.RawURLEncoding.DecodeString(jwk.X)
			if err != nil {
				return nil, fmt.Errorf("failed to decode X25519: %w", err)
			}
			key, err := ecdh.X25519().NewPublicKey(x)
			if err != nil {
				return nil, fmt.Errorf("failed to parse X25519 public key: %w", err)
			}
			return key, nil
		default:
			return nil, fmt.Errorf("unsupported OKP curve: '%s'", jwk.Crv)
		}
	case "EC":
		switch jwk.Crv {
		case "P-256":
			pubBytes, err := convertNistJWK(jwk.X, jwk.Y, ecdh.P256())
			if err != nil {
				return nil, fmt.Errorf("failed convert JWK with NIST P256: %w", err)
			}
			return ecdh.P256().NewPublicKey(pubBytes)
		case "P-384":
			pubBytes, err := convertNistJWK(jwk.X, jwk.Y, ecdh.P384())
			if err != nil {
				return nil, fmt.Errorf("failed convert JWK with NIST P384: %w", err)
			}
			return ecdh.P384().NewPublicKey(pubBytes)
		case "P-521":
			pubBytes, err := convertNistJWK(jwk.X, jwk.Y, ecdh.P521())
			if err != nil {
				return nil, fmt.Errorf("failed convert JWK with NIST P521: %w", err)
			}
			return ecdh.P521().NewPublicKey(pubBytes)
		default:
			return nil, fmt.Errorf("unsupported EC curve: '%s'", jwk.Crv)
		}
	default:
		return nil, fmt.Errorf("unsupported kty: '%s'", jwk.Kty)
	}

}

func convertNistJWK(xBase64, yBase64 string, curve ecdh.Curve) ([]byte, error) {
	x, err := base64.RawURLEncoding.DecodeString(xBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode64 X: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(yBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode64 Y: %w", err)
	}
	c, err := convertCurve(curve)
	if err != nil {
		return nil, fmt.Errorf("failed to convert curve: %w", err)
	}
	//nolint:staticcheck // there is no another way to build ecdh.PublicKey from x and y
	pubBytes := elliptic.Marshal(c, big.NewInt(0).SetBytes(x), big.NewInt(0).SetBytes(y))
	return pubBytes, nil
}

func convertCurve(c ecdh.Curve) (elliptic.Curve, error) {
	switch c {
	case ecdh.P256():
		return elliptic.P256(), nil
	case ecdh.P384():
		return elliptic.P384(), nil
	case ecdh.P521():
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("unsupported curve: '%s'", c)
}
