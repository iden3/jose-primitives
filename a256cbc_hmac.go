package joseprimitives

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	josecipher "github.com/go-jose/go-jose/v4/cipher"
)

const (
	// KeyEncryptionAlgorithm is the key encryption algorithm.
	KeyEncryptionAlgorithm = "ECDH-1PU+A256KW"
	// ContentEncryptionAlgorithm is the content encryption algorithm.
	ContentEncryptionAlgorithm = "A256CBC-HS512"
)

const (
	HeaderKeyAlg  = "alg"
	HeaderKeyEnc  = "enc"
	HeaderKeyApu  = "apu"
	HeaderKeyApv  = "apv"
	HeaderKeyEpk  = "epk"
	HeaderKeySkid = "skid"
	HeaderKeyKid  = "kid"
)

type encryptionOption func(*encryptionOptions)

type encryptionOptions struct {
	kid          string
	skid         string
	extraHeaders map[string]string
}

// WithKid sets the 'kid' option.
func WithKid(kid string) encryptionOption {
	return func(opts *encryptionOptions) {
		opts.kid = kid
	}
}

// WithSkid sets the 'skid' option.
func WithSkid(skid string) encryptionOption {
	return func(opts *encryptionOptions) {
		opts.skid = skid
	}
}

// WithCustomHeaders sets custom headers to be included in the token.
func WithCustomHeaders(headers map[string]string) encryptionOption {
	return func(opts *encryptionOptions) {
		opts.extraHeaders = headers
	}
}

// Encrypt encrypts a plaintext using the ECDH-1PU+A256KW and A256CBC-HS512 algorithms.
func Encrypt(recipient *ecdh.PublicKey, sender *ecdh.PrivateKey, plaintext []byte, opts ...encryptionOption) (string, error) {
	if recipient.Curve() != sender.Curve() {
		return "",
			fmt.Errorf(
				"curve mismatch: recipient's curve '%s', sender's curve '%s'",
				recipient.Curve(), sender.Curve(),
			)
	}

	o := &encryptionOptions{}
	for _, opt := range opts {
		opt(o)
	}

	var (
		epk *ecdh.PrivateKey
		err error
	)

	switch recipient.Curve() {
	case ecdh.X25519():
		epk, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("failed to generate ephemeral key: %w", err)
		}
	case ecdh.P384():
		epk, err = ecdh.P384().GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("failed to generate ephemeral key: %w", err)
		}
	default:
		return "", fmt.Errorf("unsupported curve: '%s'", recipient.Curve())
	}

	kek, err := NewECDHPU1Key(
		ZxKeyPair{p: epk, pub: recipient},
		ZxKeyPair{p: sender, pub: recipient},
	)
	if err != nil {
		return "", fmt.Errorf("failed to key agreement: %w", err)
	}

	cek := make([]byte, 64)
	_, err = rand.Read(cek)
	if err != nil {
		return "", fmt.Errorf("failed to generate cek: %w", err)
	}
	nonce := make([]byte, aes.BlockSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	encrypter, err := josecipher.NewCBCHMAC(cek, aes.NewCipher)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}
	add, err := getHeaders(
		o.skid, o.kid, recipient, sender, epk, o.extraHeaders)
	if err != nil {
		return "", fmt.Errorf("failed to create headers: %w", err)
	}
	headersBytes, err := json.Marshal(add)
	if err != nil {
		return "", fmt.Errorf("failed to marshal headers: %w", err)
	}

	ciphertext := encrypter.Seal(nil, nonce, plaintext, headersBytes)
	if len(ciphertext) == 0 {
		return "", errors.New("failed to encrypt plaintext")
	}

	encryptedCek, err := kek.Wrap(cek)
	if err != nil {
		return "", fmt.Errorf("failed to wrap cek: %w", err)
	}

	noAuthCiphertext, authTag, err := extractAuthTag(ciphertext, len(plaintext), aes.BlockSize, len(cek)/2)
	if err != nil {
		return "", fmt.Errorf("failed to extract auth tag: %w", err)
	}

	compactToken := fmt.Sprintf(
		"%s.%s.%s.%s.%s",
		base64.RawURLEncoding.EncodeToString(headersBytes),
		base64.RawURLEncoding.EncodeToString(encryptedCek),
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(noAuthCiphertext),
		base64.RawURLEncoding.EncodeToString(authTag),
	)

	return compactToken, nil
}

// Decrypt decrypts a compact token.
func Decrypt(recipient *ecdh.PrivateKey, sender *ecdh.PublicKey, compactToken string) ([]byte, error) {
	headersBytes, encryptedCek, nonce, ciphertext, authTag, err := parseCompactToken(compactToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse compact token: %w", err)
	}

	headers := map[string]string{}
	if err = json.Unmarshal(headersBytes, &headers); err != nil {
		return nil, fmt.Errorf("failed to decode headers: %w", err)
	}

	e, ok := headers[HeaderKeyEpk]
	if !ok {
		return nil, errors.New("epk not found in headers")
	}
	epkjwk := &JWK{}
	if err = json.Unmarshal([]byte(e), epkjwk); err != nil {
		return nil, fmt.Errorf("failed to unmarshal epk: %w", err)
	}

	ephemeral, err := Export(epkjwk)
	if err != nil {
		return nil, fmt.Errorf("failed to export epk: %w", err)
	}

	kek, err := NewECDHPU1Key(ZxKeyPair{p: recipient, pub: ephemeral}, ZxKeyPair{p: recipient, pub: sender})
	if err != nil {
		return nil, fmt.Errorf("failed to key agreement: %w", err)
	}

	cek, err := kek.Unwrap(encryptedCek)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap cek: %w", err)
	}

	decrypter, err := josecipher.NewCBCHMAC(cek, aes.NewCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypter: %w", err)
	}

	ciphertext = append(ciphertext, authTag...)
	plaintext, err := decrypter.Open(nil, nonce, ciphertext, headersBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}

//nolint:gocritic // it's okay for the function to have many return statements
func parseCompactToken(compactToken string) (headers, encryptedCek, nonce, ciphertext, authTag []byte, err error) {
	parts := strings.Split(compactToken, ".")
	if len(parts) != 5 {
		return nil, nil, nil, nil, nil, errors.New("invalid compact token")
	}

	headers, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decode headers: %w", err)
	}

	encryptedCek, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decode encrypted cek: %w", err)
	}

	nonce, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err = base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	authTag, err = base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decode auth tag: %w", err)
	}

	return headers, encryptedCek, nonce, ciphertext, authTag, nil
}

func getHeaders(
	skid, kid string,
	recipient *ecdh.PublicKey,
	sender *ecdh.PrivateKey,
	epk *ecdh.PrivateKey,
	extraHeaders map[string]string,
) (map[string]string, error) {
	epkjwk, err := Import(epk.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to import epk to jwt: %w", err)
	}
	epkstr, err := json.Marshal(epkjwk)
	if err != nil {
		return nil, fmt.Errorf("failed to encode epk: %w", err)
	}

	apuBytes := append(epk.PublicKey().Bytes(), sender.PublicKey().Bytes()...)
	apuHash := sha256.Sum256(apuBytes)
	apvHash := sha256.Sum256(recipient.Bytes())

	headers := map[string]string{}
	headers[HeaderKeyAlg] = KeyEncryptionAlgorithm
	headers[HeaderKeyEnc] = ContentEncryptionAlgorithm
	headers[HeaderKeyApu] = base64.RawURLEncoding.EncodeToString(apuHash[:])
	headers[HeaderKeyApv] = base64.RawURLEncoding.EncodeToString(apvHash[:])
	headers[HeaderKeyEpk] = string(epkstr)

	if skid != "" {
		headers[HeaderKeySkid] = skid
	}
	if kid != "" {
		headers[HeaderKeyKid] = kid
	}

	for k, v := range extraHeaders {
		headers[k] = v
	}

	return headers, nil
}

func extractAuthTag(ciphertextWithAuthTag []byte, plaintextLength, blockSize, authTagLength int) (
	ciphertext []byte, authTag []byte, err error) {
	var paddedLength int
	remainder := plaintextLength % blockSize
	if remainder == 0 {
		// regaring go-jose implementation we should always add padding
		// even if the plaintext is already aligned to the block size
		// https://github.com/go-jose/go-jose/blob/9860c65054c4821d1e7c22200422b04181f58ebc/cipher/cbc_hmac.go#L169
		paddedLength = plaintextLength + blockSize
	} else {
		paddedLength = plaintextLength + blockSize - remainder
	}

	if len(ciphertextWithAuthTag) < paddedLength+authTagLength {
		return nil, nil, errors.New("invalid ciphertext length")
	}

	ciphertext = ciphertextWithAuthTag[:paddedLength]
	authTag = ciphertextWithAuthTag[paddedLength : paddedLength+authTagLength]

	return ciphertext, authTag, nil
}
