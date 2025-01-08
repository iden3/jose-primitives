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

// PrivateKeyResolver resolves a private key by its key ID.
type PrivateKeyResolver func(kid string) (*ecdh.PrivateKey, error)

// PublicKeyResolver resolves a public key by its key ID.
type PublicKeyResolver func(kid string) (*ecdh.PublicKey, error)

// Encrypter encrypts plaintext using the ECDH-1PU+A256KW and A256CBC-HS512 algorithms.
// Supported curves are X25519 and P384.
type Encrypter struct {
	recipientResolver PublicKeyResolver
	senderResolver    PrivateKeyResolver
}

// NewEncrypter creates a new Encrypter.
func NewEncrypter(
	recipientResolver PublicKeyResolver,
	senderResolver PrivateKeyResolver,
) *Encrypter {
	return &Encrypter{
		recipientResolver: recipientResolver,
		senderResolver:    senderResolver,
	}
}

// Encrypt encrypts a plaintext using the ECDH-1PU+A256KW and A256CBC-HS512 algorithms.
func (e *Encrypter) Encrypt(recipientKid, senderKid string, plaintext []byte) (string, error) {
	recipient, err := e.recipientResolver(recipientKid)
	if err != nil {
		return "", fmt.Errorf("failed to resolve recipient key: %w", err)
	}
	sender, err := e.senderResolver(senderKid)
	if err != nil {
		return "", fmt.Errorf("failed to resolve sender key: %w", err)
	}

	if recipient.Curve() != sender.Curve() {
		return "",
			fmt.Errorf(
				"curve mismatch: recipient's curve '%s', sender's curve '%s'",
				recipient.Curve(), sender.Curve(),
			)
	}

	var epk *ecdh.PrivateKey
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
		senderKid, recipientKid, recipient, sender, epk)
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
		base64.URLEncoding.EncodeToString(headersBytes),
		base64.URLEncoding.EncodeToString(encryptedCek),
		base64.URLEncoding.EncodeToString(nonce),
		base64.URLEncoding.EncodeToString(noAuthCiphertext),
		base64.URLEncoding.EncodeToString(authTag),
	)

	return compactToken, nil
}

type decryptionOption func(*decrypterOptions)

type decrypterOptions struct {
	kid  string
	skid string
}

// WithKid sets the 'kid' option.
func WithKid(kid string) decryptionOption {
	return func(opts *decrypterOptions) {
		opts.kid = kid
	}
}

// WithSkid sets the 'skid' option.
func WithSkid(skid string) decryptionOption {
	return func(opts *decrypterOptions) {
		opts.skid = skid
	}
}

// Decrypter decrypts a compact token. 
// Supported curves are X25519 and P384.
type Decrypter struct {
	recipientResolver PrivateKeyResolver
	senderResolver    PublicKeyResolver
}

// NewDecrypter creates a new Decrypter.
func NewDecrypter(
	recipientResolver PrivateKeyResolver,
	senderResolver PublicKeyResolver,
) *Decrypter {
	return &Decrypter{
		recipientResolver: recipientResolver,
		senderResolver:    senderResolver,
	}
}

// Decrypt decrypts a compact token.
func (d *Decrypter) Decrypt(compactToken string, opts ...decryptionOption) ([]byte, error) {
	headersBytes, encryptedCek, nonce, ciphertext, authTag, err := parseCompactToken(compactToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse compact token: %w", err)
	}

	headers := map[string]string{}
	if err = json.Unmarshal(headersBytes, &headers); err != nil {
		return nil, fmt.Errorf("failed to decode headers: %w", err)
	}

	o := &decrypterOptions{
		kid:  headers[HeaderKeyKid],
		skid: headers[HeaderKeySkid],
	}
	for _, opt := range opts {
		opt(o)
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
	recipient, err := d.recipientResolver(o.kid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve recipient: %w", err)
	}
	sender, err := d.senderResolver(o.skid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve sender: %w", err)
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

	headers, err = base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decode headers: %w", err)
	}

	encryptedCek, err = base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decode encrypted cek: %w", err)
	}

	nonce, err = base64.URLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	ciphertext, err = base64.URLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	authTag, err = base64.URLEncoding.DecodeString(parts[4])
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
	headers[HeaderKeyApu] = base64.URLEncoding.EncodeToString(apuHash[:])
	headers[HeaderKeyApv] = base64.URLEncoding.EncodeToString(apvHash[:])
	headers[HeaderKeyEpk] = string(epkstr)
	headers[HeaderKeySkid] = skid
	headers[HeaderKeyKid] = kid

	return headers, nil
}

func extractAuthTag(ciphertextWithAuthTag []byte, plaintextLength, blockSize, authTagLength int) (
	ciphertext []byte, authTag []byte, err error) {
	paddedLength := (plaintextLength + blockSize - 1) / blockSize * blockSize

	if len(ciphertextWithAuthTag) < paddedLength+authTagLength {
		return nil, nil, errors.New("invalid ciphertext length")
	}

	ciphertext = ciphertextWithAuthTag[:paddedLength]
	authTag = ciphertextWithAuthTag[paddedLength : paddedLength+authTagLength]

	return ciphertext, authTag, nil
}
