package joseprimitives

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImportExport(t *testing.T) {
	p, err := ecdh.P384().GenerateKey(rand.Reader)
	require.NoError(t, err)
	jwk, err := Import(p.PublicKey())
	require.NoError(t, err)
	require.NotNil(t, jwk)

	jsonJWK, err := json.Marshal(jwk)
	require.NoError(t, err)
	t.Logf("JWK: %s", jsonJWK)

	exported, err := Export(jwk)
	require.NoError(t, err)
	require.NotNil(t, exported)

	require.True(t, p.PublicKey().Equal(exported))
}
