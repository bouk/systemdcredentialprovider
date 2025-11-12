// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemdcredentialprovider

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/confmaptest"
)

const credSchemePrefix = schemeName + ":"

const testCredValue = "my-secret-token-12345"

func TestValidateProviderScheme(t *testing.T) {
	assert.NoError(t, confmaptest.ValidateProviderScheme(createProvider()))
}

func TestEmptyName(t *testing.T) {
	env := createProvider()
	_, err := env.Retrieve(context.Background(), "", nil)
	require.Error(t, err)
	assert.NoError(t, env.Shutdown(context.Background()))
}

func TestUnsupportedScheme(t *testing.T) {
	env := createProvider()
	_, err := env.Retrieve(context.Background(), "https://", nil)
	assert.Error(t, err)
	assert.NoError(t, env.Shutdown(context.Background()))
}

func TestCredentialWithSpecialChars(t *testing.T) {
	const credName = "special_chars"
	const credValue = "token-with-special!@#$%^&*()chars"
	credDir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", credDir)
	require.NoError(t, os.WriteFile(filepath.Join(credDir, credName), []byte(credValue), 0600))

	prov := createProvider()
	ret, err := prov.Retrieve(context.Background(), credSchemePrefix+credName, nil)
	require.NoError(t, err)
	str, err := ret.AsString()
	require.NoError(t, err)
	assert.Equal(t, credValue, str)
	assert.NoError(t, prov.Shutdown(context.Background()))
}

func TestCredential(t *testing.T) {
	const credName = "api_token"
	credDir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", credDir)
	require.NoError(t, os.WriteFile(filepath.Join(credDir, credName), []byte(testCredValue), 0600))

	prov := createProvider()
	ret, err := prov.Retrieve(context.Background(), credSchemePrefix+credName, nil)
	require.NoError(t, err)
	str, err := ret.AsString()
	require.NoError(t, err)
	assert.Equal(t, testCredValue, str)

	assert.NoError(t, prov.Shutdown(context.Background()))
}

func TestMissingCredential(t *testing.T) {
	const credName = "missing_cred"
	credDir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", credDir)

	prov := createProvider()
	ret, err := prov.Retrieve(context.Background(), credSchemePrefix+credName, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read credential")
	assert.Nil(t, ret)
	assert.NoError(t, prov.Shutdown(context.Background()))
}

func TestCredentialNameRestriction(t *testing.T) {
	const credName = "default%config"
	credDir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", credDir)

	prov := createProvider()
	ret, err := prov.Retrieve(context.Background(), credSchemePrefix+credName, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid name")
	assert.NoError(t, prov.Shutdown(context.Background()))
	assert.Nil(t, ret)
}

func TestEmptyCredential(t *testing.T) {
	const credName = "empty_cred"
	credDir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", credDir)
	require.NoError(t, os.WriteFile(filepath.Join(credDir, credName), []byte(""), 0600))

	prov := createProvider()
	ret, err := prov.Retrieve(context.Background(), credSchemePrefix+credName, nil)
	require.NoError(t, err)
	str, err := ret.AsString()
	require.NoError(t, err)
	assert.Equal(t, "", str)

	assert.NoError(t, prov.Shutdown(context.Background()))
}

func TestMissingCredentialsDirectory(t *testing.T) {
	const credName = "MY_CRED"
	prov := createProvider()
	ret, err := prov.Retrieve(context.Background(), credSchemePrefix+credName, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CREDENTIALS_DIRECTORY environment variable is not set")
	assert.Nil(t, ret)
	assert.NoError(t, prov.Shutdown(context.Background()))
}

func TestCredentialWithTrailingNewline(t *testing.T) {
	const credName = "token_with_newline"
	const credValue = "my-secret-token"
	credDir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", credDir)
	// Write credential with trailing newline (common when using echo)
	require.NoError(t, os.WriteFile(filepath.Join(credDir, credName), []byte(credValue+"\n"), 0600))

	prov := createProvider()
	ret, err := prov.Retrieve(context.Background(), credSchemePrefix+credName, nil)
	require.NoError(t, err)
	str, err := ret.AsString()
	require.NoError(t, err)
	// Should have newline trimmed
	assert.Equal(t, credValue, str)
	assert.NoError(t, prov.Shutdown(context.Background()))
}

func createProvider() confmap.Provider {
	return NewFactory().Create(confmaptest.NewNopProviderSettings())
}
