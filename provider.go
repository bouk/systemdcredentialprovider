// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package systemdcredentialprovider // import "bou.ke/systemdcredentialprovider"

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.opentelemetry.io/collector/confmap"
)

const (
	schemeName = "systemdcredential"
)

var (
	// credNameValidation matches valid credential names (alphanumeric, underscore, dash)
	credNameValidation = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)
)

type provider struct {
}

// NewFactory returns a factory for a confmap.Provider that reads the configuration from systemd credentials.
//
// This Provider supports "systemdcredential" scheme, and can be called with a selector:
// `systemdcredential:CREDENTIAL_NAME`
//
// The credential is read from $CREDENTIALS_DIRECTORY/CREDENTIAL_NAME
//
// See also: https://systemd.io/CREDENTIALS/
func NewFactory() confmap.ProviderFactory {
	return confmap.NewProviderFactory(newProvider)
}

func newProvider(ps confmap.ProviderSettings) confmap.Provider {
	return &provider{}
}

func (p *provider) Retrieve(_ context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if !strings.HasPrefix(uri, schemeName+":") {
		return nil, fmt.Errorf("%q uri is not supported by %q provider", uri, schemeName)
	}
	credName := uri[len(schemeName)+1:]
	if !credNameValidation.MatchString(credName) {
		return nil, fmt.Errorf("credential name %q has invalid name: must match regex %s", credName, credNameValidation.String())
	}

	credDir, exists := os.LookupEnv("CREDENTIALS_DIRECTORY")
	if !exists {
		return nil, fmt.Errorf("CREDENTIALS_DIRECTORY environment variable is not set")
	}

	credPath := filepath.Join(credDir, credName)
	val, err := os.ReadFile(credPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credential %q from %q: %w", credName, credPath, err)
	}

	// Return the credential value as a string, trimming any trailing newline
	return confmap.NewRetrieved(strings.TrimSuffix(string(val), "\n"))
}

func (*provider) Scheme() string {
	return schemeName
}

func (*provider) Shutdown(context.Context) error {
	return nil
}
