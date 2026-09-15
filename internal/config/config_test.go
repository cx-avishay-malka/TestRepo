package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultsTLSFields verifies that TLS certificate and key paths are
// present in the default configuration, ensuring the server is always wired
// for TLS even when environment variables are absent.
func TestLoad_DefaultsTLSFields(t *testing.T) {
	// Ensure env vars are not set so we exercise the defaults.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile == "" {
		t.Error("TLSCertFile must not be empty: server requires a TLS certificate to prevent plaintext transport (CWE-319)")
	}
	if cfg.TLSKeyFile == "" {
		t.Error("TLSKeyFile must not be empty: server requires a TLS private key to prevent plaintext transport (CWE-319)")
	}
}

// TestLoad_TLSFieldsFromEnv verifies that TLS_CERT_FILE and TLS_KEY_FILE
// environment variables are respected, allowing operators to supply custom
// certificate paths in production.
func TestLoad_TLSFieldsFromEnv(t *testing.T) {
	const wantCert = "/etc/ssl/certs/app.crt"
	const wantKey = "/etc/ssl/private/app.key"

	os.Setenv("TLS_CERT_FILE", wantCert)
	os.Setenv("TLS_KEY_FILE", wantKey)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile = %q, want %q", cfg.TLSCertFile, wantCert)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile = %q, want %q", cfg.TLSKeyFile, wantKey)
	}
}

// TestLoad_DefaultServerPort verifies that the server port is populated by
// default, ensuring the TLS listener always has an address to bind to.
func TestLoad_DefaultServerPort(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("ServerPort must not be empty")
	}
}

// TestLoad_ServerPortFromEnv verifies that the SERVER_PORT environment
// variable is respected.
func TestLoad_ServerPortFromEnv(t *testing.T) {
	const wantPort = ":8443"

	os.Setenv("SERVER_PORT", wantPort)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != wantPort {
		t.Errorf("ServerPort = %q, want %q", cfg.ServerPort, wantPort)
	}
}

// TestLoad_AllFieldsPresent is a regression guard that ensures no TLS-related
// field is accidentally removed from Config in future refactors.
func TestLoad_AllFieldsPresent(t *testing.T) {
	cfg := Load()

	// Validate that all fields required for a TLS server are non-empty.
	fields := map[string]string{
		"ServerPort":  cfg.ServerPort,
		"TLSCertFile": cfg.TLSCertFile,
		"TLSKeyFile":  cfg.TLSKeyFile,
	}
	for name, val := range fields {
		if val == "" {
			t.Errorf("Config.%s must not be empty after Load()", name)
		}
	}
}
