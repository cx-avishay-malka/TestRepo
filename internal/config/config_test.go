package config

import (
	"os"
	"testing"
)

// TestLoad_TLSFieldsDefaultToEmpty verifies that TLS cert and key paths default to
// empty strings when the environment variables are not set, ensuring the server will
// not silently fall back to plain HTTP (ListenAndServeTLS returns an error when paths
// are empty, preventing an insecure startup).
func TestLoad_TLSFieldsDefaultToEmpty(t *testing.T) {
	// Ensure env vars are not set
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to default to empty string, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to default to empty string, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsFromEnv verifies that TLS cert and key paths are read from
// environment variables so operators can supply production certificates without
// modifying source code.
func TestLoad_TLSFieldsFromEnv(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/etc/ssl/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/ssl/server.key")
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != "/etc/ssl/server.crt" {
		t.Errorf("expected TLSCertFile %q, got %q", "/etc/ssl/server.crt", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/ssl/server.key" {
		t.Errorf("expected TLSKeyFile %q, got %q", "/etc/ssl/server.key", cfg.TLSKeyFile)
	}
}

// TestLoad_DefaultServerPort verifies that the default server port is still set
// correctly after adding the TLS fields to Config.
func TestLoad_DefaultServerPort(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected ServerPort %q, got %q", ":8081", cfg.ServerPort)
	}
}

// TestLoad_ServerPortFromEnv verifies that the server port can be overridden via
// an environment variable.
func TestLoad_ServerPortFromEnv(t *testing.T) {
	os.Setenv("SERVER_PORT", ":443")
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":443" {
		t.Errorf("expected ServerPort %q, got %q", ":443", cfg.ServerPort)
	}
}
