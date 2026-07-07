package config

import (
	"os"
	"testing"
)

// TestLoadDefaultValues verifies that default configuration values are set correctly.
func TestLoadDefaultValues(t *testing.T) {
	// Ensure no relevant env vars are set during this test
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("CLONE_DIR")
	os.Unsetenv("DOWNLOAD_DIR")
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	// Default port should be the HTTPS port, not plain HTTP
	if cfg.ServerPort != ":8443" {
		t.Errorf("expected default ServerPort ':8443', got '%s'", cfg.ServerPort)
	}

	// TLS fields should default to empty strings (requiring explicit configuration)
	if cfg.TLSCertFile != "" {
		t.Errorf("expected default TLSCertFile to be empty, got '%s'", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected default TLSKeyFile to be empty, got '%s'", cfg.TLSKeyFile)
	}
}

// TestLoadFromEnvVars verifies that configuration is correctly loaded from environment variables.
func TestLoadFromEnvVars(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	os.Setenv("TLS_CERT_FILE", "/path/to/cert.pem")
	os.Setenv("TLS_KEY_FILE", "/path/to/key.pem")
	os.Setenv("CLONE_DIR", "/tmp/clones")
	os.Setenv("DOWNLOAD_DIR", "/tmp/downloads")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
		os.Unsetenv("CLONE_DIR")
		os.Unsetenv("DOWNLOAD_DIR")
	}()

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort ':9443', got '%s'", cfg.ServerPort)
	}
	if cfg.TLSCertFile != "/path/to/cert.pem" {
		t.Errorf("expected TLSCertFile '/path/to/cert.pem', got '%s'", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/path/to/key.pem" {
		t.Errorf("expected TLSKeyFile '/path/to/key.pem', got '%s'", cfg.TLSKeyFile)
	}
	if cfg.CloneDir != "/tmp/clones" {
		t.Errorf("expected CloneDir '/tmp/clones', got '%s'", cfg.CloneDir)
	}
	if cfg.DownloadDir != "/tmp/downloads" {
		t.Errorf("expected DownloadDir '/tmp/downloads', got '%s'", cfg.DownloadDir)
	}
}

// TestTLSFieldsExist verifies that the Config struct contains TLS configuration fields,
// which are required for CWE-319 remediation (no plaintext transport).
func TestTLSFieldsExist(t *testing.T) {
	cfg := &Config{}

	// Assign TLS fields to verify they exist on the struct (compilation check)
	cfg.TLSCertFile = "/etc/ssl/cert.pem"
	cfg.TLSKeyFile = "/etc/ssl/key.pem"

	if cfg.TLSCertFile != "/etc/ssl/cert.pem" {
		t.Error("TLSCertFile field not settable on Config struct")
	}
	if cfg.TLSKeyFile != "/etc/ssl/key.pem" {
		t.Error("TLSKeyFile field not settable on Config struct")
	}
}

// TestTLSConfigEmptyByDefault verifies that TLS paths are empty by default,
// forcing operators to explicitly configure TLS rather than having insecure defaults.
func TestTLSConfigEmptyByDefault(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	// Empty TLS paths ensure the server refuses to start without explicit TLS config,
	// preventing accidental plaintext HTTP deployment (CWE-319).
	if cfg.TLSCertFile != "" {
		t.Errorf("TLSCertFile should be empty when TLS_CERT_FILE is not set; got '%s'", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("TLSKeyFile should be empty when TLS_KEY_FILE is not set; got '%s'", cfg.TLSKeyFile)
	}
}
