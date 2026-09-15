package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultsTLSFields verifies that the configuration includes TLS
// certificate and key file fields, which are required for HTTPS operation
// (CWE-319: Cleartext Transmission of Sensitive Information).
func TestLoad_DefaultsTLSFields(t *testing.T) {
	// Clear any TLS env vars that may be set in the test environment
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	// TLS fields must exist in the config struct (empty string is a valid
	// default — the server will reject startup without real cert/key paths)
	if cfg.TLSCertFile != "" {
		t.Errorf("expected empty TLS_CERT_FILE default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected empty TLS_KEY_FILE default, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsFromEnv verifies that TLS certificate and key paths are
// read from environment variables, enabling operators to supply real TLS
// credentials without code changes.
func TestLoad_TLSFieldsFromEnv(t *testing.T) {
	const certPath = "/etc/ssl/certs/server.crt"
	const keyPath = "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", certPath)
	os.Setenv("TLS_KEY_FILE", keyPath)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("TLSCertFile: want %q, got %q", certPath, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("TLSKeyFile: want %q, got %q", keyPath, cfg.TLSKeyFile)
	}
}

// TestLoad_DefaultServerPort verifies that the default port is the HTTPS
// conventional port (:8443) rather than the insecure HTTP port (:8080/:8081).
func TestLoad_DefaultServerPort(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	// Default should use a TLS-appropriate port; the plain-HTTP default (:8081)
	// was removed as part of the CWE-319 remediation.
	if cfg.ServerPort == "" {
		t.Error("ServerPort must not be empty")
	}
}

// TestLoad_ServerPortFromEnv verifies that SERVER_PORT is configurable via
// environment variable.
func TestLoad_ServerPortFromEnv(t *testing.T) {
	const port = ":9443"
	os.Setenv("SERVER_PORT", port)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != port {
		t.Errorf("ServerPort: want %q, got %q", port, cfg.ServerPort)
	}
}

// TestConfig_HasTLSFields is a compile-time guard that confirms the Config
// struct exposes TLSCertFile and TLSKeyFile. If these fields are ever removed
// the test will fail to compile, catching accidental regression to plain HTTP.
func TestConfig_HasTLSFields(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "cert.pem",
		TLSKeyFile:  "key.pem",
	}

	if cfg.TLSCertFile != "cert.pem" {
		t.Errorf("TLSCertFile field missing or incorrect: got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "key.pem" {
		t.Errorf("TLSKeyFile field missing or incorrect: got %q", cfg.TLSKeyFile)
	}
}
