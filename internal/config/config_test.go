package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultsDoNotContainTLSPaths verifies that the default config
// intentionally leaves TLS paths empty, forcing operators to supply them
// explicitly via environment variables (fail-secure behaviour).
func TestLoad_DefaultsDoNotContainTLSPaths(t *testing.T) {
	// Ensure the TLS env vars are unset for this test.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty by default, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSPathsReadFromEnv verifies that TLS_CERT_FILE and TLS_KEY_FILE
// environment variables are correctly loaded into the Config struct.
func TestLoad_TLSPathsReadFromEnv(t *testing.T) {
	const wantCert = "/etc/ssl/server.crt"
	const wantKey = "/etc/ssl/server.key"

	os.Setenv("TLS_CERT_FILE", wantCert)
	os.Setenv("TLS_KEY_FILE", wantKey)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile: want %q, got %q", wantCert, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: want %q, got %q", wantKey, cfg.TLSKeyFile)
	}
}

// TestLoad_AllConfigFieldsPresent ensures the Config struct returned by Load
// contains all expected fields, including the new TLS fields introduced to
// support HTTPS (CWE-319 remediation).
func TestLoad_AllConfigFieldsPresent(t *testing.T) {
	cfg := Load()

	// Verify the struct has all required fields (compile-time check via field access).
	_ = cfg.ServerPort
	_ = cfg.CloneDir
	_ = cfg.DownloadDir
	_ = cfg.TLSCertFile
	_ = cfg.TLSKeyFile
}

// TestLoad_ServerPortDefault verifies the default server port is set correctly.
func TestLoad_ServerPortDefault(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected default ServerPort %q, got %q", ":8081", cfg.ServerPort)
	}
}

// TestLoad_ServerPortFromEnv verifies SERVER_PORT is overridable via environment.
func TestLoad_ServerPortFromEnv(t *testing.T) {
	os.Setenv("SERVER_PORT", ":443")
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":443" {
		t.Errorf("expected ServerPort %q, got %q", ":443", cfg.ServerPort)
	}
}
