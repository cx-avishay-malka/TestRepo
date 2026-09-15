package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultValues verifies that Config.Load() returns sensible defaults
// when no environment variables are set.
func TestLoad_DefaultValues(t *testing.T) {
	// Unset all relevant env vars so defaults are used.
	for _, key := range []string{"SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE"} {
		os.Unsetenv(key)
	}

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("expected non-empty default ServerPort")
	}
	// TLS fields should be empty strings by default (operator must explicitly provide them).
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile default to be empty, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile default to be empty, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsFromEnv verifies that TLS_CERT_FILE and TLS_KEY_FILE
// environment variables are read into the Config struct.
// These are the fields used by ListenAndServeTLS to enable encrypted transport.
func TestLoad_TLSFieldsFromEnv(t *testing.T) {
	const wantCert = "/etc/ssl/certs/server.crt"
	const wantKey = "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", wantCert)
	os.Setenv("TLS_KEY_FILE", wantKey)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile: got %q, want %q", cfg.TLSCertFile, wantCert)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: got %q, want %q", cfg.TLSKeyFile, wantKey)
	}
}

// TestLoad_AllFieldsPresent verifies that all expected Config fields exist and
// are populated, ensuring future refactors don't accidentally drop TLS fields.
func TestLoad_AllFieldsPresent(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	os.Setenv("CLONE_DIR", "/tmp/clones")
	os.Setenv("DOWNLOAD_DIR", "/tmp/downloads")
	os.Setenv("TLS_CERT_FILE", "/certs/server.crt")
	os.Setenv("TLS_KEY_FILE", "/certs/server.key")
	defer func() {
		for _, k := range []string{"SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE"} {
			os.Unsetenv(k)
		}
	}()

	cfg := Load()

	checks := map[string]string{
		"ServerPort":  cfg.ServerPort,
		"CloneDir":    cfg.CloneDir,
		"DownloadDir": cfg.DownloadDir,
		"TLSCertFile": cfg.TLSCertFile,
		"TLSKeyFile":  cfg.TLSKeyFile,
	}
	for field, value := range checks {
		if value == "" {
			t.Errorf("field %s should not be empty when env var is set", field)
		}
	}
}
