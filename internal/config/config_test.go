package config

import (
	"os"
	"testing"
)

// TestLoad_TLSFieldsDefaultToEmpty verifies that TLSCertFile and TLSKeyFile
// are empty strings (not insecure defaults) when the environment variables are
// unset. An empty string will cause http.ListenAndServeTLS to return an error
// rather than silently falling back to plain HTTP.
func TestLoad_TLSFieldsDefaultToEmpty(t *testing.T) {
	// Ensure variables are unset for this test.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty when TLS_CERT_FILE is unset, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty when TLS_KEY_FILE is unset, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsFromEnvironment verifies that TLSCertFile and TLSKeyFile
// are populated from the TLS_CERT_FILE and TLS_KEY_FILE environment variables.
func TestLoad_TLSFieldsFromEnvironment(t *testing.T) {
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
		t.Errorf("TLSCertFile: want %q, got %q", wantCert, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: want %q, got %q", wantKey, cfg.TLSKeyFile)
	}
}

// TestLoad_ServerPortDefault verifies the default server port is preserved.
func TestLoad_ServerPortDefault(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected default ServerPort :8081, got %q", cfg.ServerPort)
	}
}

// TestLoad_ServerPortFromEnvironment verifies that the server port is read
// from the SERVER_PORT environment variable.
func TestLoad_ServerPortFromEnvironment(t *testing.T) {
	const wantPort = ":9443"
	os.Setenv("SERVER_PORT", wantPort)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != wantPort {
		t.Errorf("ServerPort: want %q, got %q", wantPort, cfg.ServerPort)
	}
}

// TestLoad_AllFieldsPresent verifies that all expected fields exist on the
// Config struct so that callers like cmd/server/main.go can pass TLSCertFile
// and TLSKeyFile to http.ListenAndServeTLS without a compile error.
func TestLoad_AllFieldsPresent(t *testing.T) {
	cfg := Load()

	// Accessing the fields causes a compile-time error if they are removed,
	// acting as a regression guard for the TLS fix.
	_ = cfg.TLSCertFile
	_ = cfg.TLSKeyFile
	_ = cfg.ServerPort
	_ = cfg.CloneDir
	_ = cfg.DownloadDir
}
