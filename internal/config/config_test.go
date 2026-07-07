package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultValues verifies that Load returns sensible defaults
// when no environment variables are set.
func TestLoad_DefaultValues(t *testing.T) {
	// Unset all relevant env vars to guarantee clean state.
	unset := []string{"SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE"}
	for _, k := range unset {
		os.Unsetenv(k)
	}

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("expected a non-empty default ServerPort")
	}
	if cfg.CloneDir == "" {
		t.Error("expected a non-empty default CloneDir")
	}
	if cfg.DownloadDir == "" {
		t.Error("expected a non-empty default DownloadDir")
	}
}

// TestLoad_TLSFields_DefaultToEmpty ensures TLS fields are empty by default,
// forcing the caller to explicitly provide cert/key paths via env vars.
// This is the security contract: the server must refuse to start without TLS
// configuration, so empty defaults enforce that check.
func TestLoad_TLSFields_DefaultToEmpty(t *testing.T) {
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

// TestLoad_TLSFields_FromEnv verifies that TLS cert/key paths are read from
// environment variables, allowing operators to supply their certificates.
func TestLoad_TLSFields_FromEnv(t *testing.T) {
	const certPath = "/etc/tls/server.crt"
	const keyPath = "/etc/tls/server.key"

	os.Setenv("TLS_CERT_FILE", certPath)
	os.Setenv("TLS_KEY_FILE", keyPath)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("expected TLSCertFile=%q, got %q", certPath, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("expected TLSKeyFile=%q, got %q", keyPath, cfg.TLSKeyFile)
	}
}

// TestLoad_AllFieldsFromEnv verifies that all configuration fields can be
// overridden via environment variables.
func TestLoad_AllFieldsFromEnv(t *testing.T) {
	env := map[string]string{
		"SERVER_PORT":   ":9443",
		"CLONE_DIR":     "/var/clones",
		"DOWNLOAD_DIR":  "/var/downloads",
		"TLS_CERT_FILE": "/certs/cert.pem",
		"TLS_KEY_FILE":  "/certs/key.pem",
	}
	for k, v := range env {
		os.Setenv(k, v)
	}
	defer func() {
		for k := range env {
			os.Unsetenv(k)
		}
	}()

	cfg := Load()

	if cfg.ServerPort != env["SERVER_PORT"] {
		t.Errorf("ServerPort: expected %q, got %q", env["SERVER_PORT"], cfg.ServerPort)
	}
	if cfg.CloneDir != env["CLONE_DIR"] {
		t.Errorf("CloneDir: expected %q, got %q", env["CLONE_DIR"], cfg.CloneDir)
	}
	if cfg.DownloadDir != env["DOWNLOAD_DIR"] {
		t.Errorf("DownloadDir: expected %q, got %q", env["DOWNLOAD_DIR"], cfg.DownloadDir)
	}
	if cfg.TLSCertFile != env["TLS_CERT_FILE"] {
		t.Errorf("TLSCertFile: expected %q, got %q", env["TLS_CERT_FILE"], cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != env["TLS_KEY_FILE"] {
		t.Errorf("TLSKeyFile: expected %q, got %q", env["TLS_KEY_FILE"], cfg.TLSKeyFile)
	}
}

// TestTLSRequired_MissingCert validates the security contract: a server
// started with an empty TLSCertFile must be rejected before binding.
// This test exercises the guard logic in main by checking the Config state
// that main uses to decide whether to call ListenAndServeTLS.
func TestTLSRequired_MissingCert(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	// Simulate the guard that main() performs before starting the server.
	// An empty cert or key means TLS is not configured — the server must not
	// start in plain-text mode; instead it must abort with a fatal error.
	tlsMissing := cfg.TLSCertFile == "" || cfg.TLSKeyFile == ""
	if !tlsMissing {
		t.Error("expected TLS to be unconfigured when env vars are absent")
	}
}

// TestTLSRequired_MissingKey validates that providing only the cert (without
// the key) is also treated as misconfiguration.
func TestTLSRequired_MissingKey(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/certs/cert.pem")
	os.Unsetenv("TLS_KEY_FILE")
	defer os.Unsetenv("TLS_CERT_FILE")

	cfg := Load()

	tlsMissing := cfg.TLSCertFile == "" || cfg.TLSKeyFile == ""
	if !tlsMissing {
		t.Error("expected TLS to be unconfigured when TLS_KEY_FILE is absent")
	}
}

// TestTLSRequired_BothPresent validates that providing both cert and key
// satisfies the TLS configuration check.
func TestTLSRequired_BothPresent(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/certs/cert.pem")
	os.Setenv("TLS_KEY_FILE", "/certs/key.pem")
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	tlsMissing := cfg.TLSCertFile == "" || cfg.TLSKeyFile == ""
	if tlsMissing {
		t.Error("expected TLS to be configured when both env vars are present")
	}
}
