package config

import (
	"os"
	"testing"
)

// TestTLSEnabled verifies that TLSEnabled returns true only when both
// TLSCertFile and TLSKeyFile are non-empty, ensuring the server enforces
// encrypted transport (CWE-319 prevention).
func TestTLSEnabled(t *testing.T) {
	tests := []struct {
		name     string
		certFile string
		keyFile  string
		want     bool
	}{
		{
			name:     "both cert and key set returns true",
			certFile: "/path/to/cert.pem",
			keyFile:  "/path/to/key.pem",
			want:     true,
		},
		{
			name:     "only cert set returns false",
			certFile: "/path/to/cert.pem",
			keyFile:  "",
			want:     false,
		},
		{
			name:     "only key set returns false",
			certFile: "",
			keyFile:  "/path/to/key.pem",
			want:     false,
		},
		{
			name:     "neither cert nor key set returns false",
			certFile: "",
			keyFile:  "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				TLSCertFile: tt.certFile,
				TLSKeyFile:  tt.keyFile,
			}
			got := cfg.TLSEnabled()
			if got != tt.want {
				t.Errorf("TLSEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLoadDefaultPort verifies that the default server port is the HTTPS port
// (:8443), not a plain HTTP port, preventing accidental plain-text serving.
func TestLoadDefaultPort(t *testing.T) {
	// Ensure environment variable is not set so defaults are exercised.
	os.Unsetenv("SERVER_PORT")
	cfg := Load()
	if cfg.ServerPort != ":8443" {
		t.Errorf("default ServerPort = %q, want %q (HTTPS port)", cfg.ServerPort, ":8443")
	}
}

// TestLoadTLSFromEnvironment verifies that TLS cert/key paths are loaded
// from environment variables, allowing secure deployment without hardcoded paths.
func TestLoadTLSFromEnvironment(t *testing.T) {
	const wantCert = "/etc/ssl/certs/server.pem"
	const wantKey = "/etc/ssl/private/server.key"

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
	if !cfg.TLSEnabled() {
		t.Error("TLSEnabled() = false after setting both TLS env vars, want true")
	}
}

// TestLoadTLSNotSetByDefault verifies that TLS is NOT silently enabled with
// hardcoded certificate paths — the operator must explicitly configure them.
func TestLoadTLSNotSetByDefault(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("TLSCertFile default should be empty, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("TLSKeyFile default should be empty, got %q", cfg.TLSKeyFile)
	}
	// TLSEnabled() must return false so the server startup logic enforces the
	// requirement instead of silently falling through with no TLS.
	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() = true when no env vars are set, want false")
	}
}

// TestLoadServerPortOverride verifies the SERVER_PORT env var is respected.
func TestLoadServerPortOverride(t *testing.T) {
	const wantPort = ":9443"
	os.Setenv("SERVER_PORT", wantPort)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()
	if cfg.ServerPort != wantPort {
		t.Errorf("ServerPort = %q, want %q", cfg.ServerPort, wantPort)
	}
}

// TestLoadCloneDirDefault verifies that the default clone directory does not
// contain a hardcoded user home path (e.g. /Users/benalvo/…).
func TestLoadCloneDirDefault(t *testing.T) {
	os.Unsetenv("CLONE_DIR")
	cfg := Load()
	if cfg.CloneDir == "" {
		t.Error("CloneDir should not be empty")
	}
	// Ensure no developer-specific path leaked into the default.
	if cfg.CloneDir == "/Users/benalvo/clones" {
		t.Errorf("CloneDir default %q is a hardcoded developer path", cfg.CloneDir)
	}
}

// TestLoadDownloadDirDefault verifies that the default download directory does
// not contain a hardcoded user home path.
func TestLoadDownloadDirDefault(t *testing.T) {
	os.Unsetenv("DOWNLOAD_DIR")
	cfg := Load()
	if cfg.DownloadDir == "" {
		t.Error("DownloadDir should not be empty")
	}
	if cfg.DownloadDir == "/Users/benalvo/downloads" {
		t.Errorf("DownloadDir default %q is a hardcoded developer path", cfg.DownloadDir)
	}
}
