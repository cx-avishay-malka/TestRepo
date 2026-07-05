package config

import "os"

// Config holds application configuration
type Config struct {
	ServerPort  string
	CloneDir    string
	DownloadDir string
	// TLSCertFile and TLSKeyFile enable HTTPS when both are set.
	// Set via TLS_CERT_FILE and TLS_KEY_FILE environment variables.
	TLSCertFile string
	TLSKeyFile  string
}

// Load loads configuration from environment variables or defaults
func Load() *Config {
	return &Config{
		ServerPort:  getEnv("SERVER_PORT", ":8443"),
		CloneDir:    getEnv("CLONE_DIR", "/tmp/clones"),
		DownloadDir: getEnv("DOWNLOAD_DIR", "/tmp/downloads"),
		TLSCertFile: os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("TLS_KEY_FILE"),
	}
}

// TLSEnabled returns true when both a certificate file and a key file are configured.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
