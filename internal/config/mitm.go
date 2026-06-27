package config

import (
	"errors"
	"fmt"
	"os"
)

// MITMConfig configures opt-in HTTPS interception (man-in-the-middle) for
// traffic debugging. It is DISABLED by default.
//
// SECURITY WARNING: when enabled the proxy decrypts TLS traffic by minting leaf
// certificates signed by the configured CA. The CA private key can impersonate
// any site to trusting clients. Only enable in controlled debugging
// environments with a dedicated throwaway CA; never reuse a production CA.
type MITMConfig struct {
	// Enabled turns interception on. Default false.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// CACertFile and CAKeyFile point at the PEM signing CA certificate and key.
	// Both are required when Enabled is true.
	CACertFile string `yaml:"ca_cert_file" json:"ca_cert_file"`
	CAKeyFile  string `yaml:"ca_key_file" json:"ca_key_file"`

	// LeafTTL is the validity period of minted leaf certificates. Zero defaults
	// to 24h.
	LeafTTL Duration `yaml:"leaf_ttl" json:"leaf_ttl"`

	// MaxCachedCerts bounds the in-memory leaf certificate cache (0 = default).
	MaxCachedCerts int `yaml:"max_cached_certs" json:"max_cached_certs"`
}

var (
	errMITMCACertRequired = errors.New("mitm: enabled but ca_cert_file is empty")
	errMITMCAKeyRequired  = errors.New("mitm: enabled but ca_key_file is empty")
)

// Validate checks the MITM configuration. When disabled it always passes. When
// enabled it requires both CA file paths to be set so a misconfiguration fails
// closed at load time rather than silently disabling interception.
func (c MITMConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.CACertFile == "" {
		return errMITMCACertRequired
	}
	if c.CAKeyFile == "" {
		return errMITMCAKeyRequired
	}
	return nil
}

// LoadCA reads the configured CA certificate and key PEM files. It returns an
// error if MITM is disabled (callers should check Enabled first) or if either
// file cannot be read.
func (c MITMConfig) LoadCA() (certPEM, keyPEM []byte, err error) {
	if !c.Enabled {
		return nil, nil, errors.New("mitm: disabled")
	}
	if verr := c.Validate(); verr != nil {
		return nil, nil, verr
	}
	certPEM, err = os.ReadFile(c.CACertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("mitm: read ca_cert_file: %w", err)
	}
	keyPEM, err = os.ReadFile(c.CAKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("mitm: read ca_key_file: %w", err)
	}
	return certPEM, keyPEM, nil
}
