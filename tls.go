package forwardauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// getTLSConfiguration returns the util.Config.
func getTLSConfiguration(ca, certificate, key string, caOptional, caIncludeSystem, insecureSkipVerify bool) (config *tls.Config, err error) {
	config = &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		ClientAuth:         tls.NoClientCert,
	}
	config.InsecureSkipVerify = insecureSkipVerify

	if caIncludeSystem {
		config.RootCAs, err = x509.SystemCertPool()
		if err != nil {
			config.RootCAs = x509.NewCertPool()
		}
	} else {
		config.RootCAs = x509.NewCertPool()
	}

	if ca != "" {
		var pemCACerts []byte
		if _, err := os.Stat(ca); err == nil {
			pemCACerts, err = os.ReadFile(ca)
			if err != nil {
				return nil, fmt.Errorf("failed to load ca cert (reading file): %w", err)
			}
		} else {
			pemCACerts = []byte(ca)
		}

		if !config.RootCAs.AppendCertsFromPEM(pemCACerts) {
			return nil, fmt.Errorf("failed to load ca cert (potentially not in PEM format): %w", err)
		}

		if caOptional {
			config.ClientAuth = tls.VerifyClientCertIfGiven
		} else {
			config.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	tlsCert := tls.Certificate{}

	if certificate != "" && key != "" {
		_, certificateErr := os.Stat(certificate)
		_, keyErr := os.Stat(key)

		switch {
		case certificateErr == nil && keyErr == nil:
			tlsCert, err = tls.LoadX509KeyPair(certificate, key)
			if err != nil {
				return nil, fmt.Errorf("failed to load x509 keypair (potentially not in PEM format): %w", err)
			}
		default:
			var (
				certificateBytes []byte
				keyBytes         []byte
			)
			switch {
			case certificateErr != nil && keyErr != nil:
				certificateBytes = []byte(certificate)
				keyBytes = []byte(key)
			case certificateErr == nil && keyErr != nil:
				certificateBytes, err = os.ReadFile(certificate)
				if err != nil {
					return nil, fmt.Errorf("failed to load x509 certificate: %w", err)
				}
				keyBytes = []byte(key)
			case certificateErr != nil && keyErr == nil:
				keyBytes, err = os.ReadFile(key)
				if err != nil {
					return nil, fmt.Errorf("failed to load x509 key: %w", err)
				}
				certificateBytes = []byte(certificate)
			}

			tlsCert, err = tls.X509KeyPair(certificateBytes, keyBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to load x509 keypair (potentially not in PEM format): %w", err)
			}
		}

		config.Certificates = []tls.Certificate{tlsCert}
	}

	return config, nil
}
