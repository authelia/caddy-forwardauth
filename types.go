package forwardauth

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
)

type private struct {
	address        *url.URL
	trustedProxies []*net.IPNet
	tlsConfig      *tls.Config
	client         http.Client
}

// ForwardAuth is the main Caddy module representation.
type ForwardAuth struct {
	Address               string   `json:"address"`
	TrustedProxies        []string `json:"trustedProxies"`
	TrustForwardedHeaders bool     `json:"trustForwardedHeaders"`
	SetXOriginalURL       bool     `json:"setXOriginalURL"`

	AuthResponseHeaders []string `json:"authResponseHeaders"`
	AuthRequestHeaders  []string `json:"authRequestHeaders"`

	UserHeaders UserHeaders `json:"userHeaders"`

	TLS *TLSSettings `json:"util"`

	priv private
}

// UserHeaders maps headers to metadata fields for caddy.
type UserHeaders struct {
	ID     string `json:"id"`
	Emails string `json:"emails"`
	Name   string `json:"name"`
	Groups string `json:"groups"`
}

// TLSSettings are settings specific to TLS.
type TLSSettings struct {
	CA                 string `json:"ca"`
	CAOptional         bool   `json:"caOptional"`
	CAIncludeSystem    bool   `json:"caIncludeSystem"`
	Certificate        string `json:"cert"`
	Key                string `json:"key"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`

	Configuration *tls.Config `json:"-"`
}
