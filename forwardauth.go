package forwardauth

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func (ForwardAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.authentication.providers.forwardauth",
		New: func() caddy.Module {
			return new(ForwardAuth)
		},
	}
}

func (m *ForwardAuth) Provision(ctx caddy.Context) (err error) {
	m.priv = private{
		trustedProxies: []*net.IPNet{},
	}

	m.priv.address, err = url.Parse(m.Address)
	if err != nil {
		return fmt.Errorf("could not parse forward auth address: %w", err)
	}

	m.priv.client = http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	if m.priv.address.Scheme == "https" && m.TLS != nil {
		tlsClientConfig, err := getTLSConfiguration(m.TLS.CA, m.TLS.Certificate, m.TLS.Key, m.TLS.CAOptional, m.TLS.CAIncludeSystem, m.TLS.InsecureSkipVerify)
		if err != nil {
			return fmt.Errorf("failed to load forward auth: %w", err)
		}

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = tlsClientConfig

		m.priv.client.Transport = transport
	}

	for _, trustedProxy := range m.TrustedProxies {
		_, trustedProxyNet, err := net.ParseCIDR(trustedProxy)
		if err != nil {
			return fmt.Errorf("could not parse trusted proxy %s (must be in CIDR notation): %w", trustedProxy, err)
		}
		m.priv.trustedProxies = append(m.priv.trustedProxies, trustedProxyNet)
	}

	return nil
}

func (m *ForwardAuth) Validate() (err error) {
	if m.priv.address.Scheme != "http" && m.priv.address.Scheme != "https" {
		return fmt.Errorf("forward auth address must have either the http or https scheme")
	}

	return nil
}

func (m ForwardAuth) Authenticate(rw http.ResponseWriter, req *http.Request) (user caddyauth.User, authenticated bool, err error) {
	forwardAuth, err := http.NewRequest(http.MethodGet, m.priv.address.String(), nil)
	if err != nil {
		return user, false, fmt.Errorf("could not perform forward auth request: %w", err)
	}

	setForwardAuthHeaders(req, forwardAuth, m.priv.trustedProxies, m.TrustForwardedHeaders, m.SetXOriginalURL, m.AuthRequestHeaders)

	resp, err := m.priv.client.Do(forwardAuth)
	if err != nil {
		return user, false, fmt.Errorf("failed to make request to %s: %w", m.priv.address.String(), err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return user, false, fmt.Errorf("failed to read body from %s: %w", m.priv.address.String(), err)
	}

	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		proxyHeaders(resp.Header, rw.Header())

		location, err := resp.Location()
		if err != nil {
			if !errors.Is(err, http.ErrNoLocation) {
				return user, false, fmt.Errorf("could not read resp location header %s: %w", m.priv.address.String(), err)
			}
		} else if location.String() != "" {
			rw.Header().Set("Location", location.String())
		}

		rw.WriteHeader(resp.StatusCode)

		_, _ = rw.Write(body)

		return user, false, fmt.Errorf("not authenticated")
	}

	setResponseHeaders(req, resp, m.AuthResponseHeaders)

	req.RequestURI = req.URL.RequestURI()

	return getUserFromHeaders(m.UserHeaders, resp), true, nil
}
