package forwardauth

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func proxyHeaders(src http.Header, dst http.Header) {
	for header, value := range src {
		dst[header] = append(dst[header], value...)
	}

	dst.Del(headerConnection)
	dst.Del(headerTE)
	dst.Del(headerKeepAlive)
	dst.Del(headerTrailers)
	dst.Del(headerTransferEncoding)
	dst.Del(headerUpgrade)
}

func getUserFromHeaders(headers UserHeaders, resp *http.Response) (user caddyauth.User) {
	if headers.ID != "" {
		if value := resp.Header.Get(http.CanonicalHeaderKey(headers.ID)); value != "" {
			user.ID = value
		}
	}

	if headers.Name != "" {
		if value := resp.Header.Get(http.CanonicalHeaderKey(headers.Name)); value != "" {
			user.Metadata["name"] = value
		}
	}

	if headers.Groups != "" {
		if value := resp.Header.Get(http.CanonicalHeaderKey(headers.Groups)); value != "" {
			user.Metadata["groups"] = value
		}
	}

	if headers.Emails != "" {
		if value := resp.Header.Get(http.CanonicalHeaderKey(headers.Emails)); value != "" {
			user.Metadata["emails"] = value
		}
	}

	return user
}

func setResponseHeaders(req *http.Request, resp *http.Response, headers []string) {
	for _, h := range headers {
		header := http.CanonicalHeaderKey(h)
		req.Header.Del(header)
		if len(resp.Header[header]) > 0 {
			req.Header[header] = append([]string(nil), resp.Header[header]...)
		}
	}
}

func setForwardAuthHeaders(req, forwardAuth *http.Request, trustedProxies []*net.IPNet, trustXForwardHeaders, setXOriginalURL bool, headerFilter []string) {
	proxyHeaders(req.Header, forwardAuth.Header)

	if len(headerFilter) != 0 {
		headers := http.Header{}

		for _, header := range headerFilter {
			vals := forwardAuth.Header.Values(header)
			if len(vals) > 0 {
				headers[http.CanonicalHeaderKey(header)] = append([]string(nil), vals...)
			}
		}

		forwardAuth.Header = headers
	}

	trusted := trustXForwardHeaders

	strRemoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		remoteIP := net.ParseIP(strRemoteIP)

		trusted = trustXForwardHeaders || isIPInCIDRs(remoteIP, trustedProxies)

		addForwardedFor(strRemoteIP, forwardAuth, trusted)
	}

	setForwardedHeader(headerXForwardedMethod, req, forwardAuth, trusted)
	setForwardedHeader(headerXForwardedProto, req, forwardAuth, trusted)
	setForwardedHeader(headerXForwardedHost, req, forwardAuth, trusted)
	setForwardedHeader(headerXForwardedPort, req, forwardAuth, trusted)
	setForwardedHeader(headerXForwardedURI, req, forwardAuth, trusted)

	if setXOriginalURL {
		valueXOriginalURL := fmt.Sprintf("%s://%s%s", forwardAuth.Header.Get(headerXForwardedProto), forwardAuth.Header.Get(headerXForwardedHost), forwardAuth.Header.Get(headerXForwardedURI))
		forwardAuth.Header.Set(headerXOriginalURL, valueXOriginalURL)
	}
}

func addForwardedFor(ip string, req *http.Request, trusted bool) {
	if trusted {
		if forwardedFor, ok := req.Header[headerXForwardedFor]; ok {
			forwardedFor = append(forwardedFor, ip)
			req.Header.Set(headerXForwardedFor, strings.Join(forwardedFor, ", "))

			return
		}
	}

	req.Header.Set(headerXForwardedFor, ip)
}

func setForwardedHeader(name string, src, dst *http.Request, trusted bool) {
	var fallback string

	switch name {
	case headerXForwardedMethod:
		fallback = src.Method
	case headerXForwardedProto:
		if src.TLS != nil {
			fallback = "https"
		} else {
			fallback = "http"
		}
	case headerXForwardedHost:
		fallback = src.Host
	case headerXForwardedURI:
		fallback = src.URL.RequestURI()
	}

	curXForwardedHeader := src.Header.Get(name)
	switch {
	case trusted && curXForwardedHeader != "":
		dst.Header.Set(name, curXForwardedHeader)
	case fallback != "":
		dst.Header.Set(name, fallback)
	default:
		dst.Header.Del(name)
	}
}
