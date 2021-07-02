package forwardauth

const (
	headerXForwardedFor = "X-Forwarded-For"
	headerXOriginalURL  = "X-Original-URL"

	headerXForwardedMethod = "X-Forwarded-Method"
	headerXForwardedProto  = "X-Forwarded-Proto"
	headerXForwardedHost   = "X-Forwarded-Host"
	headerXForwardedPort   = "X-Forwarded-Port"
	headerXForwardedURI    = "X-Forwarded-URI"

	headerConnection       = "Connection"
	headerTE               = "Te"
	headerKeepAlive        = "Keep-Alive"
	headerTrailers         = "Trailers"
	headerTransferEncoding = "Transfer-Encoding"
	headerUpgrade          = "Upgrade"
)
