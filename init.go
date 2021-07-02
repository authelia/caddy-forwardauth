package forwardauth

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	caddy.RegisterModule(ForwardAuth{})
}

// Interface guards
var (
	_ caddy.Provisioner       = (*ForwardAuth)(nil)
	_ caddy.Validator         = (*ForwardAuth)(nil)
	_ caddyauth.Authenticator = (*ForwardAuth)(nil)
)
