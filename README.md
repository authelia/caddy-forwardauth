# caddy-forwardauth

A simple implementation of the [Traefik] forward auth spec in a Caddy v2 Module. There are no plans to backport this to 
Caddy v1. This was primarily developed to add support to Authelia for Caddy, however it should work for several other
systems that are compatible with [Traefik]'s forward auth or nginx ngx_http_auth_request_module.

The intention was to copy the configuration options that [Traefik] uses for implementation ease.


[Traefik]: https://traefik.io