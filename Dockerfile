ARG VERSION

FROM caddy:${VERSION}-builder as builder

RUN xcaddy build \
    --with github.com/authelia/caddy-forwardauth@0.1.0

FROM caddy:${VERSION}

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
