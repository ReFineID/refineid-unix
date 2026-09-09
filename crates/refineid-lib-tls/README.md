# refineid-lib-tls

Server-authenticated HTTPS client (`simple_https`, backed by rustls
behind the `tls-rustls` feature) for public-infrastructure fetches:
RFC 3161 timestamp authorities, EU trusted lists, validator APIs.

## Contents

- `simple_https.rs` -- the deliberately small HTTPS client: GET/POST,
  bounded response size, optional pre-vetted destination address so the
  caller controls DNS and redirect policy.
- `http.rs` / `framing.rs` -- TLS-agnostic HTTP/1.1 protocol types,
  percent-encoding discipline, cookie scoping, response framing.
- `policy.rs` -- CA-bundle / trust-anchor discovery per platform.

Used by `refineid-client` for its HTTPS needs. No client-certificate
paths live here: the card never enters a TLS handshake in this
workspace.
