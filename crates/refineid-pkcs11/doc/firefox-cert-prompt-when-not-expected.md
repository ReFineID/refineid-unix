# Why Firefox sometimes prompts for PIN1 on sites you didn't expect

A document of behavior, not a bug. Captured
so the next person who sees a PIN prompt on
`login.microsoftonline.com` or another Microsoft-Entra-federated
SaaS doesn't have to re-derive it.

## What you'll observe

You open a SaaS app whose tenant uses Entra federation. The browser
redirects through `login.microsoftonline.com/<tenant>/saml2`.
Before the tenant's sign-in page renders -- while the status bar
still shows "Looking up device.login.microsoftonline.com..." --
Firefox pops the NSS password dialog for the `Basic (PIN 1)`
token (Finnish: "Perus (PIN 1)"). Typing PIN1 completes the SAML
flow; Cancel generally continues without the cert via Microsoft's
non-cert fallback.

## Why it happens (verified 2026-05-19)

1. Entra's federation pipeline inserts a device-evaluation probe at
   `device.login.microsoftonline.com` early in the SAML flow.
2. That host's TLS handshake sends a `CertificateRequest` with an
   **open** accepted-CA list ("any CA") -- verified with
   `openssl s_client -connect device.login.microsoftonline.com:443`,
   which shows unconstrained `Acceptable client certificate CA names`.
3. Firefox's default `security.default_personal_cert =
   "Select Automatically"` makes NSS auto-pick the FINEID cert --
   usually the only client cert on the system.
4. To produce the `CertificateVerify` signature, NSS calls this
   module's `C_Login`; that is the PIN dialog.

Microsoft is not asking for a FINEID cert specifically; NSS
volunteers it because nothing excludes it.

## Is this a bug in refineid-pkcs11?

No. The module does exactly what PKCS#11 requires: expose the cert
object, accept `C_Login` / `C_Sign` when invoked. PKCS#11 gives the
token no server identity or `CertificateRequest` contents, so the
module cannot filter per-server. The eager-PIN1 rule (see the
`CKO_PROFILE` hard limit in `../src/token.rs`) is satisfied: PIN1
is asked only because a TLS client-auth handshake actually needs
the key -- the citizen just didn't consciously start one.

## What you can do

1. Remove the card from the reader when not signing in to a
   citizen-auth service. No card, no cert, no prompt. This is the
   official answer.
2. Click Cancel; Entra's non-cert fallback generally completes the
   flow (not catalogued for every tenant).
3. Not recommended: flip Firefox's `security.default_personal_cert`
   to `Ask Every Time`. The module must work correctly with stock
   Firefox, so no tool is shipped to set this.

A per-server consent UX cannot live in the PKCS#11 layer alone;
if it ever lands it belongs in a component that owns PIN
prompting. Not in scope.
