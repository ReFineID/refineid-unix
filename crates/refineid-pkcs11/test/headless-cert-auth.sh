#!/usr/bin/env bash
#
# Headless cert-auth comparator -- drives a TLS client-cert-gated
# host via NSS's `tstclnt` against one or two refineid-pkcs11
# builds, with the module's own call log captured. No Firefox
# needed; this is the exact NSS-PKCS#11 path Firefox drives, minus
# the GUI.
#
# ## Why this rig exists
#
# A transport-error-class regression can kill TLS client-cert auth
# with `SSL_ERROR_HANDSHAKE_FAILURE_ALERT` while evading every unit
# test: no unit-level path covers the cross-layer error contract
# between the card transport and the module. This rig reproduces
# that class empirically in ~5 seconds and supports byte-for-byte
# A/B comparison of two builds.
#
# ## Flow per variant
#
#   1. Fresh `sql:` NSS profile in the workdir.
#   2. Built-in CA roots registered (so public CAs validate).
#   3. The variant's librefineid_pkcs11 registered via modutil.
#   4. The card's auth cert pre-imported with certutil -A.
#      HIDDEN GOTCHA: a fresh empty NSS profile cannot enumerate
#      token-resident certs pre-login (the module correctly
#      enforces CKF_LOGIN_REQUIRED). Firefox profiles have the cert
#      cached from past sessions, which is why Firefox "just works"
#      while vanilla tstclnt sees zero certs. Pre-importing the
#      cert mimics an established Firefox profile without a GUI.
#   5. `tstclnt` performs the request; the server's client-cert
#      demand exercises C_Login + C_Sign.
#   6. Captured: module diag log (REFINEID_PKCS11_LOG -- see the
#      Diagnostics section of ../README.md), tstclnt stderr, TLS
#      keys (SSLKEYLOGFILE), HTTP response.
#
# In comparison mode the C_Login/C_Sign log lines of the two
# variants are diffed: an empty diff means a byte-equal sign path,
# which bisects a regression instantly.
#
# ## Env vars
#
#   REFINEID_HARDWARE_TEST=1   (gate) real card + real network.
#   REFINEID_TEST_PIN1         (required) 4-12 digit PIN1. Passed
#                              to tstclnt -w (tstclnt offers no
#                              non-argv channel).
#   REFINEID_CANONICAL_DYLIB   default: <repo>/target/release/
#                              librefineid_pkcs11.{so,dylib}
#   REFINEID_LEGACY_DYLIB      optional known-good build; enables
#                              comparison mode.
#   HOST / PORT                default card.refineid.fi : 443 (any
#                              SSLVerifyClient-require endpoint).
#   REQUEST_PATH               default /
#   NICKNAME                   NSS nickname for the imported cert;
#                              default ReFineID-FINEID-auth.
#   WORKDIR                    default: mktemp -d
#   NSSCKBI                    path to libnssckbi (builtin CA
#                              roots); overrides discovery.
#                              Required on NixOS.
#
# ## Exit codes
#
#   0   variant(s) ran; inspect per-variant PASS/FAIL lines.
#   2   missing pre-req tool or module build.
#   77  hardware gate not opted in.

set -u

if [ "${REFINEID_HARDWARE_TEST:-}" != "1" ]; then
  echo "skip: set REFINEID_HARDWARE_TEST=1 to opt in (real card + network)" >&2
  exit 77
fi

PIN1="${REFINEID_TEST_PIN1:?set REFINEID_TEST_PIN1}"
HOST="${HOST:-card.refineid.fi}"
PORT="${PORT:-443}"
REQUEST_PATH="${REQUEST_PATH:-/}"
NICKNAME="${NICKNAME:-ReFineID-FINEID-auth}"
WORK="${WORKDIR:-$(mktemp -d -t refineid-headless-cert-auth.XXXXXX)}"

# Platform-portable cdylib extension + builtin-CA module location.
case "$(uname -s)" in
  Darwin)
    LIBEXT=dylib
    NSSCKBI_CANDIDATES="/opt/homebrew/opt/nss/lib/libnssckbi.dylib /usr/local/opt/nss/lib/libnssckbi.dylib"
    ;;
  Linux)
    LIBEXT=so
    NSSCKBI_CANDIDATES="/usr/lib/$(uname -m)-linux-gnu/libnssckbi.so /usr/lib64/libnssckbi.so /usr/lib/libnssckbi.so /usr/lib64/nss/libnssckbi.so"
    ;;
  *)
    echo "unsupported platform: $(uname -s)" >&2
    exit 2
    ;;
esac
# NSSCKBI overrides discovery: required on NixOS, where library
# paths are per-package (e.g. "$(nix-build '<nixpkgs>' -A nss --no-out-link)/lib/libnssckbi.so").
if [ -z "${NSSCKBI:-}" ]; then
  for c in $NSSCKBI_CANDIDATES; do
    [ -f "$c" ] && NSSCKBI="$c" && break
  done
fi
[ -n "${NSSCKBI:-}" ] && [ -f "$NSSCKBI" ] || {
  echo "nssckbi (builtin CA roots) not found -- set NSSCKBI=<path to libnssckbi.$LIBEXT>; looked at: $NSSCKBI_CANDIDATES" >&2
  exit 2
}

REPO_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
CANONICAL="${REFINEID_CANONICAL_DYLIB:-$REPO_DIR/target/release/librefineid_pkcs11.$LIBEXT}"
LEGACY="${REFINEID_LEGACY_DYLIB:-}"

for cmd in tstclnt certutil modutil pkcs11-tool; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "missing: $cmd (Fedora: nss-tools opensc; Debian: libnss3-tools opensc; brew: nss opensc)" >&2
    exit 2
  }
done

[ -f "$CANONICAL" ] || {
  echo "canonical module missing: $CANONICAL" >&2
  echo "build first: cargo build --release -p refineid-pkcs11" >&2
  exit 2
}
if [ -n "$LEGACY" ] && [ ! -f "$LEGACY" ]; then
  echo "REFINEID_LEGACY_DYLIB set but not a file: $LEGACY" >&2
  exit 2
fi

mkdir -p "$WORK"

# Extract the FINEID auth cert once (idempotent; the module exposes
# exactly one certificate object, so no --id filter is needed).
AUTH_CERT="$WORK/auth-cert.der"
if [ ! -s "$AUTH_CERT" ]; then
  echo "[setup] extracting FINEID auth cert from card"
  # The module exposes exactly one certificate, but opensc >= 0.27
  # refuses --read-object without an identifier, so discover the
  # CKA_ID first.
  CERT_ID="$(pkcs11-tool --module "$CANONICAL" --list-objects --type cert 2>/dev/null \
    | sed -n 's/^ *ID: *//p' | head -1 | tr -d ':')"
  [ -n "$CERT_ID" ] || {
    echo "[setup] no certificate object found (card present? pcscd running?)" >&2
    exit 2
  }
  pkcs11-tool --module "$CANONICAL" --type cert --id "$CERT_ID" --read-object -o "$AUTH_CERT" >/dev/null 2>&1 || {
    echo "[setup] auth cert extract failed (card present? pcscd running?)" >&2
    exit 2
  }
fi

run_variant() {
  local variant="$1"
  local dylib="$2"
  local profile="$WORK/nss-$variant"
  local cdy_log="$WORK/$variant-cdylib.log"
  local tls_log="$WORK/$variant-tstclnt.log"
  local body="$WORK/$variant-body.bin"

  rm -rf "$profile" "$cdy_log" "$tls_log" "$body"
  mkdir -p "$profile"

  echo "############################################################"
  echo "### variant: $variant"
  echo "### dylib:   $dylib"
  echo "############################################################"

  certutil -N -d "sql:$profile" --empty-password
  modutil -dbdir "sql:$profile" -add 'Builtin Roots' \
    -libfile "$NSSCKBI" -force 2>&1 | tail -1
  modutil -dbdir "sql:$profile" -add 'ReFineID' -libfile "$dylib" -force 2>&1 | tail -1

  certutil -A -d "sql:$profile" -n "$NICKNAME" -t "u,u,u" -i "$AUTH_CERT" 2>&1 | tail -1

  local req="$WORK/req.txt"
  printf 'GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: refineid-headless-cert-auth/2\r\nAccept: */*\r\nConnection: close\r\n\r\n' \
    "$REQUEST_PATH" "$HOST" > "$req"

  REFINEID_PKCS11_LOG="$cdy_log" \
  SSLKEYLOGFILE="$WORK/$variant-sslkey.log" \
    tstclnt -h "$HOST" -p "$PORT" \
      -d "sql:$profile" \
      -n "$NICKNAME" \
      -w "$PIN1" \
      -A "$req" \
      < /dev/null \
      > "$body" 2> "$tls_log"
  local rc=$?
  echo "tstclnt exit=$rc"

  if [ "$rc" -eq 0 ] && grep -q '^HTTP/1\.[01] ' "$body" 2>/dev/null \
     && grep -q 'C_Sign rv=0x0000' "$cdy_log" 2>/dev/null; then
    echo "result: PASS  (handshake + card signature + HTTP response)"
    head -1 "$body"
  else
    echo "result: FAIL"
    echo "--- tstclnt stderr tail ---"
    tail -10 "$tls_log"
    echo "--- module login/sign tail ---"
    grep -E 'C_Login|C_Sign' "$cdy_log" 2>/dev/null | tail -10
  fi
  echo
}

run_variant "canonical" "$CANONICAL"
if [ -n "$LEGACY" ]; then
  run_variant "legacy" "$LEGACY"
  echo "### sign-flow diff (legacy vs canonical) -- empty diff = byte-equal sign path"
  diff <(grep -oE 'C_(Login|Sign).*' "$WORK"/legacy-cdylib.log 2>/dev/null) \
       <(grep -oE 'C_(Login|Sign).*' "$WORK"/canonical-cdylib.log 2>/dev/null) \
    | head -20 || true
fi

echo "### artifacts under $WORK/"
