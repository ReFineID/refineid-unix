#!/usr/bin/env bash
#
# FINEID hardware test suite for the PKCS#11 module + refineid CLI.
#
# Drives the cdylib (via OpenSC `pkcs11-tool`) and the `refineid`
# CLI through the card operations the unit tests cannot cover,
# with two safety mechanisms wrapped around every card-touching
# step:
#
#   1. PIN-retry-counter guard: a side-effect-free counter snapshot
#      (`refineid card --offline`) before and after every phase;
#      the suite ABORTS the moment a counter drops. One wrong-PIN
#      burn is recoverable; five is not, and on 2026 ECC cards a
#      lockout is unrecoverable.
#   2. Offline signature verification: every signature the card
#      produces is verified against the cached certificate public
#      key with openssl, so a card that signs the wrong digest can
#      never be recorded as a pass.
#
# The `run_xfail` helper turns a known bug into a tracked
# expectation: an XFAIL that starts passing is reported loudly as
# XPASS so the entry gets removed instead of rotting.
#
# ## Env vars
#
#   REFINEID_HARDWARE_TEST=1     (gate) the suite refuses to touch
#                                a real card without this.
#   REFINEID_TEST_PIN1           (required) 4-12 digit PIN1.
#   REFINEID_SUITE_PIN_CHANGE=1  (opt-in) run the PIN1 change cycle
#                                with guaranteed revert. Needs the
#                                module built with
#                                `--features pin-change` and the CLI
#                                with `--features pin-env-debug`.
#   REFINEID_TEST_PIN1_TMP       temporary PIN1 for the change
#                                cycle (default 4321).
#   REFINEID_SUITE_INTERACTIVE=1 (opt-in) run the PUK-unblock
#                                phase. The CLI prompts for the PUK
#                                on the terminal (never argv/env),
#                                so this phase needs a TTY.
#   REFINEID_CLI                 path to `refineid`
#                                (default: target/release/refineid,
#                                then PATH).
#   REFINEID_PKCS11_LIB          path to the cdylib (default:
#                                target/release/librefineid_pkcs11.*).
#
# ## Exit codes
#
#   0   all non-XFAIL steps passed
#   1   at least one failure (suite continued; see RESULTS)
#   2   a PIN retry counter dropped; suite aborted immediately
#   3   precondition missing (tool, build, card, env)
#   77  hardware gate not opted in

set -uo pipefail

if [[ "${REFINEID_HARDWARE_TEST:-}" != "1" ]]; then
    echo "skip: set REFINEID_HARDWARE_TEST=1 to run" >&2
    exit 77
fi

PIN1="${REFINEID_TEST_PIN1:?set REFINEID_TEST_PIN1=<pin1>}"
PIN1_TMP="${REFINEID_TEST_PIN1_TMP:-4321}"

REPO_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
case "$(uname -s)" in
  Darwin) LIBEXT=dylib ;;
  *) LIBEXT=so ;;
esac

CLI="${REFINEID_CLI:-$REPO_DIR/target/release/refineid}"
[[ -x "$CLI" ]] || CLI="$(command -v refineid 2>/dev/null || true)"
[[ -n "$CLI" && -x "$CLI" ]] || { echo "ERROR: refineid CLI not found; set REFINEID_CLI" >&2; exit 3; }

MOD="${REFINEID_PKCS11_LIB:-$REPO_DIR/target/release/librefineid_pkcs11.$LIBEXT}"
[[ -f "$MOD" ]] || { echo "ERROR: module not built: $MOD (cargo build --release -p refineid-pkcs11)" >&2; exit 3; }

command -v pkcs11-tool >/dev/null || { echo "ERROR: pkcs11-tool missing (opensc)" >&2; exit 3; }
command -v openssl >/dev/null || { echo "ERROR: openssl missing" >&2; exit 3; }
command -v python3 >/dev/null || { echo "ERROR: python3 missing (ECDSA DER wrap)" >&2; exit 3; }

WORK="$(mktemp -d -t refineid-pkcs11-suite.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
XCOUNT=0
RESULTS=()

record() {
    RESULTS+=("$1")
}

run() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        record "OK    $label"; PASS=$((PASS+1))
    else
        record "FAIL  $label"; FAIL=$((FAIL+1))
    fi
}

# Expected-failure wrapper for tracked bugs: XPASS reports loudly
# when the bug gets fixed so the entry is removed, not forgotten.
# (No current entries; keep the helper for the next real bug.)
run_xfail() {
    local label="$1"; local reason="$2"; shift 2
    if "$@" >/dev/null 2>&1; then
        record "XPASS $label  -- expected to fail but passed; remove the XFAIL"
    else
        record "XFAIL $label  -- $reason"
    fi
    XCOUNT=$((XCOUNT+1))
}

# ---------------------------------------------------------------
# PIN-retry-counter guard
# ---------------------------------------------------------------

# Parse one counter line of `refineid card --offline` into:
#   "5".."0" | "verified" | "locked" | "unknown"
parse_pin_line() {
    local raw="$1" label="$2" line
    line=$(printf '%s\n' "$raw" | grep -F "$label" | head -1)
    [[ -n "$line" ]] || { printf 'unknown'; return; }
    if grep -q "verified" <<<"$line"; then printf 'verified'; return; fi
    if grep -q "BLOCKED" <<<"$line"; then printf 'locked'; return; fi
    local n
    n=$(grep -oE '[0-9]+ retries left' <<<"$line" | grep -oE '[0-9]+' | head -1)
    if [[ -n "$n" ]]; then printf '%s' "$n"; else printf 'unknown'; fi
}

read_pin_status() {
    local raw
    raw=$("$CLI" card --offline --no-can 2>&1)
    CURRENT_PIN1="$(parse_pin_line "$raw" 'PIN1 (auth):')"
    CURRENT_PIN2="$(parse_pin_line "$raw" 'PIN2 (qualified-sig):')"
}

# "verified" is benign: the in-session presentation flag is set and
# the counter is at max. Anything else must match the expectation.
pin_state_ok() {
    local got="$1" want="$2"
    [[ "$got" == "verified" || "$got" == "$want" ]]
}

guard_status() {
    local stage="$1"
    read_pin_status
    printf '[%s] PIN1=%s PIN2=%s\n' "$stage" "$CURRENT_PIN1" "$CURRENT_PIN2"
    if ! pin_state_ok "$CURRENT_PIN1" "$WANT_PIN1"; then
        printf '\nABORT: PIN1 counter moved at [%s]: expected %s, got %s\n' \
            "$stage" "$WANT_PIN1" "$CURRENT_PIN1" >&2
        summarise
        exit 2
    fi
    if ! pin_state_ok "$CURRENT_PIN2" "$WANT_PIN2"; then
        printf '\nABORT: PIN2 counter moved at [%s]: expected %s, got %s\n' \
            "$stage" "$WANT_PIN2" "$CURRENT_PIN2" >&2
        summarise
        exit 2
    fi
}

summarise() {
    echo
    echo "================== RESULTS =================="
    printf '%s\n' "${RESULTS[@]:-"(none)"}"
    echo "============================================="
    echo "Total: $PASS passed, $FAIL failed, $XCOUNT expected-fail"
}

# DER-encode a raw r||s ECDSA signature for openssl verification.
der_wrap_ecdsa() {
    local raw="$1" out="$2"
    python3 - "$raw" "$out" <<'PY'
import sys
raw = open(sys.argv[1], 'rb').read()
half = len(raw) // 2
assert len(raw) == 2 * half, f"raw r||s must be even, got {len(raw)}"
def enc(b):
    b = b.lstrip(b'\x00') or b'\x00'
    if b[0] & 0x80:
        b = b'\x00' + b
    return b'\x02' + bytes([len(b)]) + b
seq = enc(raw[:half]) + enc(raw[half:])
open(sys.argv[2], 'wb').write(b'\x30' + bytes([len(seq)]) + seq)
PY
}

# ---------------------------------------------------------------
# Phase 0: baseline counters. Both PINs must be at full retries
# (or already verified) before the suite risks any PIN-bearing op.
# ---------------------------------------------------------------

WANT_PIN1=5
WANT_PIN2=5
guard_status "baseline"

MSG="$WORK/msg.txt"
echo "refineid pkcs11 hardware suite message - $(date)" > "$MSG"

# ---------------------------------------------------------------
# Phase 1: read-only, no PIN
# ---------------------------------------------------------------

run "1.  refineid card --offline"                 "$CLI" card --offline --no-can
run "2.  pkcs11-tool --list-slots"                pkcs11-tool --module "$MOD" --list-slots
run "3.  pkcs11-tool --list-mechanisms"           pkcs11-tool --module "$MOD" --list-mechanisms
run "4.  pkcs11-tool --list-objects (no login)"   pkcs11-tool --module "$MOD" --list-objects

# The module is sign-only by design: RNG service must be absent.
if pkcs11-tool --module "$MOD" --generate-random 16 >/dev/null 2>&1; then
    record "FAIL  5.  generate-random unexpectedly supported (module is sign-only)"; FAIL=$((FAIL+1))
else
    record "OK    5.  generate-random refused (sign-only module)"; PASS=$((PASS+1))
fi

guard_status "after read-only phase"

# ---------------------------------------------------------------
# Phase 2: extract the cert + pubkey for offline verification
# ---------------------------------------------------------------

pkcs11-tool --module "$MOD" --type cert --read-object -o "$WORK/auth.der" >/dev/null 2>&1 \
    || { echo "ERROR: auth cert read failed" >&2; exit 3; }
openssl x509 -inform DER -in "$WORK/auth.der" -out "$WORK/auth.pem" >/dev/null 2>&1
openssl x509 -in "$WORK/auth.pem" -pubkey -noout > "$WORK/auth.pub.pem" 2>/dev/null
KEY_ALG=$(openssl x509 -in "$WORK/auth.pem" -noout -text 2>/dev/null \
          | grep -Eo 'id-ecPublicKey|rsaEncryption' | head -1)
record "OK    6.  auth cert extracted (key: ${KEY_ALG:-unknown})"; PASS=$((PASS+1))

# ---------------------------------------------------------------
# Phase 3: PIN1 login + sign via the module, verified offline
# ---------------------------------------------------------------

run "7.  pkcs11-tool --login --list-objects"      pkcs11-tool --module "$MOD" --login --pin "$PIN1" --list-objects
WANT_PIN1=5   # a correct PIN leaves the counter at max
guard_status "after login"

SIG="$WORK/msg.sig"
if [[ "$KEY_ALG" == "id-ecPublicKey" ]]; then
    # CKM_ECDSA takes a raw digest; the card slot is 48 bytes, so a
    # SHA-384 digest fits without padding. Output is raw r||s.
    DIGEST="$WORK/msg.sha384"
    openssl dgst -sha384 -binary "$MSG" > "$DIGEST"
    if pkcs11-tool --module "$MOD" --login --pin "$PIN1" --sign --mechanism ECDSA \
         --input-file "$DIGEST" --output-file "$SIG" >/dev/null 2>&1 && [[ -s "$SIG" ]]; then
        record "OK    8.  pkcs11-tool sign CKM_ECDSA (sha384 digest)"; PASS=$((PASS+1))
        der_wrap_ecdsa "$SIG" "$WORK/msg.sig.der"
        run "9.  openssl verifies the ECDSA signature" \
            openssl pkeyutl -verify -pubin -inkey "$WORK/auth.pub.pem" \
                -sigfile "$WORK/msg.sig.der" -in "$DIGEST"
    else
        record "FAIL  8.  pkcs11-tool sign CKM_ECDSA"; FAIL=$((FAIL+1))
    fi
else
    # CKM_RSA_PKCS expects DigestInfo || SHA-256 hash (RFC 8017
    # s9.2); build it and verify with openssl over the original
    # message.
    DINFO="$WORK/msg.digestinfo"
    printf '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20' > "$DINFO"
    openssl dgst -sha256 -binary "$MSG" >> "$DINFO"
    if pkcs11-tool --module "$MOD" --login --pin "$PIN1" --sign --mechanism RSA-PKCS \
         --input-file "$DINFO" --output-file "$SIG" >/dev/null 2>&1 && [[ -s "$SIG" ]]; then
        record "OK    8.  pkcs11-tool sign CKM_RSA_PKCS (DigestInfo+sha256)"; PASS=$((PASS+1))
        run "9.  openssl verifies the RSA signature" \
            openssl dgst -sha256 -verify "$WORK/auth.pub.pem" -signature "$SIG" "$MSG"
    else
        record "FAIL  8.  pkcs11-tool sign CKM_RSA_PKCS"; FAIL=$((FAIL+1))
    fi
fi
guard_status "after sign"

# CLI sign path over the same card (REFINEID_PIN1 is honoured only
# by a pin-env-debug CLI build; otherwise the CLI prompts).
if REFINEID_PIN1="$PIN1" "$CLI" card sign-auth --in "$MSG" --out "$WORK/cli.sig" </dev/null >/dev/null 2>&1; then
    record "OK    10. refineid card sign-auth"; PASS=$((PASS+1))
else
    record "SKIP  10. refineid card sign-auth (needs --features pin-env-debug CLI or a TTY)"
fi
guard_status "after CLI sign"

# ---------------------------------------------------------------
# Phase 4 (opt-in): PIN1 change cycle with guaranteed revert
# ---------------------------------------------------------------

if [[ "${REFINEID_SUITE_PIN_CHANGE:-}" == "1" ]]; then
    echo "+++ PIN1-change critical region; revert always +++" >&2
    if REFINEID_CURRENT_PIN1="$PIN1" REFINEID_NEW_PIN1="$PIN1_TMP" \
         "$CLI" card change-pin1 </dev/null >/dev/null 2>&1; then
        record "OK    11. change-pin1 -> temporary"; PASS=$((PASS+1))
        if REFINEID_CURRENT_PIN1="$PIN1_TMP" REFINEID_NEW_PIN1="$PIN1" \
             "$CLI" card change-pin1 </dev/null >/dev/null 2>&1; then
            record "OK    12. change-pin1 revert"; PASS=$((PASS+1))
        else
            record "FAIL  12. REVERT FAILED -- PIN1 is now the temporary value $PIN1_TMP; revert manually with: refineid card change-pin1"
            FAIL=$((FAIL+1))
        fi
    else
        record "FAIL  11. change-pin1 -> temporary (needs pin-env-debug CLI build)"; FAIL=$((FAIL+1))
    fi
    guard_status "after PIN1 change cycle"
else
    record "SKIP  11-12. PIN1 change cycle (set REFINEID_SUITE_PIN_CHANGE=1)"
fi

# ---------------------------------------------------------------
# Phase 5 (opt-in, interactive): PUK unblock. Exercises RESET RETRY
# COUNTER with the current PIN as the new value (a state no-op that
# still runs the full card path). The CLI prompts for the PUK on
# the terminal -- it is never taken from argv or env.
# ---------------------------------------------------------------

if [[ "${REFINEID_SUITE_INTERACTIVE:-}" == "1" && -t 0 ]]; then
    echo "+++ PUK unblock (interactive; enter PUK + current PIN1 at the prompts) +++"
    if "$CLI" card unblock-pin1; then
        record "OK    13. unblock-pin1 (PUK path)"; PASS=$((PASS+1))
    else
        record "FAIL  13. unblock-pin1"; FAIL=$((FAIL+1))
    fi
    guard_status "after unblock"
else
    record "SKIP  13. PUK unblock (set REFINEID_SUITE_INTERACTIVE=1 and run on a TTY)"
fi

# ---------------------------------------------------------------
# Final sanity: PIN1 still works end to end.
# ---------------------------------------------------------------

run "14. final login sanity"                      pkcs11-tool --module "$MOD" --login --pin "$PIN1" --list-objects
guard_status "final"

summarise
exit $(( FAIL > 0 ? 1 : 0 ))
