# Security Policy

ReFineID handles card credentials and retry-limited operations. Please report
security issues privately through GitHub's **Report a vulnerability** action on
the repository Security tab.

Never include a real PIN, PUK, private key, personal identity code, certificate
private material, or raw credential APDU in a report.

## Inviolable Rule #1: PIN codes NEVER travel over any network

PIN codes (PIN1 and PIN2) NEVER leave the mobile device when accessed via RAPP. RAPP must absolutely deny and preclude all attempts to transport PIN codes anywhere:
- The protocol wire format has no field or message for PIN codes.
- PIN1 remains in protected on-device cache on the phone.
- PIN2 prompts appear exclusively on the mobile device screen.
- The host computer operates via a protected authentication path (`CKF_PROTECTED_AUTHENTICATION_PATH`) without any PIN prompts or transport.
