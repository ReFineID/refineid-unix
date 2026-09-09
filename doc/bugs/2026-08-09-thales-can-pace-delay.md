# Thales MultiApp v5 CAN-PACE progressive delay

Status: vendor requirement confirmed; recovery parameters undisclosed.

A Thales MultiApp v5 card can deliberately delay a CAN-PACE response
after unsuccessful attempts. Repeated interrupted attempts are a
plausible trigger. Restarting the reader stack, changing source
revisions, or moving the card to another reader does not necessarily
remove card state.

## Published behavior

BSI TR-03110 Part 1 section 2.3 defines CAN as non-blocking: the chip
must not block it after failed authentication. When a non-blocking
password has insufficient entropy, the same section requires an
additional brute-force countermeasure and explicitly permits delays.

The Thales security target makes the countermeasure concrete for
Digital Identity 1.0.A on MultiApp v5.0.A. FIA_AFL.1/PACE, Table 20 on
page 56, says:

- one unsuccessful MRZ/CAN PACE authentication exponentially increases
  the delay before another attempt is possible; and
- the CAN-specific rule defines a presentation-count parameter in the
  range 0 to 255 and an increasing wait between the terminal challenge
  and the card's PACE response.

See [`thales_multiapp_v5_security_target`](../references.md#thales_multiapp_v5_security_target)
and the BSI TR-03110 entry in [`references.md`](../references.md).

The sources do **not** publish the delay values, the counter's storage
lifetime, its decay or reset rule, or whether every interrupted exchange
increments it. Do not invent a fixed cooldown or promise that a power
cycle clears it.

## Recorded exchange

Observed 2026-08-09 on a production Thales MultiApp v5 FINEID card:

1. `SELECT MF` returned `SW=9000` in 9--18 ms.
2. PACE `MSE:Set AT` returned `SW=9000` in 14--28 ms.
3. The first `GENERAL AUTHENTICATE`, which requests the encrypted nonce,
   received no response before an iPhone dropped the tag at
   45.304--45.317 seconds.
4. One earlier run received the structurally valid 22-byte response at
   42.47 seconds. This excludes a malformed APDU as the general cause.
5. An exact clean ReFineID-Apple `origin/main` build reproduced the
   timeout.
6. The same card then failed registration on a second phone.

The successful `MSE:Set AT` only proves that PACE initialization was
accepted. It does not authenticate the CAN. The stall location and
duration match the Thales delay rule: the card remains responsive to
the setup commands and withholds the PACE response.

An earlier uncontrolled observation found that the state disappeared
after a few hours. That is observation, not a specified recovery rule.

## Operational rules

1. Do not automatically retry CAN-PACE.
2. On a delayed encrypted-nonce response, stop testing that card. Do not
   use repeated reader or source-revision A/B attempts as diagnostics.
3. Record the source revision, each command duration, final status word
   or transport timeout, and whether the exchange completed.
4. Distinguish this progressive delay from PIN1/PIN2 retry state and
   from a formally suspended password. The two states have different
   evidence and must not share an asserted recovery rule.
5. Preserve code changes before comparison. A source rollback cannot
   roll back card state.
6. A long-lived PC/SC reader can observe a response beyond the iPhone
   deadline. Whether a completed PACE or `SCARD_UNPOWER_CARD` resets the
   progressive delay remains a hardware hypothesis until a before/after
   exchange records it.

The 2026-07-24 ACR1581 observation that an unpowered reconnect cleared a
suspended-password state does **not** prove that it clears this
progressive delay. Do not merge those findings.
