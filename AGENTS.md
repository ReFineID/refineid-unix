- RULE #1: PIN CODES NEVER TRAVEL OVER ANY NETWORK.
  PIN1 and PIN2 NEVER leave the phone when accessed via RAPP.
  RAPP MUST ABSOLUTELY DENY AND PRECLUDE ALL ATTEMPTS TO TRANSPORT PIN CODES ANYWHERE.
  PIN1 stays cached on the mobile device. PIN2 prompts appear strictly on the mobile
  device screen. The host computer and browsers operate via a protected authentication
  path (CKF_PROTECTED_AUTHENTICATION_PATH) and never prompt for or handle PIN codes.
- RULE #2: ZERO PIN DATA AND CANDIDATE PIN-LENGTH LOGGING ACROSS ALL ENVIRONMENTS.
  Never log, trace, display, or format PIN bytes, character offsets, supplied/candidate
  PIN lengths, or development PIN role identifiers in log sinks, audit records, or
  error strings. Only static specification policy bounds may be reported. Never commit
  test PINs or card secrets.
- Please No AI attribution spam in commits.
  No `Co-authored-by` / `Signed-off-by` / `Reviewed-by`
  or any AI-naming trailer; subject + body only. 
- ASCII only in source, UTF-8 only where required.
- No Magic Codes - define everything.   
- Commit often when compiles and lint is clean.
- Push when feature is ready.
- Verify from specifications, don't wild guess.
  `doc/references.md` indexes which one governs what.
  Cite what a source proves, and say what it does not.
- Never put a git worktree under `/tmp`. It is cleared on reboot and
  takes the branch's only checkout with it. Keep worktrees beside the
  repository.
- Less is more. Terse is better.
- Do not leak personal or private information in commits.
- When stuck, research with fellow AI available.
- If something is not working, it is by default a bug in code,
  not a feature of the platform.

## Source comments

- Comments explain what the code does now and the constraints it honors.
  Past bugs, previous implementations, and explanations of what a fix changed
  belong in commit messages, not source comments.

## Commits and integration

- Commits are cheap backups. Make small, focused commits often, without
  asking for permission, once the required commit checks pass.
- Complete the integration without waiting for another instruction: push
  the task branch, open a pull request, and merge it into `main` once the
  required checks pass. Sync local `main` with the merged remote.
  Use merge commits to preserve the branch history; do not squash it.
