- RULE #1: PIN CODES NEVER TRAVEL OVER ANY NETWORK.
  PIN1 and PIN2 NEVER leave the phone when accessed via RAPP.
  RAPP MUST ABSOLUTELY DENY AND PRECLUDE ALL ATTEMPTS TO TRANSPORT PIN CODES ANYWHERE.
  PIN1 stays cached on the mobile device. PIN2 prompts appear strictly on the mobile
  device screen. The host computer and browsers operate via a protected authentication
  path (CKF_PROTECTED_AUTHENTICATION_PATH) and never prompt for or handle PIN codes.
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
