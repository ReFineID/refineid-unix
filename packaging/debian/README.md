# Debian packaging material

What a Debian package of this repository has to do beyond copying
files. These are the parts that were learned by getting them wrong:
a card tool on Linux fails in the daemon, the policy store and the
loader, not in its own code.

There is **no `cargo-deb` metadata yet**, so nothing here builds a
`.deb` on its own. These are the pieces a package must carry when one
is built.

| File | What it is for |
| --- | --- |
| `50-refineid-pcscd.rules` | polkit rule letting an active local-session user reach `pcscd` without a prompt. Remote inactive sessions still authenticate. Without it, every card operation raises a polkit dialog or fails outright. |
| `policies.json` | Firefox enterprise policy registering `librefineid_pkcs11.so` as a security device, so the browser finds the card without the holder adding a module by hand. |
| `postinst` | Reloads polkit so the rule applies without a session restart, enables `pcscd.socket`, and runs `ldconfig` so the cdylib's transitive libraries resolve when Firefox `dlopen`s it. |
| `prerm`, `postrm` | Debian Policy 6.5 argument handling, and `ldconfig` again on removal. |

`policies.json` names `/usr/lib/librefineid_pkcs11.so`; the crate that
builds it is [`refineid-pkcs11`](../../crates/refineid-pkcs11/), whose
cdylib is `librefineid_pkcs11.so`. A package that installs it anywhere
else has to change that path here too.
