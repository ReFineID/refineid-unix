// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Browser-free NSS discovery probe against the built cdylib.
//!
//! Answers "why doesn't Firefox see the card" in one second with no
//! GUI: it `dlopen`s the module exactly like NSS / p11-kit would and
//! replays NSS's own discovery sequence -- including the probes most
//! modules never think about (the vendor-defined NSS builtin-root
//! class and the v3.0 `CKO_PROFILE` object, which this module must
//! answer with ZERO matches; see the eager-PIN1 rule on
//! `ObjectKind` in `src/token.rs`).
//!
//! Usage (needs a card in a reader; read-only unless flags given):
//!
//! ```text
//! cargo run -p refineid-pkcs11 --example nss_debug [-- <module-path>]
//! cargo run -p refineid-pkcs11 --example nss_debug -- --login --sign-probe
//! ```
//!
//! Without `<module-path>` the probe loads the freshly built cdylib
//! next to its own executable (`target/<profile>/`). `--login` runs a
//! `C_Login` probe with PIN1 taken from the `REFINEID_PIN1`
//! environment variable (never argv -- argv is visible in `ps`);
//! `--sign-probe` follows with a `C_SignInit` / `C_Sign` round trip
//! using the module's advertised mechanism. PIN bytes ride in a
//! zeroizing `PinBytes` and are never printed.

// This example talks to the module through the raw PKCS#11 C ABI --
// the same way NSS does -- so FFI is its entire point, like the
// cdylib itself (see `src/lib.rs`).
#![cfg_attr(
    unix,
    expect(
        unsafe_code,
        reason = "the probe drives the module's PKCS#11 C ABI via dlopen/dlsym, exactly as NSS would"
    )
)]

#[cfg(unix)]
mod probe {
    use std::ffi::CString;
    use std::fmt::Write as _;

    use refineid_lib_core::pin::PinBytes;
    use refineid_pkcs11::ck::{
        CK_TRUE, CK_UNAVAILABLE_INFORMATION, CKA_ALWAYS_AUTHENTICATE, CKA_CLASS, CKA_EXTRACTABLE,
        CKA_ID, CKA_ISSUER, CKA_KEY_TYPE, CKA_LABEL, CKA_NEVER_EXTRACTABLE, CKA_SERIAL_NUMBER,
        CKA_SIGN, CKA_SUBJECT, CKA_TOKEN, CKF_SERIAL_SESSION, CKM_RSA_PKCS, CKO_CERTIFICATE,
        CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKR_OK, CKU_USER, CkAttribute, CkAttributeType, CkBbool,
        CkFunctionList, CkFunctionListPtr, CkInfo, CkMechanism, CkMechanismType, CkObjectHandle,
        CkRv, CkSessionHandle, CkSlotId, CkTokenInfo, CkUlong,
    };

    /// PKCS#11 v3.0 `CKO_PROFILE` object class. Not part of the
    /// crate's v2.40 `ck` transcription; probed here because NSS
    /// searches for it and this module must never expose one (a
    /// `CKP_AUTHENTICATION_TOKEN` profile makes NSS prompt PIN1
    /// eagerly at browser startup).
    const CKO_PROFILE: CkUlong = 0x0000_0009;

    /// NSS's vendor-defined "builtin root list" object class:
    /// `CKO_VENDOR_DEFINED (0x8000_0000) | NSSCK_VENDOR_NSS
    /// (0x4E53_4350 = "NSCP") + 4`, from NSS `pkcs11n.h`. NSS
    /// probes every module for it during discovery.
    const CKO_NSS_BUILTIN_ROOT_LIST: CkUlong = 0xCE53_4354;

    /// ASN.1 `DigestInfo` prefix for SHA-256 (RFC 8017 s9.2 note 1):
    /// `SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL },
    /// OCTET STRING (32) }` minus the hash bytes. `CKM_RSA_PKCS`
    /// callers pass `DigestInfo || hash`.
    const DIGEST_INFO_SHA256_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    /// The one symbol PKCS#11 modules export (v2.40 s5.6.4).
    type GetFunctionList = unsafe extern "C" fn(*mut CkFunctionListPtr) -> CkRv;

    /// Parsed command line.
    struct Config {
        module_path: std::path::PathBuf,
        login: bool,
        sign_probe: bool,
    }

    /// Saturating usize -> `CkUlong` for buffer lengths.
    fn ulong_len(value: usize) -> CkUlong {
        CkUlong::try_from(value).unwrap_or(CkUlong::MAX)
    }

    /// Saturating `CkUlong` -> usize for buffer lengths.
    fn usize_len(value: CkUlong) -> usize {
        usize::try_from(value).unwrap_or(usize::MAX)
    }

    /// Lowercase hex of a byte string.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    /// Hex truncated to 16 bytes with a length marker.
    fn short_hex(bytes: &[u8]) -> String {
        match bytes.get(..16) {
            Some(head) if bytes.len() > 16 => format!("{}... ({}B)", hex(head), bytes.len()),
            _ => hex(bytes),
        }
    }

    /// A space-padded fixed-width PKCS#11 text field, trimmed.
    fn field_str(field: &[u8]) -> String {
        String::from_utf8_lossy(field).trim_end().to_owned()
    }

    fn parse_args() -> Result<Config, String> {
        let mut module_path = None;
        let mut login = false;
        let mut sign_probe = false;
        for arg in std::env::args().skip(1) {
            match arg.as_str() {
                "--login" => login = true,
                "--sign-probe" => sign_probe = true,
                "--help" | "-h" => {
                    return Err(
                        "usage: nss_debug [<module-path>] [--login] [--sign-probe]\n\
                         --login reads PIN1 from the REFINEID_PIN1 environment variable"
                            .to_owned(),
                    );
                }
                other if module_path.is_none() && !other.starts_with('-') => {
                    module_path = Some(std::path::PathBuf::from(other));
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        let module_path = match module_path {
            Some(path) => path,
            None => default_module_path()?,
        };
        Ok(Config {
            module_path,
            login,
            sign_probe,
        })
    }

    /// Locate the freshly built cdylib next to this example's own
    /// executable: examples land in `target/<profile>/examples/`,
    /// the cdylib in `target/<profile>/`.
    fn default_module_path() -> Result<std::path::PathBuf, String> {
        let exe = std::env::current_exe().map_err(|error| format!("current_exe: {error}"))?;
        let profile_dir = exe
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or_else(|| "cannot locate target profile dir".to_owned())?;
        let file = if cfg!(target_os = "macos") {
            "librefineid_pkcs11.dylib"
        } else {
            "librefineid_pkcs11.so"
        };
        let candidate = profile_dir.join(file);
        if candidate.is_file() {
            Ok(candidate)
        } else {
            Err(format!(
                "module not built: {} (cargo build -p refineid-pkcs11, or pass a module path)",
                candidate.display()
            ))
        }
    }

    /// `dlopen` the module and resolve its vtable via
    /// `C_GetFunctionList`, exactly like NSS. The handle is never
    /// `dlclose`d: the module holds process-lifetime state and the
    /// probe exits right after, matching how a browser treats it.
    fn load_vtable(path: &std::path::Path) -> Result<&'static CkFunctionList, String> {
        let c_path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_nul| "module path contains a NUL byte".to_owned())?;
        // SAFETY: dlopen with a valid NUL-terminated path; a NULL
        // return is handled below.
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW) };
        if handle.is_null() {
            return Err(format!("dlopen failed for {}", path.display()));
        }
        let symbol = CString::new("C_GetFunctionList")
            .map_err(|_nul| "symbol name contains a NUL byte".to_owned())?;
        // SAFETY: dlsym on a live handle with a valid symbol name.
        let sym = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
        if sym.is_null() {
            return Err("C_GetFunctionList symbol not exported".to_owned());
        }
        // SAFETY: PKCS#11 defines C_GetFunctionList's exact
        // signature; transmuting the dlsym pointer to it is the
        // standard (and only) way to call a dlopen'd module.
        let get_list = unsafe { std::mem::transmute::<*mut libc::c_void, GetFunctionList>(sym) };
        let mut list: CkFunctionListPtr = std::ptr::null_mut();
        // SAFETY: `list` is a valid writable location for one
        // pointer, per the function's contract.
        let rv = unsafe { get_list(&raw mut list) };
        if rv != CKR_OK || list.is_null() {
            return Err(format!("C_GetFunctionList rv={rv:#06x}"));
        }
        // SAFETY: the module hands back a pointer to its static
        // vtable, which outlives the process's use of the module.
        Ok(unsafe { &*list })
    }

    /// `C_GetAttributeValue` two-call read of one attribute.
    fn read_attr(
        f: &CkFunctionList,
        session: CkSessionHandle,
        object: CkObjectHandle,
        attr_type: CkAttributeType,
    ) -> Result<Vec<u8>, CkRv> {
        let mut entry = CkAttribute {
            attr_type,
            p_value: std::ptr::null_mut(),
            ul_value_len: 0,
        };
        // SAFETY: a single valid CK_ATTRIBUTE with NULL p_value is
        // the spec's length query.
        let rv = unsafe { (f.C_GetAttributeValue)(session, object, &raw mut entry, 1) };
        if rv != CKR_OK || entry.ul_value_len == CK_UNAVAILABLE_INFORMATION {
            return Err(rv);
        }
        let mut buf = vec![0_u8; usize_len(entry.ul_value_len)];
        entry.p_value = buf.as_mut_ptr().cast();
        entry.ul_value_len = ulong_len(buf.len());
        // SAFETY: p_value now points at ul_value_len writable bytes.
        let rv = unsafe { (f.C_GetAttributeValue)(session, object, &raw mut entry, 1) };
        if rv != CKR_OK {
            return Err(rv);
        }
        buf.truncate(usize_len(entry.ul_value_len));
        Ok(buf)
    }

    /// Run one NSS-style `C_FindObjects` probe for a class template
    /// (`CKA_TOKEN = TRUE`, `CKA_CLASS = class_value`).
    fn find_by_class(
        f: &CkFunctionList,
        session: CkSessionHandle,
        name: &str,
        class_value: CkUlong,
    ) -> Result<Vec<CkObjectHandle>, String> {
        let mut class_storage = class_value;
        let mut token_true: CkBbool = CK_TRUE;
        let mut template = [
            CkAttribute {
                attr_type: CKA_TOKEN,
                p_value: std::ptr::from_mut(&mut token_true).cast(),
                ul_value_len: ulong_len(size_of::<CkBbool>()),
            },
            CkAttribute {
                attr_type: CKA_CLASS,
                p_value: std::ptr::from_mut(&mut class_storage).cast(),
                ul_value_len: ulong_len(size_of::<CkUlong>()),
            },
        ];
        // SAFETY: template points at 2 valid entries whose values
        // stay alive across the call.
        let rv = unsafe {
            (f.C_FindObjectsInit)(session, template.as_mut_ptr(), ulong_len(template.len()))
        };
        if rv != CKR_OK {
            return Err(format!("find {name}: C_FindObjectsInit rv={rv:#06x}"));
        }
        let mut handles: [CkObjectHandle; 8] = [0; 8];
        let mut count: CkUlong = 0;
        // SAFETY: handles has 8 writable slots and count is writable.
        let rv = unsafe {
            (f.C_FindObjects)(
                session,
                handles.as_mut_ptr(),
                ulong_len(handles.len()),
                &raw mut count,
            )
        };
        // SAFETY: session has an active find operation.
        let final_rv = unsafe { (f.C_FindObjectsFinal)(session) };
        if rv != CKR_OK {
            return Err(format!("find {name}: C_FindObjects rv={rv:#06x}"));
        }
        if final_rv != CKR_OK {
            return Err(format!(
                "find {name}: C_FindObjectsFinal rv={final_rv:#06x}"
            ));
        }
        let found: Vec<CkObjectHandle> = handles.iter().copied().take(usize_len(count)).collect();
        let list = found.iter().fold(String::new(), |mut out, handle| {
            if !out.is_empty() {
                out.push_str(", ");
            }
            let _ = write!(out, "{handle}");
            out
        });
        println!("find {name:<34} -> {} match(es) [{list}]", found.len());
        Ok(found)
    }

    /// Dump the attributes NSS reads while pairing certs and keys.
    fn dump_object(
        f: &CkFunctionList,
        session: CkSessionHandle,
        label: &str,
        object: CkObjectHandle,
    ) {
        println!("  {label} {object}:");
        let text_attrs = [(CKA_LABEL, "label")];
        for (attr, name) in text_attrs {
            match read_attr(f, session, object, attr) {
                Ok(value) => println!("    {name:<20} = {}", String::from_utf8_lossy(&value)),
                Err(rv) => println!("    {name:<20} : rv={rv:#06x}"),
            }
        }
        let hex_attrs = [
            (CKA_ID, "cka_id"),
            (CKA_SUBJECT, "subject"),
            (CKA_ISSUER, "issuer"),
            (CKA_SERIAL_NUMBER, "serial"),
        ];
        for (attr, name) in hex_attrs {
            if let Ok(value) = read_attr(f, session, object, attr) {
                println!("    {name:<20} = {}", short_hex(&value));
            }
        }
        let scalar_attrs = [
            (CKA_KEY_TYPE, "key_type"),
            (CKA_SIGN, "sign"),
            (CKA_ALWAYS_AUTHENTICATE, "always_authenticate"),
            (CKA_EXTRACTABLE, "extractable"),
            (CKA_NEVER_EXTRACTABLE, "never_extractable"),
        ];
        for (attr, name) in scalar_attrs {
            if let Ok(value) = read_attr(f, session, object, attr) {
                println!("    {name:<20} = {}", hex(&value));
            }
        }
    }

    /// `C_Login(CKU_USER)` with PIN1 from `REFINEID_PIN1`.
    fn login_probe(f: &CkFunctionList, session: CkSessionHandle) -> Result<(), String> {
        let raw = std::env::var("REFINEID_PIN1")
            .map_err(|_missing| "--login needs REFINEID_PIN1 in the environment".to_owned())?;
        let pin = PinBytes::new(raw.into_bytes()).map_err(|error| format!("PIN1: {error}"))?;
        // SAFETY: the PIN buffer stays alive across the call; the
        // module copies the bytes into its own zeroizing storage.
        let rv = unsafe {
            (f.C_Login)(
                session,
                CKU_USER,
                pin.as_bytes().as_ptr().cast_mut(),
                ulong_len(pin.as_bytes().len()),
            )
        };
        println!("login: C_Login(CKU_USER) rv={rv:#06x}");
        if rv == CKR_OK {
            Ok(())
        } else {
            Err("login failed".to_owned())
        }
    }

    /// `C_SignInit` + two-call `C_Sign` with a digest-shaped payload
    /// matching the module's advertised mechanism.
    fn sign_probe(
        f: &CkFunctionList,
        session: CkSessionHandle,
        mechanism_type: CkMechanismType,
        key: CkObjectHandle,
    ) {
        let hash: Vec<u8> = (1_u8..=32).collect();
        let payload = if mechanism_type == CKM_RSA_PKCS {
            let mut data = DIGEST_INFO_SHA256_PREFIX.to_vec();
            data.extend_from_slice(&hash);
            data
        } else {
            hash
        };
        let mut mechanism = CkMechanism {
            mechanism: mechanism_type,
            p_parameter: std::ptr::null_mut(),
            ul_parameter_len: 0,
        };
        // SAFETY: mechanism is a valid CK_MECHANISM.
        let rv = unsafe { (f.C_SignInit)(session, &raw mut mechanism, key) };
        if rv != CKR_OK {
            println!("sign probe: C_SignInit rv={rv:#06x}");
            return;
        }
        let mut needed: CkUlong = 0;
        // SAFETY: NULL signature + writable length is the size query.
        let rv = unsafe {
            (f.C_Sign)(
                session,
                payload.as_ptr().cast_mut(),
                ulong_len(payload.len()),
                std::ptr::null_mut(),
                &raw mut needed,
            )
        };
        if rv != CKR_OK {
            println!("sign probe: C_Sign size query rv={rv:#06x}");
            return;
        }
        let mut signature = vec![0_u8; usize_len(needed)];
        let mut sig_len = ulong_len(signature.len());
        // SAFETY: signature has sig_len writable bytes.
        let rv = unsafe {
            (f.C_Sign)(
                session,
                payload.as_ptr().cast_mut(),
                ulong_len(payload.len()),
                signature.as_mut_ptr(),
                &raw mut sig_len,
            )
        };
        println!(
            "sign probe: mechanism={mechanism_type:#06x} rv={rv:#06x} sig_len={}",
            usize_len(sig_len)
        );
    }

    /// Software-verify probe, PIN-free: an all-zero signature of the
    /// right length must come back `CKR_SIGNATURE_INVALID (0x00c0)`
    /// after real math against the token's cached public key --
    /// proving the whole `C_VerifyInit` / `C_Verify` path without a
    /// valid signature in hand.
    fn verify_probe(
        f: &CkFunctionList,
        session: CkSessionHandle,
        mechanism_type: CkMechanismType,
        key: CkObjectHandle,
    ) {
        let hash: Vec<u8> = (1_u8..=48).collect();
        let (payload, sig_len) = if mechanism_type == CKM_RSA_PKCS {
            let mut data = DIGEST_INFO_SHA256_PREFIX.to_vec();
            data.extend_from_slice(hash.get(..32).unwrap_or(&hash));
            (data, 384_usize)
        } else {
            (hash, 96_usize)
        };
        let mut mechanism = CkMechanism {
            mechanism: mechanism_type,
            p_parameter: std::ptr::null_mut(),
            ul_parameter_len: 0,
        };
        // SAFETY: mechanism is a valid CK_MECHANISM.
        let rv = unsafe { (f.C_VerifyInit)(session, &raw mut mechanism, key) };
        if rv != CKR_OK {
            println!("verify probe: C_VerifyInit rv={rv:#06x}");
            return;
        }
        let bogus_signature = vec![0_u8; sig_len];
        // SAFETY: payload and bogus_signature are valid readable
        // slices for the lengths passed.
        let rv = unsafe {
            (f.C_Verify)(
                session,
                payload.as_ptr().cast_mut(),
                ulong_len(payload.len()),
                bogus_signature.as_ptr().cast_mut(),
                ulong_len(bogus_signature.len()),
            )
        };
        println!(
            "verify probe: mechanism={mechanism_type:#06x} rv={rv:#06x} (expect 0x00c0 signature-invalid for the all-zero signature)"
        );
    }

    /// Print `C_GetInfo` + slot/token/mechanism discovery; returns
    /// the chosen slot and its advertised mechanism.
    fn discover(f: &CkFunctionList) -> Result<(CkSlotId, CkMechanismType), String> {
        let mut info = CkInfo {
            cryptoki_version: refineid_pkcs11::ck::CkVersion { major: 0, minor: 0 },
            manufacturer_id: [0; 32],
            flags: 0,
            library_description: [0; 32],
            library_version: refineid_pkcs11::ck::CkVersion { major: 0, minor: 0 },
        };
        // SAFETY: info is a valid writable CK_INFO.
        let rv = unsafe { (f.C_GetInfo)(&raw mut info) };
        if rv == CKR_OK {
            println!(
                "library: '{}' v{}.{} (cryptoki {}.{})",
                field_str(&info.library_description),
                info.library_version.major,
                info.library_version.minor,
                info.cryptoki_version.major,
                info.cryptoki_version.minor,
            );
        }

        let mut count: CkUlong = 0;
        // SAFETY: NULL list + writable count is the size query.
        let rv = unsafe { (f.C_GetSlotList)(CK_TRUE, std::ptr::null_mut(), &raw mut count) };
        if rv != CKR_OK {
            return Err(format!("C_GetSlotList rv={rv:#06x}"));
        }
        let mut slots: Vec<CkSlotId> = vec![0; usize_len(count)];
        // SAFETY: slots has `count` writable entries.
        let rv = unsafe { (f.C_GetSlotList)(CK_TRUE, slots.as_mut_ptr(), &raw mut count) };
        if rv != CKR_OK {
            return Err(format!("C_GetSlotList rv={rv:#06x}"));
        }
        slots.truncate(usize_len(count));
        println!("token slots: {}", slots.len());
        let Some(slot) = slots.first().copied() else {
            return Err("no slot with a FINEID token present".to_owned());
        };

        let mut token_info: CkTokenInfo = default_token_info();
        // SAFETY: token_info is a valid writable CK_TOKEN_INFO.
        let rv = unsafe { (f.C_GetTokenInfo)(slot, &raw mut token_info) };
        if rv != CKR_OK {
            return Err(format!("C_GetTokenInfo rv={rv:#06x}"));
        }
        println!(
            "slot={slot} label='{}' model='{}' serial='{}' flags={:#010x}",
            field_str(&token_info.label),
            field_str(&token_info.model),
            field_str(&token_info.serial_number),
            token_info.flags,
        );

        let mut mech_count: CkUlong = 1;
        let mut mechs: [CkMechanismType; 1] = [0];
        // SAFETY: mechs has mech_count writable entries.
        let rv = unsafe { (f.C_GetMechanismList)(slot, mechs.as_mut_ptr(), &raw mut mech_count) };
        if rv != CKR_OK {
            return Err(format!("C_GetMechanismList rv={rv:#06x}"));
        }
        let Some(mechanism_type) = mechs.first().copied() else {
            return Err("no mechanism advertised".to_owned());
        };
        println!("mechanism: {mechanism_type:#06x}");
        Ok((slot, mechanism_type))
    }

    /// Discovery main: everything NSS does before any login.
    pub fn run() -> Result<(), String> {
        let config = parse_args()?;
        println!("module: {}", config.module_path.display());
        let f = load_vtable(&config.module_path)?;

        // SAFETY: NULL pInitArgs is the spec's default init.
        let rv = unsafe { (f.C_Initialize)(std::ptr::null_mut()) };
        if rv != CKR_OK {
            return Err(format!("C_Initialize rv={rv:#06x}"));
        }
        let (slot, mechanism_type) = discover(f)?;

        let mut session: CkSessionHandle = 0;
        // SAFETY: session is a writable handle slot; notify is NULL.
        let rv = unsafe {
            (f.C_OpenSession)(
                slot,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut session,
            )
        };
        if rv != CKR_OK {
            return Err(format!("C_OpenSession rv={rv:#06x}"));
        }

        let profile = find_by_class(f, session, "NSS profile (CKO_PROFILE)", CKO_PROFILE)?;
        if !profile.is_empty() {
            println!(
                "WARNING: CKO_PROFILE matched -- NSS will prompt PIN1 eagerly at startup \
                 (see the eager-PIN1 rule on ObjectKind)"
            );
        }
        find_by_class(
            f,
            session,
            "NSS builtin root list (vendor)",
            CKO_NSS_BUILTIN_ROOT_LIST,
        )?;
        let certs = find_by_class(
            f,
            session,
            "certificates (CKO_CERTIFICATE)",
            CKO_CERTIFICATE,
        )?;
        let pubs = find_by_class(f, session, "public keys (CKO_PUBLIC_KEY)", CKO_PUBLIC_KEY)?;
        let privs = find_by_class(
            f,
            session,
            "private keys (CKO_PRIVATE_KEY)",
            CKO_PRIVATE_KEY,
        )?;

        for object in &certs {
            dump_object(f, session, "cert", *object);
        }
        for object in &pubs {
            dump_object(f, session, "pubkey", *object);
        }
        for object in &privs {
            dump_object(f, session, "privkey", *object);
        }

        if config.login {
            login_probe(f, session)?;
        }
        if config.sign_probe {
            match privs.first() {
                Some(key) => sign_probe(f, session, mechanism_type, *key),
                None => println!("sign probe: no private key object found"),
            }
        }
        // Verify is software-only and PIN-free; probe it always.
        match pubs.first() {
            Some(key) => verify_probe(f, session, mechanism_type, *key),
            None => println!("verify probe: no public key object found"),
        }

        // SAFETY: session is a live handle; NULL is C_Finalize's
        // required reserved argument.
        unsafe {
            (f.C_CloseSession)(session);
            (f.C_Finalize)(std::ptr::null_mut());
        }
        Ok(())
    }

    /// Zeroed `CK_TOKEN_INFO` for the out-parameter call.
    const fn default_token_info() -> CkTokenInfo {
        CkTokenInfo {
            label: [0; 32],
            manufacturer_id: [0; 32],
            model: [0; 16],
            serial_number: [0; 16],
            flags: 0,
            ul_max_session_count: 0,
            ul_session_count: 0,
            ul_max_rw_session_count: 0,
            ul_rw_session_count: 0,
            ul_max_pin_len: 0,
            ul_min_pin_len: 0,
            ul_total_public_memory: 0,
            ul_free_public_memory: 0,
            ul_total_private_memory: 0,
            ul_free_private_memory: 0,
            hardware_version: refineid_pkcs11::ck::CkVersion { major: 0, minor: 0 },
            firmware_version: refineid_pkcs11::ck::CkVersion { major: 0, minor: 0 },
            utc_time: [0; 16],
        }
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match probe::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("nss_debug: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "nss_debug: NSS module probing is a Unix (dlopen) tool; use certutil/modutil on Windows"
    );
    std::process::ExitCode::FAILURE
}
