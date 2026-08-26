#!/usr/bin/env python3
"""
Drive Firefox to log in to Suomi.fi using ReFineID PKCS#11 module via Marionette.

Usage:
  REFINEID_TEST_PIN1="456789" ./crates/refineid-pkcs11/test/marionette-suomi-fi.py
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

def find_pkcs11_lib():
    candidates = [
        os.path.expanduser("~/snap/firefox/common/lib/librefineid_pkcs11.so"),
        "/usr/lib/librefineid_pkcs11.so",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../target/release/librefineid_pkcs11.so")),
        os.path.expanduser("~/.local/lib/librefineid_pkcs11.so"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None

def extract_auth_cert(pkcs11_lib, out_path):
    out = subprocess.check_output(
        ["pkcs11-tool", "--module", pkcs11_lib, "--list-objects", "--type", "cert"],
        text=True, stderr=subprocess.DEVNULL
    )
    cert_id = None
    for line in out.splitlines():
        if "ID:" in line:
            cert_id = line.split("ID:", 1)[1].strip().replace(":", "")
            break
    if not cert_id:
        raise RuntimeError("No certificate object found on card token")
    subprocess.run(
        ["pkcs11-tool", "--module", pkcs11_lib, "--type", "cert", "--id", cert_id, "--read-object", "-o", out_path],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

class MarionetteSession:
    def __init__(self, host="127.0.0.1", port=2828):
        self.sock = None
        for _ in range(30):
            time.sleep(0.5)
            try:
                s = socket.create_connection((host, port), timeout=3)
                buf = b""
                while b":" not in buf:
                    c = s.recv(1)
                    if not c:
                        raise EOFError()
                    buf += c
                l = int(buf.split(b":", 1)[0])
                body = s.recv(l)
                self.sock = s
                self.msg_id = 1
                break
            except Exception:
                pass
        if not self.sock:
            raise RuntimeError(f"Could not connect to Marionette on {host}:{port}")

    def send_cmd(self, name, params=None):
        mid = self.msg_id
        self.msg_id += 1
        req = [0, mid, name, params or {}]
        payload = json.dumps(req).encode("utf-8")
        self.sock.sendall(f"{len(payload)}:".encode("utf-8") + payload)
        buf = b""
        while b":" not in buf:
            c = self.sock.recv(1)
            if not c:
                raise EOFError()
            buf += c
        l = int(buf.split(b":", 1)[0])
        body = b""
        while len(body) < l:
            c = self.sock.recv(l - len(body))
            if not c:
                raise EOFError()
            body += c
        return json.loads(body.decode("utf-8"))

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

def main():
    pin1 = os.environ.get("REFINEID_TEST_PIN1")
    if not pin1:
        if len(sys.argv) > 1:
            pin1 = sys.argv[1]
        else:
            print("ERROR: Set REFINEID_TEST_PIN1 or provide PIN1 as first argument", file=sys.stderr)
            sys.exit(1)

    lib = find_pkcs11_lib()
    if not lib:
        print("ERROR: ReFineID PKCS#11 library not found", file=sys.stderr)
        sys.exit(2)
    print(f"[*] Using PKCS#11 module: {lib}")

    snap_common = os.path.expanduser("~/snap/firefox/common")
    if os.path.isdir(snap_common):
        profile_dir = os.path.join(snap_common, "refineid-marionette-test-profile")
    else:
        profile_dir = tempfile.mkdtemp(prefix="refineid-marionette-")

    shutil.rmtree(profile_dir, ignore_errors=True)
    os.makedirs(profile_dir, exist_ok=True)

    auth_der = os.path.join(profile_dir, "auth.der")
    print("[*] Extracting authentication certificate from card...")
    extract_auth_cert(lib, auth_der)

    print("[*] Initializing NSS database in profile...")
    subprocess.run(["certutil", "-N", "-d", f"sql:{profile_dir}", "--empty-password"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["modutil", "-dbdir", f"sql:{profile_dir}", "-add", "ReFineID", "-libfile", lib, "-force"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["certutil", "-A", "-d", f"sql:{profile_dir}", "-n", "ReFineID-FINEID-auth", "-t", "u,u,u", "-i", auth_der], check=True, stdout=subprocess.DEVNULL)

    user_js = os.path.join(profile_dir, "user.js")
    with open(user_js, "w") as f:
        f.write('user_pref("marionette.enabled", true);\n')
        f.write('user_pref("marionette.port", 2828);\n')
        f.write('user_pref("security.default_personal_cert", "Select Automatically");\n')
        f.write('user_pref("security.enterprise_roots.enabled", true);\n')
        f.write('user_pref("security.osclientcerts.autoload", true);\n')

    print(f"[*] Launching Firefox with Marionette profile: {profile_dir}...")
    env = dict(os.environ)
    env["REFINEID_DEBUG"] = "1"
    proc = subprocess.Popen(["firefox", "--no-remote", "--marionette", "--profile", profile_dir], env=env)

    stop_dialog_watcher = threading.Event()
    def dialog_handler():
        while not stop_dialog_watcher.is_set():
            time.sleep(0.2)
            try:
                out = subprocess.check_output(["xdotool", "search", "--onlyvisible", "--class", "firefox"], text=True)
                wids = [w.strip() for w in out.splitlines() if w.strip()]
                for wid in wids:
                    try:
                        wname = subprocess.check_output(["xdotool", "getwindowname", wid], text=True).strip()
                        if any(w in wname.lower() for w in ["password", "salasana", "pin", "tunnusluku", "token", "master", "user identification", "henkilö"]):
                            print(f"\n[PIN Prompt] Entering PIN1 into dialog '{wname}'...")
                            subprocess.run(["xdotool", "windowactivate", "--sync", wid])
                            time.sleep(0.1)
                            subprocess.run(["xdotool", "type", "--window", wid, pin1])
                            time.sleep(0.1)
                            subprocess.run(["xdotool", "key", "--window", wid, "Return"])
                            time.sleep(2)
                    except Exception:
                        pass
            except Exception:
                pass

    th = threading.Thread(target=dialog_handler, daemon=True)
    th.start()

    session = None
    try:
        session = MarionetteSession()
        resp = session.send_cmd("WebDriver:NewSession", {"capabilities": {}})
        sid = resp[3].get("sessionId")
        print(f"[*] Marionette connected. Session ID: {sid}")

        print("[*] Navigating to https://www.suomi.fi/etusivu ...")
        session.send_cmd("WebDriver:Navigate", {"url": "https://www.suomi.fi/etusivu"})
        time.sleep(3)

        print("[*] Clicking 'Tunnistaudu'...")
        session.send_cmd("WebDriver:ExecuteScript", {
            "script": "let el = document.querySelector('.login-container'); if (el) (el.querySelector('a, button') || el).click();",
            "args": []
        })
        time.sleep(3)

        print("[*] Selecting 'Varmennekortti'...")
        session.send_cmd("WebDriver:ExecuteScript", {
            "script": "let cardLink = document.querySelector('#varmennekortti, a[href*=\"VARMENNEKORTTI\"]'); if (cardLink) cardLink.click();",
            "args": []
        })
        time.sleep(3)

        print("[*] Submitting on card prompt page (kortti.tunnistautuminen.suomi.fi)...")
        session.send_cmd("WebDriver:ExecuteScript", {
            "script": "let btn = document.querySelector('#tunnistaudu, button[type=\"submit\"], input[type=\"submit\"]'); if (btn) btn.click();",
            "args": []
        })

        print("[*] Waiting for card TLS authentication and redirect to complete...")
        success = False
        for i in range(25):
            time.sleep(1)
            try:
                url_resp = session.send_cmd("WebDriver:GetCurrentURL", {})
                title_resp = session.send_cmd("WebDriver:GetTitle", {})
                url = url_resp[3].get("value", "")
                title = title_resp[3].get("value", "")
                print(f"    [{i+1:02d}s] URL: {url} | Title: {title}")
                if ("suomi.fi" in url and "tunnist" not in url and "etusivu" not in url) or "asiointitili" in url or "omat-tiedot" in url or "viestit" in url:
                    print("\n=======================================================")
                    print("SUCCESSFULLY LOGGED IN TO SUOMI.FI!")
                    print(f"Landing URL: {url}")
                    print(f"Page Title:  {title}")
                    print("=======================================================\n")
                    success = True
                    break
            except Exception as e:
                print(f"    [{i+1:02d}s] {e}")

        if not success:
            print("\n[-] Login did not complete within timeout.")
            sys.exit(1)

    finally:
        stop_dialog_watcher.set()
        if session:
            try:
                session.send_cmd("WebDriver:DeleteSession", {})
            except Exception:
                pass
            session.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        shutil.rmtree(profile_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
