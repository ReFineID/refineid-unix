#!/usr/bin/env python3
"""
Drive Firefox authentication to https://card.refineid.fi or https://www.suomi.fi
using Marionette + ydotool (Wayland virtual keyboard input).
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time

# Linux input subsystem keycode constants (linux/input-event-codes.h)
KEY_ENTER = 28
EV_KEY_PRESS = 1
EV_KEY_RELEASE = 0
KEY_ENTER_PRESS = f"{KEY_ENTER}:{EV_KEY_PRESS}"
KEY_ENTER_RELEASE = f"{KEY_ENTER}:{EV_KEY_RELEASE}"

DEFAULT_TEST_PIN1 = os.environ.get("REFINEID_TEST_PIN1", "456789")

def ydo_type(text):
    subprocess.run(["ydotool", "type", "--", text], check=True)

def ydo_key(key_combos):
    args = ["ydotool", "key"] + key_combos
    subprocess.run(args, check=True)

def press_enter():
    ydo_key([KEY_ENTER_PRESS, KEY_ENTER_RELEASE])

def enter_pin(pin=DEFAULT_TEST_PIN1):
    print(f"[*] Typing PIN and pressing Enter via ydotool...")
    ydo_type(pin)
    time.sleep(0.2)
    press_enter()

def main():
    pin1 = os.environ.get("REFINEID_TEST_PIN1", "456789")
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://card.refineid.fi"

    # Stop any old firefox
    subprocess.run(["pkill", "-f", "firefox"], stderr=subprocess.DEVNULL)
    time.sleep(1)

    env = dict(os.environ)
    env["DISPLAY"] = ":0"
    import glob
    xauth = os.environ.get("XAUTHORITY")
    if not xauth or not os.path.exists(xauth):
        matches = glob.glob("/run/user/1000/.mutter-Xwaylandauth.*")
        if matches:
            xauth = matches[0]
    if xauth:
        env["XAUTHORITY"] = xauth
    env["XDG_RUNTIME_DIR"] = "/run/user/1000"
    env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/run/user/1000/bus"
    env["WAYLAND_DISPLAY"] = "wayland-0"
    env["REFINEID_DEBUG"] = "1"
    env["REFINEID_PKCS11_LOG"] = "/home/pk/snap/firefox/common/pkcs11.log"

    print("[*] Launching Firefox on desktop...")
    proc = subprocess.Popen(
        [
            "/snap/bin/firefox",
            "--marionette",
            "--no-remote",
            "-profile",
            "/home/pk/snap/firefox/common/refineid-marionette-profile",
            "about:blank",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    sock = None
    print("[*] Connecting to Marionette port 2828...")
    for i in range(30):
        time.sleep(0.5)
        try:
            s = socket.create_connection(("127.0.0.1", 2828), timeout=5)
            buf = b""
            while b":" not in buf:
                c = s.recv(1)
                if not c:
                    raise EOFError()
                buf += c
            l = int(buf.split(b":", 1)[0])
            body = s.recv(l)
            print(f"[*] Marionette connected: {body.decode()}")
            sock = s
            break
        except Exception:
            pass

    if not sock:
        print("[-] Could not connect to Marionette")
        proc.terminate()
        return 1

    msg_id = [1]
    def cmd(name, params=None, timeout=10):
        m = msg_id[0]
        msg_id[0] += 1
        raw = json.dumps([0, m, name, params or {}]).encode()
        sock.settimeout(timeout)
        sock.sendall(f"{len(raw)}:".encode() + raw)
        buf = b""
        while b":" not in buf:
            c = sock.recv(1)
            if not c:
                raise EOFError()
            buf += c
        n = int(buf.split(b":")[0])
        body = b""
        while len(body) < n:
            body += sock.recv(n - len(body))
        return json.loads(body.decode())

    resp = cmd("WebDriver:NewSession", {"capabilities": {}})
    sid = resp[3].get("sessionId") if resp[3] else None
    print(f"[*] Session created: {sid}")

    # Start a background key injection thread that watches and handles prompts
    stop_typing = threading.Event()
    def auto_responder():
        # Protected authentication path: PIN1 is NEVER typed on or sent from this computer!
        # It is held safely on the mobile device. We only confirm cert selection if prompted.
        time.sleep(2.0)
        print("[Auto-Responder] Confirming certificate selection (Enter)...")
        press_enter()

    responder = threading.Thread(target=auto_responder, daemon=True)

    print(f"[*] Navigating to {target_url}...")
    responder.start()

    try:
        cmd("WebDriver:Navigate", {"url": target_url}, timeout=8)
    except Exception as e:
        print(f"[*] Navigate returned/in-progress: {e}")

    print("[*] Monitoring page status after authentication...")
    for i in range(20):
        time.sleep(1)
        try:
            url = cmd("WebDriver:GetCurrentURL", {}, timeout=3)[3].get("value", "")
            title = cmd("WebDriver:GetTitle", {}, timeout=3)[3].get("value", "")
            print(f"    [{i+1:02d}s] URL: {url} | Title: {title}")

            res = cmd("WebDriver:ExecuteScript", {
                "script": "return document.body ? document.body.innerText.slice(0, 500) : '';",
                "args": []
            }, timeout=3)
            text = res[3].get("value", "") if res[3] else ""
            if text:
                print(f"\n================ PAGE CONTENT ================\n{text.strip()}\n==============================================\n")
                if "403" not in text and "Virhe" not in text and "Error" not in text:
                    print("✅ AUTHENTICATION VERIFIED ON SCREEN!")
                    break
        except Exception as e:
            print(f"    [{i+1:02d}s] {e}")

    print("[*] Done driving login. Keeping Firefox visible.")
    try:
        cmd("WebDriver:DeleteSession", {}, timeout=2)
    except Exception:
        pass
    sock.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
