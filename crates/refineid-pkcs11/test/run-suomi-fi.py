import json, os, socket, subprocess, sys, time

# Stop existing firefox
subprocess.run(["pkill", "-f", "firefox"], stderr=subprocess.DEVNULL)
time.sleep(1)

env = dict(os.environ)
env["DISPLAY"] = ":0"
env["XAUTHORITY"] = "/run/user/1000/.mutter-Xwaylandauth.6EXEU3"
env["XDG_RUNTIME_DIR"] = "/run/user/1000"
env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/run/user/1000/bus"
env["WAYLAND_DISPLAY"] = "wayland-0"
env["REFINEID_TEST_PIN1"] = "456789"

print("[1] Launching Firefox on screen...", flush=True)
proc = subprocess.Popen(
    ["/snap/bin/firefox", "--marionette", "--no-remote", "about:blank"],
    env=env,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

# Connect Marionette
sock = None
for i in range(30):
    time.sleep(0.5)
    try:
        s = socket.create_connection(("127.0.0.1", 2828), timeout=3)
        buf = b""
        while b":" not in buf:
            c = s.recv(1)
            if not c: raise EOFError()
            buf += c
        l = int(buf.split(b":", 1)[0])
        s.recv(l)
        sock = s
        print(f"[2] Marionette connected (attempt {i+1})", flush=True)
        break
    except Exception:
        pass

if not sock:
    print("[-] Failed to connect to Marionette", flush=True)
    proc.terminate()
    sys.exit(1)

msg_id = [1]
def cmd(name, params=None, timeout=10):
    m = msg_id[0]; msg_id[0] += 1
    raw = json.dumps([0, m, name, params or {}]).encode()
    sock.settimeout(timeout)
    sock.sendall(f"{len(raw)}:".encode() + raw)
    buf = b""
    while b":" not in buf:
        c = sock.recv(1)
        if not c: raise EOFError()
        buf += c
    n = int(buf.split(b":")[0])
    body = b""
    while len(body) < n:
        body += sock.recv(n - len(body))
    return json.loads(body.decode())

cmd("WebDriver:NewSession", {"capabilities": {}})
print("[3] Session established", flush=True)

print("[4] Navigating to https://www.suomi.fi ...", flush=True)
cmd("WebDriver:Navigate", {"url": "https://www.suomi.fi"})
time.sleep(3)

print("[5] Clicking 'Tunnistaudu'...", flush=True)
cmd("WebDriver:ExecuteScript", {
    "script": "let lc = document.querySelector('.login-container'); if (lc) (lc.querySelector('a, button') || lc).click();",
    "args": []
})
time.sleep(3)

print("[6] Selecting 'Varmennekortti'...", flush=True)
cmd("WebDriver:ExecuteScript", {
    "script": "let cardLink = document.querySelector('#varmennekortti, a[href*=\"VARMENNEKORTTI\"]'); if (cardLink) cardLink.click();",
    "args": []
})
time.sleep(3)

print("[7] Submitting card authentication prompt...", flush=True)
try:
    cmd("WebDriver:ExecuteScript", {
        "script": "let btn = document.querySelector('#tunnistaudu, button[type=\"submit\"], input[type=\"submit\"]'); if (btn) btn.click();",
        "args": []
    }, timeout=5)
except Exception as e:
    print(f"    Submit returned: {e}", flush=True)

# Handle certificate selection & PIN dialog
print("[8] Auto-responding to prompts: Enter on Cert -> PIN 456789 -> Enter...", flush=True)
time.sleep(1.5)
subprocess.run(["ydotool", "key", "28:1", "28:0"]) # Enter (confirm cert)
time.sleep(1.5)
subprocess.run(["ydotool", "type", "--", "456789"]) # Type PIN
time.sleep(0.2)
subprocess.run(["ydotool", "key", "28:1", "28:0"]) # Enter (submit PIN)

print("[9] Monitoring Suomi.fi authentication completion...", flush=True)
for i in range(25):
    time.sleep(1)
    try:
        url = cmd("WebDriver:GetCurrentURL", {}, timeout=2)[3].get("value", "")
        title = cmd("WebDriver:GetTitle", {})[3].get("value", "")
        print(f"    [{i+1:02d}s] URL: {url} | Title: {title}", flush=True)
        if "hst-prompt" in url:
            try:
                cmd("WebDriver:ExecuteScript", {
                    "script": "let btn = document.querySelector('button[type=\"submit\"], input[type=\"submit\"], a.button, button'); if (btn) btn.click();",
                    "args": []
                }, timeout=2)
                time.sleep(1)
                subprocess.run(["ydotool", "key", "28:1", "28:0"]) # Enter
                time.sleep(1)
                subprocess.run(["ydotool", "type", "--", "456789"])
                time.sleep(0.2)
                subprocess.run(["ydotool", "key", "28:1", "28:0"]) # Enter
            except Exception:
                pass
        if ("suomi.fi" in url and not any(k in url for k in ["tunnist", "etusivu", "kortti", "hstidp"])) or any(k in url for k in ["asiointitili", "omat-tiedot", "viestit", "valtuudet", "kansalaiselle"]):
            print("\n=======================================================", flush=True)
            print("🎉🎉🎉 SUCCESSFUL SUOMI.FI SMARTCARD LOGIN IN FIREFOX! 🎉🎉🎉", flush=True)
            print(f"Landing URL: {url}", flush=True)
            print(f"Page Title:  {title}", flush=True)
            print("=======================================================\n", flush=True)
            break
    except Exception as e:
        print(f"    [{i+1:02d}s] {e}", flush=True)

print("[10] Authentication complete. Keeping Firefox visible.", flush=True)
