import network
import socket
import time
import os
import json
import hashlib
import ubinascii
import machine


# ─────────────────────────────────────────────────────────────────────────────
# Crypto helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_mac():
    return ubinascii.hexlify(machine.unique_id()).decode()

def _sha256_str(s):
    return ubinascii.hexlify(hashlib.sha256(s.encode()).digest()).decode()

def _derive_key(length):
    mac  = _get_mac()
    key  = _sha256_str(mac + "HR-WiFi-Key-2024")
    while len(key) < length * 2:
        key += _sha256_str(key)
    return bytes(int(key[i*2:i*2+2], 16) for i in range(length))

def _xor_crypt(data_bytes, key_bytes):
    kl = len(key_bytes)
    return bytes(data_bytes[i] ^ key_bytes[i % kl] for i in range(len(data_bytes)))

def encrypt_wifi_password(plaintext):
    if not plaintext:
        return ""
    data = plaintext.encode("utf-8")
    key  = _derive_key(len(data))
    return ubinascii.hexlify(_xor_crypt(data, key)).decode()

def decrypt_wifi_password(ciphertext_hex):
    if not ciphertext_hex:
        return ""
    try:
        enc = ubinascii.unhexlify(ciphertext_hex)
        key = _derive_key(len(enc))
        return _xor_crypt(enc, key).decode("utf-8")
    except:
        return ""

def _random_token():
    mac = _get_mac()
    try:
        rnd = ubinascii.hexlify(os.urandom(16)).decode()
    except:
        rnd = "0"
    return _sha256_str(mac + str(time.ticks_ms()) + rnd)[:32]

def _default_password():
    return "HR-" + _sha256_str(_get_mac() + "HR-default-pw")[:8].upper()


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

def _load_config():
    try:
        with open("config.json") as f:
            return json.load(f)
    except:
        return {}

def _save_config(cfg):
    with open("config.json", "w") as f:
        json.dump(cfg, f)

def _get_device_id():
    return "HeartRate-{}".format(_get_mac().upper()[-4:])


# ─────────────────────────────────────────────────────────────────────────────
# HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _url_decode(s):
    result = ""
    i = 0
    while i < len(s):
        if s[i] == "%" and i + 2 < len(s):
            try:
                result += chr(int(s[i+1:i+3], 16))
                i += 3
            except:
                result += s[i]; i += 1
        elif s[i] == "+":
            result += " "; i += 1
        else:
            result += s[i]; i += 1
    return result

def _parse_form(body):
    fields = {}
    for pair in body.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            fields[_url_decode(k)] = _url_decode(v)
    return fields

def _parse_cookie(headers):
    for line in headers:
        if line.lower().startswith("cookie:"):
            for part in line[7:].split(";"):
                part = part.strip()
                if part.startswith("session="):
                    return part[8:].strip()
    return None

def _parse_request(conn):
    try:
        raw = b""
        conn.settimeout(5)
        while True:
            chunk = conn.recv(512)
            if not chunk:
                break
            raw += chunk
            if b"\r\n\r\n" in raw:
                break
    except:
        pass
    try:
        header_part, _, body_part = raw.partition(b"\r\n\r\n")
        lines  = header_part.decode("utf-8", "ignore").split("\r\n")
        parts  = lines[0].split(" ")
        method = parts[0] if len(parts) > 0 else "GET"
        path   = parts[1] if len(parts) > 1 else "/"
        if "?" in path:
            path = path.split("?")[0]
        headers = lines[1:]
        body    = body_part.decode("utf-8", "ignore")
        return method, path, headers, body
    except:
        return "GET", "/", [], ""

def _send(conn, status, ctype, body, extra=""):
    b = body.encode("utf-8")
    if extra and not extra.endswith("\r\n"):
        extra += "\r\n"
    h = (
        "HTTP/1.1 {}\r\n"
        "Content-Type: {}; charset=utf-8\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "{}\r\n"
    ).format(status, ctype, len(b), extra)
    conn.send(h.encode())
    conn.send(b)


# ─────────────────────────────────────────────────────────────────────────────
# HTML
# ─────────────────────────────────────────────────────────────────────────────

def _page_login(error="", device_id="HeartRate"):
    err = '<p class="err">{}</p>'.format(error) if error else ""
    return """<!DOCTYPE html>
<html lang="da"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{n} - Login</title>
<style>
body{{font-family:sans-serif;background:#1a1a2e;color:#eee;
     display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{background:#16213e;padding:2rem;border-radius:12px;width:300px;text-align:center}}
h2{{color:#e94560;margin-bottom:1.5rem}}
input{{width:100%;padding:.6rem;margin:.4rem 0;border-radius:6px;
       border:1px solid #444;background:#0f3460;color:#fff;box-sizing:border-box}}
button{{width:100%;padding:.7rem;margin-top:1rem;background:#e94560;
        border:none;border-radius:6px;color:#fff;font-size:1rem;cursor:pointer}}
.err{{color:#ff6b6b;font-size:.85rem;margin-top:.5rem}}
</style></head><body>
<div class="box">
<div style="font-size:3rem;margin-bottom:1rem">&#10084;&#65039;</div>
<h2>{n}</h2>
<form method="POST" action="/login" autocomplete="off">
<input type="password" name="password" placeholder="Adgangskode" autofocus>
<button type="submit">Log ind</button>
</form>{e}
</div></body></html>""".format(n=device_id, e=err)


def _page_wifi(device_id, networks):
    # Byg netvaerksliste direkte i HTML - ingen JavaScript scan noedvendig
    items = ""
    for ssid, rssi, secured in networks:
        lock = "&#128274;" if secured else "&#128275;"
        ssid_safe = ssid.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")
        ssid_js   = ssid.replace("\\", "\\\\").replace("'", "\\'")
        items += '<li onclick="sel(this)" data-ssid="{ss}">{lk} {ss} ({rs}dBm)</li>\n'.format(
            ss=ssid_safe, lk=lock, rs=rssi)

    if not items:
        items = '<li style="color:#aaa;cursor:default">Ingen netvaerk fundet</li>'

    return """<!DOCTYPE html>
<html lang="da"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{n} - WiFi</title>
<style>
body{{font-family:sans-serif;background:#1a1a2e;color:#eee;padding:1rem;margin:0}}
h2{{color:#e94560;text-align:center}}
ul{{list-style:none;padding:0;margin:0}}
li{{padding:.8rem;margin:.4rem 0;background:#16213e;border-radius:8px;
    cursor:pointer;border:2px solid transparent}}
li.sel{{border-color:#e94560}}
input{{width:100%;padding:.6rem;margin:.4rem 0;border-radius:6px;
       border:1px solid #444;background:#0f3460;color:#fff;box-sizing:border-box}}
button{{width:100%;padding:.7rem;margin-top:.5rem;background:#e94560;
        border:none;border-radius:6px;color:#fff;font-size:1rem;cursor:pointer}}
button:disabled{{background:#555;cursor:not-allowed}}
.rfr{{background:#0f3460;margin-bottom:.5rem}}
.info{{color:#aaa;font-size:.85rem;text-align:center;margin-top:1rem}}
a{{color:#e94560}}
</style></head><body>
<h2>&#10084;&#65039; {n} - WiFi</h2>
<button class="rfr" onclick="window.location='/wifi'">&#128260; Scan igen</button>
<ul id="list">
{items}
</ul>
<form method="POST" action="/wifi/connect" autocomplete="off">
<input type="hidden" name="ssid" id="ssid">
<input type="password" name="password" id="pw"
       placeholder="WiFi adgangskode (tom hvis aabent)" autocomplete="new-password">
<button type="submit" id="btn" disabled>Tilslut</button>
</form>
<p class="info">
<a href="/change-password">Skift adgangskode</a> |
<a href="/ota">OTA</a> |
<a href="/data">Data</a>
</p>
<script>
function sel(el){{
  document.querySelectorAll("li").forEach(function(l){{l.classList.remove("sel")}});
  el.classList.add("sel");
  document.getElementById("ssid").value=el.dataset.ssid;
  document.getElementById("btn").disabled=false;
  document.getElementById("pw").focus();
}}
</script>
</body></html>""".format(n=device_id, items=items)


def _page_home(device_id):
    return """<!DOCTYPE html>
<html lang="da"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{n} - Hjem</title>
<style>
body{{font-family:sans-serif;background:#1a1a2e;color:#eee;
     display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{background:#16213e;padding:2rem;border-radius:12px;width:320px;text-align:center}}
h2{{color:#e94560;margin-bottom:2rem}}
.btn{{display:block;width:100%;padding:.9rem;margin:.6rem 0;border:none;
      border-radius:8px;font-size:1rem;cursor:pointer;text-decoration:none;
      box-sizing:border-box}}
.btn-data{{background:#e94560;color:#fff}}
.btn-wifi{{background:#0f3460;color:#fff}}
.btn-data:hover{{background:#c73652}}
.btn-wifi:hover{{background:#1a4a7a}}
nav{{margin-top:1.5rem;font-size:.85rem}}
a{{color:#aaa}}
</style></head><body>
<div class="box">
<div style="font-size:3rem;margin-bottom:1rem">&#10084;&#65039;</div>
<h2>{n}</h2>
<a href="/data" class="btn btn-data">&#128200; Se data</a>
<a href="/wifi" class="btn btn-wifi">&#128246; WiFi indstillinger</a>
<nav><a href="/logout">Log ud</a></nav>
</div></body></html>""".format(n=device_id)


def _page_change_password(error="", success=""):
    msg = ""
    if error:   msg = '<p style="color:#ff6b6b">{}</p>'.format(error)
    if success: msg = '<p style="color:#6bff8e">{}</p>'.format(success)
    return """<!DOCTYPE html>
<html lang="da"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Skift adgangskode</title>
<style>
body{{font-family:sans-serif;background:#1a1a2e;color:#eee;
     display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{background:#16213e;padding:2rem;border-radius:12px;width:320px}}
h2{{color:#e94560;text-align:center}}
input{{width:100%;padding:.6rem;margin:.4rem 0;border-radius:6px;
       border:1px solid #444;background:#0f3460;color:#fff;box-sizing:border-box}}
button{{width:100%;padding:.7rem;margin-top:.5rem;background:#e94560;
        border:none;border-radius:6px;color:#fff;font-size:1rem;cursor:pointer}}
a{{color:#e94560;display:block;text-align:center;margin-top:1rem}}
</style></head><body>
<div class="box">
<h2>&#128273; Skift adgangskode</h2>{m}
<form method="POST" action="/change-password" autocomplete="off">
<input type="password" name="current" placeholder="Nuvaerende adgangskode">
<input type="password" name="new1" placeholder="Ny adgangskode (min. 8 tegn)">
<input type="password" name="new2" placeholder="Bekraeft ny adgangskode">
<button type="submit">Skift</button>
</form>
<a href="/wifi">&#8592; Tilbage</a>
</div></body></html>""".format(m=msg)


def _page_connecting(ssid):
    return """<!DOCTYPE html>
<html lang="da"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="12;url=/wifi/status">
<title>Tilslutter...</title>
<style>
body{{font-family:sans-serif;background:#1a1a2e;color:#eee;
     display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{text-align:center}}
.sp{{font-size:3rem;animation:spin 1s linear infinite;display:inline-block}}
@keyframes spin{{from{{transform:rotate(0deg)}}to{{transform:rotate(360deg)}}}}
</style></head><body>
<div class="box">
<div class="sp">&#9203;</div>
<h2>Tilslutter til {}</h2>
<p>Vent venligst...</p>
</div></body></html>""".format(ssid)


def _page_ota(error="", success="", ota_url=""):
    msg = ""
    if error:   msg = '<p style="color:#ff6b6b">{}</p>'.format(error)
    if success: msg = '<p style="color:#6bff8e">{}</p>'.format(success)
    return """<!DOCTYPE html>
<html lang="da"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OTA</title>
<style>
body{{font-family:sans-serif;background:#1a1a2e;color:#eee;padding:1rem;max-width:500px;margin:0 auto}}
h2{{color:#e94560;text-align:center}}
input{{width:100%;padding:.6rem;margin:.4rem 0;border-radius:6px;
       border:1px solid #444;background:#0f3460;color:#fff;box-sizing:border-box}}
button{{width:100%;padding:.7rem;margin-top:.5rem;background:#e94560;
        border:none;border-radius:6px;color:#fff;font-size:1rem;cursor:pointer}}
.info{{color:#aaa;font-size:.8rem;margin:.5rem 0}}
a{{color:#e94560;display:block;text-align:center;margin-top:1rem}}
</style></head><body>
<h2>&#128260; OTA</h2>{m}
<form method="POST" action="/ota/update">
<label>GitHub raw URL:</label>
<input type="text" name="ota_url" value="{u}"
       placeholder="https://raw.githubusercontent.com/...">
<p class="info">manifest.json skal indeholde filliste + SHA256 checksums</p>
<button type="submit">Start opdatering</button>
</form>
<a href="/wifi">&#8592; Tilbage</a>
</body></html>""".format(m=msg, u=ota_url)


def _page_data(device_id):
    return """<!DOCTYPE html>
<html lang="da"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{n} - Data</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:sans-serif;background:#1a1a2e;color:#eee;margin:0;padding:1rem}}
h2{{color:#e94560;text-align:center;margin-bottom:.5rem}}
.bx{{text-align:center;margin:1.5rem 0}}
.bv{{font-size:5rem;font-weight:bold;color:#e94560;line-height:1}}
.bl{{color:#aaa;font-size:1rem;margin-top:.2rem}}
.ht{{display:inline-block;animation:beat 1s infinite}}
@keyframes beat{{0%,100%{{transform:scale(1)}}50%{{transform:scale(1.2)}}}}
canvas{{width:100%;background:#16213e;border-radius:8px;display:block}}
.st{{text-align:center;color:#aaa;font-size:.85rem;margin-top:1rem}}
a{{color:#e94560}}
nav{{text-align:center;margin-top:1.5rem;font-size:.9rem}}
</style></head><body>
<h2><span class="ht">&#10084;&#65039;</span> {n}</h2>
<div class="bx">
<div class="bv" id="bpm">--</div>
<div class="bl">BPM</div>
</div>
<canvas id="chart" height="120"></canvas>
<p class="st" id="st">Henter data...</p>
<nav><a href="/wifi">&#9881;&#65039; Indstillinger</a> | <a href="/logout">Log ud</a></nav>
<script>
var MAX=60,pts=[];
var cv=document.getElementById("chart"),ctx=cv.getContext("2d");
function draw(){{
  var W=cv.width=cv.offsetWidth,H=cv.height;
  ctx.clearRect(0,0,W,H);
  if(pts.length<2)return;
  var vs=pts.map(function(p){{return p.bpm;}});
  var mn=Math.max(30,Math.min.apply(null,vs)-5);
  var mx=Math.min(220,Math.max.apply(null,vs)+5);
  var xs=W/(MAX-1);
  ctx.beginPath();ctx.strokeStyle="#e94560";ctx.lineWidth=2;
  pts.forEach(function(p,i){{
    var x=i*xs,y=H-((p.bpm-mn)/(mx-mn))*(H-10)-5;
    i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
  }});
  ctx.stroke();
  ctx.lineTo((pts.length-1)*xs,H);ctx.lineTo(0,H);ctx.closePath();
  ctx.fillStyle="rgba(233,69,96,0.15)";ctx.fill();
}}
async function fetchData(){{
  try{{
    var r=await fetch("/api/bpm");
    if(r.status===302||r.status===401){{window.location="/login";return;}}
    var d=await r.json();
    document.getElementById("bpm").textContent=d.bpm>0?d.bpm:"--";
    document.getElementById("st").textContent=
      d.bpm>0?"Maaler... opdateres hvert 2 sek":
              "Ingen puls - saet fingeren paa sensoren";
    if(d.history&&d.history.length>0){{pts=d.history.slice(-MAX);draw();}}
  }}catch(e){{document.getElementById("st").textContent="Fejl: "+e.message;}}
}}
fetchData();setInterval(fetchData,2000);
window.addEventListener("resize",draw);
</script>
</body></html>""".format(n=device_id)


# ─────────────────────────────────────────────────────────────────────────────
# DNS
# ─────────────────────────────────────────────────────────────────────────────

class DNSServer:
    def __init__(self, ip="192.168.4.1"):
        self._ip   = ip
        self._sock = None
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setblocking(False)
            self._sock.bind(("0.0.0.0", 53))
        except:
            if self._sock:
                try: self._sock.close()
                except: pass
            self._sock = None

    def handle(self):
        if not self._sock: return
        try:
            data, addr = self._sock.recvfrom(512)
            r  = data[:2] + b"\x81\x80"
            r += data[4:6] + data[4:6]
            r += b"\x00\x00\x00\x00"
            r += data[12:]
            r += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
            r += bytes(int(x) for x in self._ip.split("."))
            self._sock.sendto(r, addr)
        except:
            pass

    def close(self):
        if self._sock:
            try: self._sock.close()
            except: pass
            self._sock = None


# ─────────────────────────────────────────────────────────────────────────────
# WiFiManager
# ─────────────────────────────────────────────────────────────────────────────

class WiFiManager:

    AP_IP = "192.168.4.1"

    def __init__(self):
        self._cfg       = _load_config()
        self._device_id = self._cfg.get("device_id") or _get_device_id()
        self._sessions  = {}
        self._attempts  = []
        self._sta       = network.WLAN(network.STA_IF)
        self._ap        = network.WLAN(network.AP_IF)
        self._dns       = None

        if not self._cfg.get("password_hash"):
            pw = _default_password()
            self._cfg["password_hash"] = _sha256_str(pw)
            print("\n" + "="*44)
            print("  STANDARD ADGANGSKODE: {}".format(pw))
            print("  Skift den via /change-password !")
            print("="*44 + "\n")

        if not self._cfg.get("device_id"):
            self._cfg["device_id"] = self._device_id

        _save_config(self._cfg)

    def _new_session(self):
        token   = _random_token()
        timeout = self._cfg.get("session_timeout", 300)
        now     = time.ticks_ms()
        self._sessions[token] = now + timeout * 1000
        self._sessions = {t: e for t, e in self._sessions.items()
                          if time.ticks_diff(e, now) > 0}
        return token

    def _valid_session(self, token):
        if not token or token not in self._sessions:
            return False
        if time.ticks_diff(self._sessions[token], time.ticks_ms()) <= 0:
            del self._sessions[token]
            return False
        return True

    def _check_auth(self, headers):
        return self._valid_session(_parse_cookie(headers))

    def _check_password(self, pw):
        stored = self._cfg.get("password_hash", "")
        return bool(stored) and _sha256_str(pw) == stored

    def _rate_limited(self):
        now = time.ticks_ms()
        self._attempts = [t for t in self._attempts
                          if time.ticks_diff(now, t) < 60000]
        return len(self._attempts) >= 5

    def _failed_attempt(self):
        self._attempts.append(time.ticks_ms())

    def connect_sta(self, timeout=20):
        ssid = self._cfg.get("wifi_ssid", "")
        enc  = self._cfg.get("wifi_password_enc", "")
        pw   = decrypt_wifi_password(enc) if enc else self._cfg.get("wifi_password", "")
        if not ssid:
            return False
        print("[WiFi] Forsøger: {}".format(ssid))
        self._sta.active(True)
        self._sta.connect(ssid, pw)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._sta.isconnected():
                print("[WiFi] Tilsluttet! IP: {}".format(self._sta.ifconfig()[0]))
                return True
            time.sleep(0.5)
        print("[WiFi] Fejlede.")
        self._sta.active(False)
        return False

    def _connect_new(self, ssid, password):
        self._sta.active(True)
        self._sta.connect(ssid, password)
        deadline = time.ticks_ms() + 20000
        while time.ticks_diff(deadline, time.ticks_ms()) > 0:
            if self._sta.isconnected():
                self._cfg["wifi_ssid"]         = ssid
                self._cfg["wifi_password_enc"] = encrypt_wifi_password(password)
                self._cfg.pop("wifi_password", None)
                _save_config(self._cfg)
                return True
            time.sleep(0.5)
        return False

    def start_ap(self):
        ap_pw = _default_password()
        self._ap.active(True)
        self._ap.config(
            essid=self._device_id,
            password=ap_pw,
            authmode=network.AUTH_WPA2_PSK
        )
        self._ap.ifconfig((self.AP_IP, "255.255.255.0", self.AP_IP, self.AP_IP))
        print("[AP] Startet: {} @ {}".format(self._device_id, self.AP_IP))
        print("[AP] WPA2 kode: {}".format(ap_pw))
        self._dns = DNSServer(self.AP_IP)

    def stop_ap(self):
        if self._dns:
            self._dns.close()
            self._dns = None
        self._ap.active(False)
        print("[AP] Stoppet.")

    def scan_networks(self):
        try:
            self._sta.active(False)
            time.sleep(0.5)
            self._sta.active(True)
            if self._sta.isconnected():
                self._sta.disconnect()
            time.sleep(1)
            results = self._sta.scan()
            seen, nets = set(), []
            for r in sorted(results, key=lambda x: -x[3]):
                ssid = r[0].decode("utf-8", "ignore")
                if ssid and ssid not in seen:
                    seen.add(ssid)
                    nets.append((ssid, r[3], r[4] != 0))
            print("[WiFi] Fandt {} netvaerk".format(len(nets)))
            return nets[:15]
        except Exception as e:
            print("[WiFi] Scan fejl: {}".format(e))
            return []

    def handle_request(self, conn, addr, sensor=None):
        method, path, headers, body = _parse_request(conn)
        auth = self._check_auth(headers)
        ip   = self.ip

        portal_paths = [
            "/generate_204", "/connecttest.txt", "/hotspot-detect.html",
            "/ncsi.txt", "/success.txt", "/canonical.html", "/redirect"
        ]

        # Captive portal OS paths
        if path in portal_paths:
            _send(conn, "302 Found", "text/html", "",
                  "Location: http://{}/login\r\n".format(ip))
            conn.close()
            return

        # Ikke logget ind
        if not auth and path not in ["/login", "/favicon.ico"]:
            _send(conn, "302 Found", "text/html", "",
                  "Location: http://{}/login\r\n".format(ip))
            conn.close()
            return

        # GET /login
        if path == "/login" and method == "GET":
            _send(conn, "200 OK", "text/html", _page_login(device_id=self._device_id))

        # POST /login
        elif path == "/login" and method == "POST":
            if self._rate_limited():
                time.sleep(2)
                _send(conn, "200 OK", "text/html",
                      _page_login("For mange forsog. Vent et minut.", self._device_id))
            else:
                pw = _parse_form(body).get("password", "")
                if self._check_password(pw):
                    token = self._new_session()
                    _send(conn, "302 Found", "text/html", "",
                          "Location: /home\r\n"
                          "Set-Cookie: session={}; HttpOnly; Path=/\r\n".format(token))
                else:
                    self._failed_attempt()
                    time.sleep(1)
                    _send(conn, "200 OK", "text/html",
                          _page_login("Forkert adgangskode", self._device_id))

        # GET /home - forside
        elif path == "/home" and auth:
            _send(conn, "200 OK", "text/html", _page_home(self._device_id))

        # GET /wifi — scan kun hvis ikke allerede forbundet
        elif path == "/wifi" and auth:
            if self._sta.isconnected():
                nets = []
            else:
                nets = self.scan_networks()
            _send(conn, "200 OK", "text/html", _page_wifi(self._device_id, nets))

        # POST /wifi/connect
        elif path == "/wifi/connect" and method == "POST" and auth:
            fields = _parse_form(body)
            ssid   = fields.get("ssid", "")
            pw     = fields.get("password", "")
            if ssid:
                _send(conn, "200 OK", "text/html", _page_connecting(ssid))
                conn.close()
                self._connect_new(ssid, pw)
                return
            _send(conn, "302 Found", "text/html", "", "Location: /wifi\r\n")

        # GET /wifi/status
        elif path == "/wifi/status" and auth:
            if self._sta.isconnected():
                sip  = self._sta.ifconfig()[0]
                html = ('<html><body style="font-family:sans-serif;background:#1a1a2e;'
                        'color:#eee;text-align:center;padding:2rem">'
                        '<h2 style="color:#6bff8e">Tilsluttet!</h2>'
                        '<p>IP: <strong>{}</strong></p>'
                        '<p><a style="color:#e94560" href="http://{}/data">'
                        'Ga til data</a></p></body></html>').format(sip, sip)
            else:
                html = ('<html><body style="font-family:sans-serif;background:#1a1a2e;'
                        'color:#eee;text-align:center;padding:2rem">'
                        '<h2 style="color:#ff6b6b">Tilslutning fejlede</h2>'
                        '<p><a style="color:#e94560" href="/wifi">Prov igen</a></p>'
                        '</body></html>')
            _send(conn, "200 OK", "text/html", html)

        # GET /change-password
        elif path == "/change-password" and method == "GET" and auth:
            _send(conn, "200 OK", "text/html", _page_change_password())

        # POST /change-password
        elif path == "/change-password" and method == "POST" and auth:
            f    = _parse_form(body)
            cur  = f.get("current", "")
            new1 = f.get("new1", "")
            new2 = f.get("new2", "")
            if not self._check_password(cur):
                _send(conn, "200 OK", "text/html",
                      _page_change_password(error="Forkert nuvaerende adgangskode"))
            elif len(new1) < 8:
                _send(conn, "200 OK", "text/html",
                      _page_change_password(error="Min. 8 tegn kraeves"))
            elif new1 != new2:
                _send(conn, "200 OK", "text/html",
                      _page_change_password(error="Adgangskoderne matcher ikke"))
            else:
                self._cfg["password_hash"] = _sha256_str(new1)
                _save_config(self._cfg)
                self._sessions = {}
                _send(conn, "200 OK", "text/html",
                      _page_change_password(success="Adgangskode aendret - log ind igen"))

        # GET /ota
        elif path == "/ota" and method == "GET" and auth:
            _send(conn, "200 OK", "text/html",
                  _page_ota(ota_url=self._cfg.get("ota_url", "")))

        # POST /ota/update
        elif path == "/ota/update" and method == "POST" and auth:
            f = _parse_form(body)
            u = f.get("ota_url", "").strip()
            if u:
                self._cfg["ota_url"] = u
                _save_config(self._cfg)
            _send(conn, "200 OK", "text/html",
                  _page_ota(success="OTA startet - genstarter...",
                             ota_url=self._cfg.get("ota_url", "")))
            conn.close()
            with open("ota_trigger.txt", "w") as f2:
                f2.write("1")
            return

        # GET /api/bpm
        elif path == "/api/bpm" and auth:
            bpm  = sensor.bpm if sensor else 0
            hist = sensor.history_json() if sensor else "[]"
            _send(conn, "200 OK", "application/json",
                  '{{"bpm":{},"history":{}}}'.format(bpm, hist))

        # GET /data
        elif path == "/data" and auth:
            _send(conn, "200 OK", "text/html", _page_data(self._device_id))

        # GET /logout
        elif path == "/logout":
            token = _parse_cookie(headers)
            if token and token in self._sessions:
                del self._sessions[token]
            _send(conn, "302 Found", "text/html", "",
                  "Location: /login\r\n"
                  "Set-Cookie: session=; Max-Age=0; Path=/\r\n")

        # 404
        else:
            _send(conn, "404 Not Found", "text/html",
                  "<html><body><h1>404</h1><a href='/wifi'>Hjem</a></body></html>")

        conn.close()

    def handle_dns(self):
        if self._dns:
            self._dns.handle()

    @property
    def ip(self):
        if self._sta.isconnected():
            return self._sta.ifconfig()[0]
        return self.AP_IP