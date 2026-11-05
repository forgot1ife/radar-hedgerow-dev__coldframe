"""Low-interaction decoy for supermarket refrigeration controllers.

Personas:
  danfoss  Danfoss AK-SM 800A system manager: StoreView Web login page and
           the XML API at /html/xml.cgi, with known exploit attempts tagged.
  dixell   Copeland/Dixell XWEB 500 supervisor: login page and the CGI
           upload paths used by public exploits, tagged.

Optional Modbus TCP with fake case temperatures and setpoints; writes,
including "defrost" commands, are logged. Off unless MODBUS_PORT is set.

Nothing here runs commands, serves files from disk or forwards traffic.
Every event is one JSON line on stdout and appended to LOG_PATH.

    PERSONA=danfoss HTTP_PORT=8080 HTTPS_PORT=8443 python3 honeypot.py
"""

import json
import os
import random
import re
import secrets
import signal
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from email.utils import formatdate
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PERSONA = os.environ.get("PERSONA", "danfoss")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "0"))      # 0 = off
MODBUS_PORT = int(os.environ.get("MODBUS_PORT", "0"))    # 0 = off
CERT_FILE = os.environ.get("CERT_FILE", "cert.pem")
KEY_FILE = os.environ.get("KEY_FILE", "key.pem")
LOG_PATH = os.environ.get("LOG_PATH", "events.jsonl")
# Optional: the real device's favicon, for private deployments only. It is the
# vendor's artwork, so it is not shipped in this repository.
FAVICON_FILE = os.environ.get("FAVICON_FILE", "")

MAX_BODY = 8192        # bytes of request body we will read
MAX_FIELD = 512        # chars of any logged string
MAX_LINE = 8192        # bytes of one log line, after JSON escaping
MAX_CONNS = 256        # concurrent connections across all services
MAX_PER_IP = 8         # concurrent connections from one source address
MAX_LOG_BYTES = 256 * 1024 * 1024  # rotate past this size...
LOG_KEEP = 4           # ...keeping LOG_PATH.1 to LOG_PATH.4
SOCKET_TIMEOUT = 15    # seconds of silence before a socket is dropped
CONN_DEADLINE = 30     # seconds any connection may live, however it trickles

# Strings below come from public vendor manuals and security advisories.
# See README.md for sources.
PERSONAS = {
    "danfoss": {
        "server": "nginx",
        "vendor": "Danfoss",
        "product": "AK-SM 880A",
        "firmware": "SVB501.000.139",  # pre-R4.3.1, still has the code-of-the-day path
        "not_found": "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n"
                     "<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n"
                     "</body>\r\n</html>\r\n",
    },
    "dixell": {
        "server": "Apache",
        "vendor": "Dixell",
        "product": "XWEB500",
        "firmware": "1.8.2",
        "not_found": '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n'
                     "<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n"
                     "<p>The requested URL was not found on this server.</p>\n</body></html>\n",
    },
}
P = PERSONAS[PERSONA]
FIRMWARE_MTIME = 0x6A198BB7  # Fri, 29 May 2026 12:51:03 GMT, as on a real unit
FAVICON = b""
if FAVICON_FILE:
    with open(FAVICON_FILE, "rb") as f:
        FAVICON = f.read(65536)

_log_lock = threading.Lock()
_slots_lock = threading.Lock()
_active = {}  # source IP -> open connections


def take_slot(ip):
    """Reserve a connection slot, so one source cannot crowd out the others."""
    with _slots_lock:
        if sum(_active.values()) >= MAX_CONNS or _active.get(ip, 0) >= MAX_PER_IP:
            return False
        _active[ip] = _active.get(ip, 0) + 1
        return True


def give_slot(ip):
    with _slots_lock:
        _active[ip] -= 1
        if not _active[ip]:
            del _active[ip]


_refused = {}  # source IP -> when we last logged a refusal


def note_refused(src):
    """Log refused connections, at most once a minute per source."""
    now = time.monotonic()
    with _slots_lock:
        if now - _refused.get(src[0], -60.0) < 60:
            return
        if len(_refused) > 10000:
            _refused.clear()
        _refused[src[0]] = now
    log("tcp", src, "conn_refused")


_watch_lock = threading.Lock()
_watched = {}  # socket -> monotonic deadline


def watch(sock):
    with _watch_lock:
        _watched[sock] = time.monotonic() + CONN_DEADLINE


def unwatch(sock):
    with _watch_lock:
        _watched.pop(sock, None)


def reaper():
    """Cut connections past CONN_DEADLINE, so slow drips cannot hold slots."""
    while True:
        time.sleep(1)
        now = time.monotonic()
        with _watch_lock:
            for sock, deadline in list(_watched.items()):
                if now > deadline:
                    del _watched[sock]
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass


class Guarded:
    """Server mixin: apply the connection caps before a thread is started."""

    daemon_threads = True

    def process_request(self, request, client_address):
        if not take_slot(client_address[0]):
            note_refused(client_address)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except RuntimeError:  # could not start a thread
            give_slot(client_address[0])
            self.shutdown_request(request)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            give_slot(client_address[0])

    def handle_error(self, request, client_address):
        # Dropped and reset sockets are routine here; anything else is a bug.
        exc = sys.exc_info()[1]
        if not isinstance(exc, OSError):
            log("system", client_address, "internal_error", error=repr(exc))


def clip(value):
    text = value if isinstance(value, str) else repr(value)
    return text[:MAX_FIELD]


def log(proto, src, event, **details):
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "persona": PERSONA,
        "proto": proto,
        "src_ip": src[0],
        "src_port": src[1],
        "event": event,
    }
    record.update({k: clip(v) if isinstance(v, str) else v for k, v in details.items()})
    line = json.dumps(record, ensure_ascii=True)
    if len(line) > MAX_LINE:  # escaping can grow binary junk about 6x
        for k in details:
            record[k] = clip(record[k])[:64]
        record["truncated"] = True
        line = json.dumps(record, ensure_ascii=True)
    with _log_lock:
        print(line, flush=True)
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
            full = f.tell() > MAX_LOG_BYTES
        if full:
            for i in range(LOG_KEEP - 1, 0, -1):
                if os.path.exists(f"{LOG_PATH}.{i}"):
                    os.replace(f"{LOG_PATH}.{i}", f"{LOG_PATH}.{i + 1}")
            os.replace(LOG_PATH, LOG_PATH + ".1")


# --- Danfoss AK-SM 800A -------------------------------------------------------
# Layout follows the local-screen login in the AK-SM 800A user guide.

DANFOSS_LOGIN = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Danfoss StoreView</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#fff;color:#333}
.bar{background:#e2000f;color:#fff;font-size:12px;text-align:right;padding:4px 10px;height:14px}
.box{width:300px;margin:60px auto;text-align:center}
.brand{color:#e2000f;font:italic bold 30px Georgia,serif;margin-bottom:18px}
h1{color:#e2000f;font-size:15px;margin:0 0 22px}
.row{display:flex;align-items:center;justify-content:center;margin:10px 0;font-size:13px}
.row label{width:80px;text-align:left}.row input[type=text],.row input[type=password]{width:170px;padding:6px;border:1px solid #bbb}
.show{position:absolute;margin-left:300px;font-size:12px;color:#888}
button{display:block;width:194px;margin:12px 0 0 80px;padding:8px;font-size:13px;border:1px solid #bbb;background:#fff;cursor:pointer}
.forgot{background:#eee;color:#999}.signin{background:#323a45;color:#fff;font-weight:bold;margin-top:28px}
.err{color:#e2000f;font-size:12px;min-height:16px;margin-top:14px}
.dash{max-width:760px;margin:24px auto;font-size:13px}.dash h1{text-align:left}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px;border-bottom:1px solid #ddd}
th{background:#323a45;color:#fff;font-weight:normal}td button{width:auto;margin:0;padding:3px 8px}</style></head>
<body><div class="bar" id="clock"></div><div class="box">
<div class="brand">Danfoss</div><h1>Danfoss System Manager - SM800A</h1>
<form id="f"><div class="row"><label for="u">User name</label><input type="text" id="u" autocomplete="off"></div>
<div class="row"><label for="p">Password</label><input type="password" id="p">
<label class="show"><input type="checkbox" id="s"> Show</label></div>
<button type="button" class="forgot">Forgot credentials..</button>
<button type="submit" class="signin">Sign In</button><button type="reset">Cancel</button>
<div class="err" id="e"></div></form></div>
<script>
function tick(){var d=new Date(),p=function(n){return(n<10?'0':'')+n},h=d.getHours();
document.getElementById('clock').textContent=p(d.getMonth()+1)+'/'+p(d.getDate())+'/'+String(d.getFullYear()).slice(2)+' '+p(h%12||12)+':'+p(d.getMinutes())+':'+p(d.getSeconds())+(h<12?' AM':' PM')}
tick();setInterval(tick,1000);
document.getElementById('s').onchange=function(){document.getElementById('p').type=this.checked?'text':'password'};
function x(s){return s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;')}
var tok='';
function api(cmd){return fetch('/html/xml.cgi',{method:'POST',headers:{'Content-Type':'text/xml','AKSM-Auth':tok},body:cmd})
.then(function(r){return r.text()}).then(function(t){return new DOMParser().parseFromString(t,'text/xml')})}
function cell(tr,text){var td=document.createElement('td');td.textContent=text;tr.appendChild(td);return td}
function load(){api('<cmd action="read_devices"/>').then(function(d){var tb=document.getElementById('cases');tb.innerHTML='';
[].forEach.call(d.getElementsByTagName('device'),function(v){var tr=document.createElement('tr'),n=v.getAttribute('node');
cell(tr,v.getAttribute('name'));cell(tr,v.getAttribute('temp')+' °C');cell(tr,v.getAttribute('setpoint')+' °C');
cell(tr,v.getAttribute('defrost')=='1'?'Defrost':'Cooling');var b=document.createElement('button');b.textContent='Start defrost';
b.onclick=function(){api('<cmd action="start_defrost" node="'+n+'"/>').then(load)};cell(tr,'').appendChild(b);tb.appendChild(tr)})})}
function dash(){api('<cmd action="read_units"/>').then(function(d){var n=d.getElementsByTagName('store_name')[0];
document.body.innerHTML='<div class="bar" id="clock"></div><div class="dash"><h1 id="st"></h1>'+
'<table><thead><tr><th>Case</th><th>Air temp</th><th>Setpoint</th><th>State</th><th></th></tr></thead><tbody id="cases"></tbody></table></div>';
document.getElementById('st').textContent=n?n.textContent:'';tick();load();setInterval(load,10000)})}
document.getElementById('f').onsubmit=function(ev){ev.preventDefault();
var b='<cmd action="getauth" user="'+x(document.getElementById('u').value)+'" password="'+x(document.getElementById('p').value)+'" lang="English"/>';
api(b).then(function(d){var t=d.getElementsByTagName('session_token')[0];
if(t){tok=t.textContent;dash()}else{document.getElementById('e').textContent='Invalid user name or password'}})};
</script></body></html>"""

NOT_ALLOWED = ("<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n"
               "<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")

DANFOSS_STATIC_HEADERS = [
    ("Access-Control-Allow-Origin", "*"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
    ("Access-Control-Allow-Headers",
     "aksm-auth,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type"),
    ("Cache-Control", "no-store, no-cache"),
    ("Accept-Ranges", "bytes"),
]

CMD_RE = re.compile(r"<cmd\b([^>]{0,2000})>", re.S)
ATTR_RE = re.compile(r'([A-Za-z_][\w.-]*)\s*=\s*"([^"]*)"')


def danfoss_exploit_tag(action, attrs):
    """Name the public exploit a command matches, if any."""
    if action == "get_file" and ".." in attrs.get("filename", ""):
        return "CVE-2023-25914 path traversal"
    if action == "load_cert":
        return "CVE-2023-25915 command injection"
    if action == "load_nginx_headers":
        return "CVE-2025-41452 nginx header overwrite"
    if "eds_only" in attrs or "quantum_only" in attrs:
        return "SM800 code-of-the-day auth bypass"
    return ""


# Logins that "work", so we can watch what attackers do next. Supervisor/12345
# is reported as an AK-SM factory default; the others are common guesses.
WEAK_LOGINS = {("supervisor", "12345"), ("superviseur", "12345"), ("admin", "admin"), ("admin", "1234")}
STORE_NAME = "Fresh Market 0412"
SESSION_TTL = 3600
_sessions = {}  # token -> expiry (monotonic)
_sessions_lock = threading.Lock()


def code_of_the_day(day):
    """The CVE-2025-41450 bypass code, as published by Ironhackers."""
    s = "%02d%02d%02d%02d" % (day.month, day.day, day.year % 100, day.month)
    return "%05d" % ((int(s, 16) // int("%02d" % day.day, 16)) % 100000)


def valid_codes():
    today = datetime.now(timezone.utc).date()  # allow for the unit's timezone
    return {code_of_the_day(today + timedelta(days=d)) for d in (-1, 0, 1)}


def new_session():
    token = secrets.token_hex(32)
    now = time.monotonic()
    with _sessions_lock:
        for t, expiry in list(_sessions.items()):
            if expiry < now:
                del _sessions[t]
        if len(_sessions) > 1000:
            _sessions.clear()
        _sessions[token] = now + SESSION_TTL
    return token


def has_session(token):
    with _sessions_lock:
        return _sessions.get(token, 0) > time.monotonic()


def danfoss_xml(src, proto, body, headers):
    match = CMD_RE.search(body)
    pairs = ATTR_RE.findall(match.group(1))[:16] if match else []
    attrs = {k[:32]: v[:256] for k, v in pairs}
    action = attrs.get("action", "")
    token = headers.get("AKSM-Auth", "")
    exploit = danfoss_exploit_tag(action, attrs)
    authed = has_session(token)

    granted = False
    user, password = attrs.get("user", ""), attrs.get("password", attrs.get("pass", ""))
    if action == "getauth" or "user" in attrs or "pass" in attrs:
        if "eds_only" in attrs or "quantum_only" in attrs:
            granted = password in valid_codes()
            exploit = "CVE-2025-41450 code-of-the-day bypass" + (", correct code" if granted else "")
        else:
            granted = (user.lower(), password) in WEAK_LOGINS
    authed = authed or granted  # user=/pass= on any command is the pre-4.0 auth style
    log(proto, src, "xml_cmd", action=action, attrs=attrs, auth_header=token,
        session=authed, exploit=exploit)
    if action == "getauth" or "user" in attrs or "pass" in attrs:
        log(proto, src, "login_attempt", username=user, password=password, granted=granted)
        time.sleep(random.uniform(0.6, 1.4))

    head = '<?xml version="1.0" encoding="utf-8"?>\n'
    act = escape(action)
    if action == "read_date_time":  # answered without login on real units
        now = datetime.now()
        return head + (f'<resp action="read_date_time" error="0"><year>{now.year}</year>'
                       f'<month>{now.month}</month><day>{now.day}</day><hour>{now.hour}</hour>'
                       f'<minute>{now.minute}</minute><second>{now.second}</second></resp>')
    if action == "getauth":
        if not granted:  # denial shape per the Ironhackers write-up
            return head + '<resp action="getauth" error="0"><authtype>-1</authtype><accesslevel>255</accesslevel></resp>'
        return head + ('<resp action="getauth" error="0"><authorization>01-01</authorization>'
                       '<authtype>16777215</authtype><access>01-01</access><accesslevel>1</accesslevel>'
                       f'<strongpassword>1</strongpassword><session_token>{new_session()}</session_token></resp>')
    if not authed:
        # 15 is the documented "failed in authorization" code.
        return head + f'<resp action="{act}" error="15"/>'

    if action == "read_units":
        return head + (f'<resp action="read_units" error="0"><store_name>{STORE_NAME}</store_name>'
                       f'<software>{P["firmware"]}</software><macaddr>00:0a:5c:3e:91:4d</macaddr>'
                       '<port>80</port></resp>')
    if action == "read_devices":
        rows = "".join(f'<device node="{n + 1}" name="{CASE_NAMES[n]}" temp="{t / 10:.1f}" '
                       f'setpoint="{sp / 10:.1f}" defrost="{d}"/>' for n, (t, sp, d) in enumerate(case_status()))
        return head + f'<resp action="read_devices" error="0">{rows}</resp>'
    # Anything else from a logged-in session is a control attempt: accept, log, do nothing real.
    node = attrs.get("node", "")
    defrost = "defrost" in action.lower()
    log(proto, src, "control", action=action, node=node, defrost=defrost)
    if defrost and node.isdigit() and 1 <= int(node) <= len(CASE_NAMES):
        write_registers(200 + int(node) - 1, [1])
    return head + f'<resp action="{act}" error="0"/>'


# --- Dixell XWEB 500 ----------------------------------------------------------

DIXELL_LOGIN = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>XWEB500</title>
<style>body{{font-family:Arial,sans-serif;background:#eef1f4;margin:0}}
.box{{width:320px;margin:120px auto;background:#fff;padding:24px;border:1px solid #c8ced6}}
h1{{font-size:18px;margin:0 0 16px}}input{{width:100%;margin:6px 0 12px;padding:6px}}
.err{{color:#b00020;font-size:13px}}</style>
</head><body><div class="box"><h1>XWEB500</h1>{error}
<form method="post" action="/login">
<label>User name<input name="username" autocomplete="off"></label>
<label>Password<input name="password" type="password"></label>
<input type="submit" value="Log in"></form></div></body></html>"""

# Paths used by the public CVE-2021-45420 exploit (Exploit-DB 50639).
DIXELL_EXPLOIT_PATHS = {
    "/cgi-bin/logo_extra_upload.cgi": "CVE-2021-45420 file upload",
    "/cgi-bin/cal_save.cgi": "CVE-2021-45420 file upload",
    "/cgi-bin/lo_utils.cgi": "CVE-2021-45420 command execution",
    "/cgi-bin/cal_dir.cgi": "CVE-2021-45420 result check",
    "/logo/": "CVE-2021-45420 result check",
}


# --- HTTP ---------------------------------------------------------------------

class DecoyHTTP(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = SOCKET_TIMEOUT

    def version_string(self):
        return P["server"]

    def log_message(self, format, *args):
        pass  # we do our own logging

    def setup(self):
        watch(self.request)
        super().setup()

    def finish(self):
        try:
            super().finish()
        finally:
            unwatch(self.request)

    @property
    def proto(self):
        return "https" if isinstance(self.request, ssl.SSLSocket) else "http"

    def reply(self, status, body, content_type="text/html; charset=utf-8", static=False):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if static and PERSONA == "danfoss":
            # Header set and order seen on real AK-SM 800A units (Shodan, Nov 2026).
            self.send_header("Last-Modified", formatdate(FIRMWARE_MTIME, usegmt=True))
            self.send_header("Connection", "keep-alive")
            self.send_header("ETag", f'"{FIRMWARE_MTIME:x}-{len(data):x}"')
            for name, value in DANFOSS_STATIC_HEADERS:
                self.send_header(name, value)
        else:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_error(self, code, message=None, explain=None):
        # Malformed request lines and the like; never show Python's stock error page.
        log(self.proto, self.client_address, "bad_request", code=code,
            raw=self.raw_requestline.decode("latin-1") if hasattr(self, "raw_requestline") else "")
        self.close_connection = True
        self.request_version = "HTTP/1.1"  # always send a status line and headers
        self.reply(code, P["not_found"] if code == 404 else
                   f"<html><head><title>{code}</title></head><body><h1>{code}</h1></body></html>")

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        return self.rfile.read(min(max(length, 0), MAX_BODY)).decode("latin-1")

    def handle_any(self):
        body = self.read_body()  # any method: leftover bytes would desync keep-alive
        path = urlsplit(self.path).path
        exploit = DIXELL_EXPLOIT_PATHS.get(path, "") if PERSONA == "dixell" else ""
        log(self.proto, self.client_address, "request",
            method=self.command, path=self.path, host=self.headers.get("Host", ""),
            user_agent=self.headers.get("User-Agent", ""),
            authorization=self.headers.get("Authorization", ""),
            body=body, exploit=exploit)

        if PERSONA == "danfoss":
            if path in ("/html/xml.cgi", "/xml.cgi"):
                if self.command == "POST":
                    return self.reply(200, danfoss_xml(self.client_address, self.proto, body, self.headers),
                                      "text/xml; charset=utf-8")
                if self.command == "OPTIONS":  # CORS preflight from the web app
                    return self.reply(204, b"", "text/plain")
                return self.reply(405, NOT_ALLOWED, "text/html")
            if path in ("/", "/index.html"):
                return self.reply(200, DANFOSS_LOGIN, "text/html", static=True)
            if path == "/favicon.ico" and FAVICON:
                return self.reply(200, FAVICON, "image/x-icon", static=True)
            return self.reply(404, P["not_found"])

        if path == "/login" and self.command == "POST":
            form = parse_qs(body, keep_blank_values=True)
            log(self.proto, self.client_address, "login_attempt",
                username=form.get("username", [""])[0], password=form.get("password", [""])[0])
            time.sleep(random.uniform(0.6, 1.4))
            return self.reply(200, DIXELL_LOGIN.format(
                error='<p class="err">Invalid user name or password.</p>'))
        if exploit:
            return self.reply(200, "")
        if path in ("/", "/index.html"):
            return self.reply(200, DIXELL_LOGIN.format(error=""))
        return self.reply(404, P["not_found"])

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = do_TRACE = handle_any


class DecoyHTTPServer(Guarded, ThreadingHTTPServer):
    pass


class TLSHTTPServer(DecoyHTTPServer):
    """Does the TLS handshake in the per-connection thread, not in accept()."""

    def __init__(self, address, handler, context):
        super().__init__(address, handler)
        self.context = context

    def finish_request(self, request, client_address):
        request.settimeout(SOCKET_TIMEOUT)
        watch(request)
        try:
            tls = self.context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as e:
            log("https", client_address, "tls_error", error=str(e))
            return
        finally:
            unwatch(request)
        try:
            super().finish_request(tls, client_address)
        finally:
            tls.close()


# --- Modbus TCP ---------------------------------------------------------------
# Holding registers, temperatures in tenths of a degree C (signed).
#   0..7     case temperatures
#   100..107 case setpoints
#   200..207 defrost command (1 = start defrost)

_state_lock = threading.Lock()
REGISTERS = {}
for case in range(8):
    REGISTERS[case] = -180 + random.randint(-15, 15) if case < 4 else 30 + random.randint(-10, 10)
    REGISTERS[100 + case] = -200 if case < 4 else 20
    REGISTERS[200 + case] = 0


CASE_NAMES = ["Frozen 1", "Frozen 2", "Ice cream", "Frozen 4", "Dairy", "Meat", "Deli", "Produce"]
_defrost_since = {}  # case -> time defrost started
DEFROST_SECONDS = 20 * 60


def case_status():
    """(air temp, setpoint, defrost) per case, in tenths of a degree C."""
    temps = read_registers(0, 8)
    with _state_lock:
        return [(struct.unpack(">h", struct.pack(">H", temps[n]))[0], REGISTERS[100 + n],
                 1 if REGISTERS[200 + n] else 0) for n in range(8)]


def mapped(start, count):
    return all(addr in REGISTERS for addr in range(start, start + count))


def read_registers(start, count):
    with _state_lock:
        values = []
        for addr in range(start, start + count):
            value = REGISTERS[addr]
            if addr < 8:
                value += random.randint(-2, 2)  # sensor jitter
                if addr in _defrost_since:  # warms about 1.5 C a minute, up to 25 C
                    elapsed = time.time() - _defrost_since[addr]
                    if elapsed > DEFROST_SECONDS:  # cycle over, back to cooling
                        del _defrost_since[addr]
                        REGISTERS[200 + addr] = 0
                    else:
                        value += min(250, int(elapsed / 4))
            values.append(value & 0xFFFF)
        return values


def write_registers(start, values):
    with _state_lock:
        for offset, value in enumerate(values):
            addr = start + offset
            REGISTERS[addr] = struct.unpack(">h", struct.pack(">H", value))[0]
            if 200 <= addr < 208:
                if value:
                    _defrost_since.setdefault(addr - 200, time.time())
                else:
                    _defrost_since.pop(addr - 200, None)


def modbus_exception(fc, code):
    return bytes([fc | 0x80, code])


def device_id_response():
    # FC 43 / MEI 14, basic identification: vendor, product, revision
    objects = [P["vendor"], P["product"], P["firmware"]]
    out = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, len(objects)])
    for obj_id, text in enumerate(objects):
        raw = text.encode()
        out += bytes([obj_id, len(raw)]) + raw
    return out


def handle_pdu(src, unit, pdu):
    fc = pdu[0]
    if fc in (3, 4) and len(pdu) == 5:
        start, count = struct.unpack(">HH", pdu[1:5])
        if not 1 <= count <= 125:
            return modbus_exception(fc, 3)
        log("modbus", src, "read", unit=unit, fc=fc, start=start, count=count)
        if not mapped(start, count):
            return modbus_exception(fc, 2)
        values = read_registers(start, count)
        return bytes([fc, count * 2]) + struct.pack(f">{count}H", *values)

    if fc == 6 and len(pdu) == 5:
        addr, value = struct.unpack(">HH", pdu[1:5])
        log("modbus", src, "write", unit=unit, fc=fc, start=addr, values=[value],
            defrost=200 <= addr < 208 and value != 0)
        if not mapped(addr, 1):
            return modbus_exception(fc, 2)
        write_registers(addr, [value])
        return pdu

    if fc == 16 and len(pdu) >= 6:
        start, count, nbytes = struct.unpack(">HHB", pdu[1:6])
        if not 1 <= count <= 123 or nbytes != count * 2 or len(pdu) != 6 + nbytes:
            return modbus_exception(fc, 3)
        values = list(struct.unpack(f">{count}H", pdu[6:]))
        log("modbus", src, "write", unit=unit, fc=fc, start=start, values=values,
            defrost=any(200 <= start + i < 208 and v != 0 for i, v in enumerate(values)))
        if not mapped(start, count):
            return modbus_exception(fc, 2)
        write_registers(start, values)
        return pdu[:5]

    if fc == 43 and len(pdu) >= 2 and pdu[1] == 0x0E:
        log("modbus", src, "device_id", unit=unit)
        return device_id_response()

    log("modbus", src, "unsupported", unit=unit, fc=fc, pdu_hex=pdu[:64].hex())
    return modbus_exception(fc, 1)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


class DecoyModbus(socketserver.BaseRequestHandler):
    def handle(self):
        watch(self.request)
        try:
            self.request.settimeout(SOCKET_TIMEOUT)
            log("modbus", self.client_address, "connect")
            while True:
                header = recv_exact(self.request, 7)
                if header is None:
                    return
                tid, proto, length, unit = struct.unpack(">HHHB", header)
                if proto != 0 or not 2 <= length <= 254:
                    log("modbus", self.client_address, "malformed", header_hex=header.hex())
                    return
                pdu = recv_exact(self.request, length - 1)
                if pdu is None:
                    return
                reply = handle_pdu(self.client_address, unit, pdu)
                self.request.sendall(struct.pack(">HHHB", tid, 0, len(reply) + 1, unit) + reply)
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            unwatch(self.request)


class ThreadingTCP(Guarded, socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))  # PID 1 in a container
    servers = [DecoyHTTPServer(("0.0.0.0", HTTP_PORT), DecoyHTTP)]
    if HTTPS_PORT:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2  # as real units
        context.load_cert_chain(CERT_FILE, KEY_FILE)
        servers.append(TLSHTTPServer(("0.0.0.0", HTTPS_PORT), DecoyHTTP, context))
    if MODBUS_PORT:
        servers.append(ThreadingTCP(("0.0.0.0", MODBUS_PORT), DecoyModbus))
    log("system", ("0.0.0.0", 0), "start",
        http_port=HTTP_PORT, https_port=HTTPS_PORT, modbus_port=MODBUS_PORT)
    threading.Thread(target=reaper, daemon=True).start()
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
