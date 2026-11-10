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

        log = events(log_path)
        logins = [e for e in log if e["event"] == "login_attempt"]
        assert [(e["username"], e["granted"]) for e in logins[:2]] == [("nobody", False), ("Supervisor", True)]
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


if __name__ == "__main__":
    workdir = tempfile.mkdtemp()
    test_danfoss(workdir)
    test_danfoss_index_file(workdir)
    test_dixell(workdir)
    print("OK: both personas")
