# coldframe

A honeypot for supermarket refrigeration controllers.

In 2026, attackers broke into internet-facing refrigeration supervisors across Europe using default passwords and old, unpatched firmware, then forced defrost cycles. coldframe pretends to be one of those controllers. It records who connects, what passwords they try and which public exploits they use, and it never gives them anything real.

It is one Python file with no dependencies outside the standard library.

## Personas

| Persona | Pretends to be | What it serves |
|---|---|---|
| `danfoss` | Danfoss AK-SM 800A system manager | StoreView login, a fake store dashboard, the XML API at `/html/xml.cgi` and `/xml.cgi`, HTTP and HTTPS |
| `dixell` | Copeland/Dixell XWEB EVO supervisor | Login page and the XWEB 500 CGI paths targeted by public exploits |
| `pcoweb` | Carel pCOWeb card (HTTP only so far) | Redirect stub, Basic-auth pages behind the documented factory logins, an admin area with the card's configuration tabs |

### Looking like a real unit

The Danfoss persona copies what internet scanners record for real AK-SM 800A units: the `nginx` server header and header order, the `Danfoss StoreView` page title, TLS 1.2 only, and a 1-year certificate for `CN=DanfossSM800A` issued by a `SelfSigned-DanfossSM800A` authority. Each build generates its own keys.

It reports firmware 4.3.1 everywhere: the login page, `read_units` and an unauthenticated `/metadata.json`, as real units do. Because 4.3.1 is patched, a CVE-2025-41450 "code of the day" is logged (with whether it was correct) but does not log in.

Weak logins (for example `Supervisor` / `12345`) **succeed**. The attacker gets a session token and a dashboard of fake refrigerated cases with defrost buttons. Every action they take is logged as a `control` event; nothing is real.

The Dixell persona follows real XWEB EVO units the same way: no `Server` header, their security-header set and order, the same asset paths and page size. Its login uses the real `/cgi-bin/login.lua` flow: the documented factory login `Admin` / `Admin` succeeds, five failures in five minutes lock the user, and attempts at the XWEB Pro `auth_mode` bypass (CVE-2026-25085) are tagged.

Real units of both vendors serve their own favicon, and scanners match devices by its hash. That icon is the vendor's artwork, so it is not in this repository. For a private deployment you can point `FAVICON_FILE` at a copy you have the right to use.

The same goes for the Danfoss start page. Real units serve a short Angular loader page from the firmware, and thousands share its exact hash. Point `INDEX_FILE` at that `index.html` (from the public firmware package) and the decoy serves it byte for byte, with its original date in `Last-Modified` and `ETag`. The loader's `main.*.js` then shows the decoy's own login page, laid out like the firmware's remote login. If the firmware's `assets/images/Danfoss-logo.png` sits beside that `index.html`, the page uses it.

The pCOWeb persona (first-generation firmware) copies the header names and order of `thttpd 2.20c`, the 364 or 367 byte redirect page at `/`, the 401 on `/http/index.html` with realm `flash/http`, and the card's habit of showing a 1970 date on units without a clock. The factory logins `admin` / `fadmin` and `httpadmin` / `fhttpadmin` work. The admin area follows the card's configuration pages: the same tab row (General, Network, pCO Com, ModbusTCP, SNMP, BACnet, Plugins, Users, Firmware), page titles, menu texts and file names, taken from the public A1.5.4 firmware package. The markup is our own, since the real pages are Carel's. The tab pages carry the card's own form labels and field names, and saving a form is logged in full and answered with a "saved, please reboot" page, without changing anything. Still guesses: the admin realm `config`, the thttpd error texts, the default field values, the output behind the menu links and the plugins page. The card's logo and images are Carel's, so they are blank. It does not speak telnet, FTP, SNMP or BACnet yet.

The Danfoss and Dixell personas can also run an optional **Modbus TCP** service with fake case temperatures, setpoints and a defrost register. Real AK-SM 800A units only use Modbus to talk to their own case controllers, so Modbus is off by default. Turn it on to catch generic industrial scanners.

### Exploits it recognises

Requests that match a public exploit get an `exploit` field in the log:

- **CVE-2023-25914**: AK-SM 800A path traversal via `get_file`
- **CVE-2023-25915**: AK-SM 800A command injection via `load_cert`
- **CVE-2025-41452**: AK-SM 800A nginx header overwrite via `load_nginx_headers`
- **CVE-2025-41450**: AK-SM 800A "code of the day" login bypass (`getauth` with `eds_only` or `quantum_only`), noting whether the attacker computed the correct code
- **SM800 code-of-the-day bypass**: `eds_only` / `quantum_only` on other commands
- **CVE-2021-45420**: XWEB 500 upload and command paths under `/cgi-bin/`
- **CVE-2026-25085**: XWEB Pro login bypass via an unexpected `auth_mode`

## Quick start

```bash
PERSONA=danfoss HTTP_PORT=8080 python3 -I honeypot.py
```

Open http://localhost:8080 and every request shows up as a JSON line on stdout and in `events.jsonl`.

Run the tests (they start the honeypot on loopback and attack it):

```bash
python3 -I test_honeypot.py
```

## Deploying

### Quickest: paste into "User data"

Create an Ubuntu 24.04 server (a $4 DigitalOcean droplet is plenty) and paste [cloud-init.yaml](cloud-init.yaml) into the **User data** box. Change `PERSONA=danfoss` to `dixell` for the XWEB persona or `pcoweb` for the Carel card. About two minutes after boot the decoy is listening on port 80 (and 443 for Danfoss), hardened as below.

Then, in your provider's firewall, allow only the decoy's ports from anywhere and SSH from your own address. Read the log with:

```bash
ssh root@<server> 'podman logs coldframe'
```

### By hand

Build the container. Each build makes a fresh self-signed certificate, so two deployments never share one.

```bash
podman build -t coldframe .
```

Run it with **rootful** podman or Docker. Rootless port forwarding rewrites the source address, which makes every attacker look like the same internal IP.

`--userns=auto` maps the container to an unused host UID range, so even the container user is nobody on the host. Podman needs a range to hand out, once per host:

```bash
echo "containers:2147483647:2147483648" | sudo tee -a /etc/subuid /etc/subgid
```

```bash
sudo podman run -d --name coldframe --restart=always \
  --read-only --cap-drop=ALL --security-opt no-new-privileges --userns=auto \
  --memory 128m --pids-limit 512 --log-opt max-size=10m \
  -p 80:8080 -p 443:8443 \
  -v coldframe-logs:/logs:U \
  -e PERSONA=danfoss \
  coldframe
```

For Modbus, add `-e MODBUS_PORT=5020 -p 502:5020`.

On the host, only expose the ports the persona would really have, and block outbound traffic except DNS and package updates: the decoy never needs to connect out. Keep SSH reachable only from your own address: a fridge controller with SSH open to the world looks wrong.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PERSONA` | `danfoss` | `danfoss`, `dixell` or `pcoweb` |
| `PCOWEB_CLOCK` | random | `1970` or `ntp`: whether the pCOWeb clock shows a 1970 date, as about a third of real cards do. Unset, it is chosen at random at start |
| `PCOWEB_IP` | `192.168.1.100` | LAN address shown on the pCOWeb home page |
| `HTTP_PORT` | `8080` | HTTP listener |
| `HTTPS_PORT` | `0` (off) | HTTPS listener, needs `CERT_FILE` and `KEY_FILE` |
| `MODBUS_PORT` | `0` (off) | Modbus TCP listener |
| `LOG_PATH` | `events.jsonl` | Where events are appended |
| `FAVICON_FILE` | none | Optional favicon to serve (private deployments only) |
| `INDEX_FILE` | none | Optional Danfoss firmware `index.html` to serve as the start page (private deployments only) |
| `STORE_NAME` | `Fresh Market 0412` | Store name in the Danfoss `read_units` reply. Set a different one on every deployment |
| `MAC_ADDRESS` | per persona | MAC address in the Danfoss `read_units` reply and on the XWEB login page. Set a different one on every deployment |

## Reading the log

Each line is one event:

```json
{"ts": "2026-11-05T10:57:21.158+00:00", "persona": "danfoss", "proto": "http",
 "src_ip": "203.0.113.7", "src_port": 6782, "event": "login_attempt",
 "username": "admin", "password": "admin"}
```

| `event` | When |
|---|---|
| `request` | Any HTTP(S) request, with method, path, Host, User-Agent, Authorization and body |
| `login_attempt` | Credentials submitted through the login page or the XML API, with `granted` |
| `control` | An action from a logged-in session, such as starting a defrost |
| `xml_cmd` | A Danfoss XML API command, with its attributes and any `exploit` match |
| `tls_error` | A failed TLS handshake (often a scanner speaking plain HTTP to 443) |
| `connect`, `read`, `write`, `device_id`, `unsupported`, `malformed` | Modbus activity; writes to the defrost registers carry `"defrost": true` |

`summary.py` turns a log into a short report:

```bash
python3 -I summary.py --hours 24 --ignore <your-own-ip> < events.jsonl
```

## Safety

- It never runs commands, reads files, or forwards traffic. Exploit payloads are logged and dropped.
- Request bodies, logged fields and connections are capped, including a per-source limit so one attacker cannot crowd out others. Idle sockets time out, and the event log rotates once it gets large.
- Connections that trickle data to stay open are cut after 30 seconds, and refused connections are logged.
- Over-long log lines are truncated, and `summary.py` neutralises terminal escape codes from attacker input.
- The container runs as a non-root user in its own user namespace, on a read-only filesystem with no capabilities.
- Log fields are attacker-controlled. Treat them as untrusted when you view or process them.

## Limitations

- **Shallow interaction.** Logged-in attackers see a small dashboard and a handful of XML commands, not the full StoreView app.
- **Public code can be fingerprinted.** Anyone can read this repository and spot its exact responses. Set `STORE_NAME` and `MAC_ADDRESS` differently on every deployment (the cloud-init file does this for you), since real units each have their own. The certificate names and the rest of the page are shared by real units of that model, so they stay the same; changing them would make the decoy easier to spot, not harder. Page layout beyond these strings is in the source.
- **Unconfirmed details.** Static paths, the full web app and some XML response shapes of real units are not public. Where they were missing, coldframe uses plausible values.
- **Vendor MAC prefixes are only partly verified.** The Danfoss persona uses a prefix the IEEE registry assigns to Danfoss A/S, and pCOWeb uses Carel's; we have not confirmed that real AK-SM units use that exact prefix. The Dixell persona still uses a placeholder prefix.
- **Cloud IPs look suspicious.** Some scanners flag industrial devices on cloud hosting as likely honeypots.

## Sources

- Danfoss AK-SM 800A user guide (port table, login screen, StoreView Web): https://assets.danfoss.com/documents/latest/590332/BC337629891709en-001101.pdf
- Danfoss AK-SM XML interface guide: https://assets.danfoss.com/documents/latest/376199/AU342138209420en-000501.pdf
- Synacktiv, AK-SM 800A vulnerabilities (CVE-2023-25914, CVE-2023-25915): https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800a-multiple-vulnerabilities.pdf
- Synacktiv, SM800 auth bypass: https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf
- Claroty Team82, Danfoss controller research (CVE-2025-41450 to 41452): https://blog.claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers
- Exploit-DB 50639, XWEB 500 (CVE-2021-45420): https://www.exploit-db.com/exploits/50639
- Copeland XWEB EVO operation manual r5.4.1 (default login, lockout): https://webapps.copeland.com/Dixell/Content/Pages/Manuals/XWEBEVO/XWEBEVOV5.4.1OPERATION/XWEB-EVO-r5.4.1-OPR-EN.pdf
- CISA ICSA-26-057-10 and Claroty Team82, XWEB Pro vulnerabilities: https://claroty.com/team82/research/chilling-discoveries-unpacking-vulnerabilities-in-copeland-xweb-pro-controllers
- Ironhackers, CVE-2025-41450 code-of-the-day analysis: https://ironhackers.es/en/danfoss-ak-sm-800a-cve-2025-41450/
- Carel pCOWeb firmware package A1.5.4 / B1.2.4 and the pCOWeb manual (routes, page titles, redirect page, factory logins), from Carel's public downloads
- RedTeam Pentesting advisory RT-SA-2019-013, pCOWeb factory logins
- IEEE OUI registry (vendor prefixes for the Danfoss and Carel MAC addresses)
- Shodan records of exposed units (header set, title, certificate fields), November 2026

## Related work

[eppser/danfoss-ak-sm-decoy](https://github.com/eppser/danfoss-ak-sm-decoy) is another AK-SM decoy, with SNMP and Service Tool listeners and a richer simulated store. coldframe focuses on matching real units' web fingerprints, detecting specific exploits, and Dixell XWEB support.

## License

MIT. See [LICENSE](LICENSE).
