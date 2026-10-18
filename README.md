# ASMB4-iKVM — komplett neue Firmware/UI (iDRAC-Style) für ASUS KCMA-D8

Kompletter Rebuild des ASUS ASMB4-iKVM Management-Interfaces auf der
**ASUS KCMA-D8** mit ASPEED **AST2050** BMC (auch ASMB4 auf anderen ASUS-Boards
mit derselben AST2050/AST2100-Firmware-Basis, z.B. KGPE-D16, P8B/…).

Das Ergebnis ersetzt die ganze Weboberfläche durch eine moderne Single-Page-App
(iDRAC-Stil): **Live-KVM-Video** (echtes ASP2000-Decoding im Browser), direkte
Tastatur+Maus, Sensoren, SEL, Power-Control, User-/Netzwerk-/System-Management,
Firmware-Update — alles auf der BMC-Karte selbst, kein Java-Applet, kein
externer Rechner.

| Port | Dienst |
|------|--------|
| 80 | **bmcweb** — neues UI + JSON-API (`/api/*`) + WebSocket-KVM-Bridge (`/ws`) |
| 8080 | Stock GoAhead-Webserver (unverändert, intern via `bindhook` dorthin verschoben) |
| 5900 | `kvmproxy` → TCP:7578 adviserd (IVTP) — wird von bmcweb `/ws` genutzt |
| 8443 | Stock HTTPS (via bindhook) |
| 623 | IPMI/RMCP+ LAN (unverändert) |
| 22 | SSH (unverändert) |

---

## Architektur — drei Ebenen

```
Browser ──HTTP/WS──> bmcweb :80  (custom, C, static, auf der Karte)
   SPA (Dashboard, KVM, Sensoren, SEL, User, Netz, System, FW-Update, RPC-Konsole)
        │  /api/*     JSON-API, Session-Auth per RMCP+ IPMI-Auth
        │  /api/ga    generischer Proxy auf ALLE Stock-RPCs (~90 WEBVAR-Endpoints)
        │  /api/kvmtoken  holt IVTP-Token aus JNLP vom Stock-Backend
        │  /ws        WebSocket→adviserd IVTP-Bridge (KVM Video+Input)
        └── Stock-Flashen 1:1 durchgereicht (verifyimage.asp / startflash)

kvmproxy :5900  (custom, C) ──> adviserd :7578 (proprietär, unverändert)
   reines TCP-Relay; bindhook ersetzt adviserd-Port-Bind NICHT — es bleibt an
   7578, kvmproxy reicht 1:1 durch, inkl. IUSB-HID-Keyboard/Mouse-Paketen.

bindhook.so  (LD_PRELOAD, nur ~300 Zeilen, kein libc-Aufruf)
   lässt Stock-webgo beim boot statt auf :80 auf :8080 binden (443→8443) —
   der alte Stack läuft KOMPLETT weiter, nur andere Ports.
   WICHTIG: altes ld.so (glibc 2.3.2) kann kein gnu.hash-only →
   IMMER mit -Wl,--hash-style=both bauen!

ASP2000-Video: adviserd → IVT-Stream (7B-Header, type 5 Fragments, "ASP-2000")
   → SocVideoDecoder.js (Port von LunarView/JViewer) → <canvas>
Input: IUSB HID-Reports (48B keyboard, 45B abs. mouse) → WebSocket → IVT type 6.
```

Warum nicht OpenBMC: es gibt keinen brauchbaren offenen AST2050-Capture-Treiber —
der proprietäre adviserd/ASP2000-Pfad ist der einzige funktionierende
Video-Weg und bleibt unangetastet. Die neue Firmware ist eine **Alternative**
Front-End-Schicht, kein Ersatz der Stock-Firmware-Funktionen: Flashen, KVM,
IPMI bleiben 1:1 beim Original-Mechanismus.

## Was das neue UI kann (iDRAC-Rebuild)

Dashboard, Remote Console (Video + Tastatur direkt + Maus + On-Screen-KB mit
sticky Modifiers + Ctrl+Alt+End→CAD-Macro), Sensors, Event Log (SEL inkl.
Clear über `/rpc/clearsel.asp`), Users, Network, System/FRU, Firmware (Upload
geht über Stock-Flow `/fw-upload` auf GoAhead), Date/NTP, Alerts/SMTP, Event
Filters, SNMP, Directory (AD/LDAP), Serial/SOL, Sessions/Mouse, Maintenance,
und eine generische **RPC Console**, die jeden der ~90 Stock-WEBVAR-Endpoints
aufruft — auch jene, für die es keine native View gibt. Stock-Antwortformat
(`WEBVAR_JSONVAR_*`) wird clientseitig geparst.

BIOS/POST ist **sichtbar und bedienbar** über die Konsole — die BIOS-"Server
Management"-Seite rendert allerdings das **Mainboard-BIOS** (Daten kommen per
IPMI/KCS von der Karte). Ein separate BIOS-Settings-API existiert auf dieser
Plattform NICHT — Settings nur über die Live-Konsole.

## Repo-Layout

```
build.sh              Host: gesamte Pipeline (docker build → .ima raus)
Dockerfile            debian:9 + arm-linux-gnueabi + mkfs.cramfs + qemu
src/bmcweb.c          neuer HTTP/WS/IPMI-Server (static OABI, kein libc)
src/bindhook.c        LD_PRELOAD-Hook: webgo :80→:8080, :443→:8443
src/kvmproxy.c        IVTP-Relay :5900 → adviserd :7578
web/app.html          SPA-Template mit @@SOC_DECODER@@ @@IKVM@@ @@APP@@
web/soc_decoder.js    AST2050/ASP2000 Video-Decoder (JPEG/VQ-Tiles)
web/ikvm.js           IVTP-Client (Framing, IUSB-HID, Keyboard/Mouse)
web/app_main.js       UI: Views, /api/*-Calls, globale Tastenerfassung, OSK
tools/extract_ima.py  .ima → work/root.cramfs + work/www.cramfs
tools/gen_spa.py      web/* → src/spa.inc + overlay/www/login.asp
tools/compile.sh      (läuft im Container) unpack+merge+compile+mkfs
tools/pack_ima.py     patchets FMH-Size/CRC, uImage-Hdr, Gesamt-Checksum
tools/flash_image.py  Netz-Flash über Stock-Mechanismus (PRESERVECFG=1)
tools/verify_upload.py  Upload + verifyimage-Check OHNE Flash
tools/cramfs_extract.py  Host-seitiger cramfs-Reader (ohne Docker)
tools/ivtp_ws_test.py   Live-Test: WS-Handshake + IVTP-Auth + Frames
tools/ivtp_client.py    IVTP-Test-Client (Protokoll-Referenz)
tools/rmcp_proto.py     RMCP+/IPMI-Test-Client (RAKP, Sensoren, Power)
overlay/root/         Dateien, die ins Stock-Rootfs rein: inittab (bmcweb+
                      kvmproxy respawn, webgo8080-Wrapper), init.d-Skripte
overlay/www/login.asp eingebettete SPA (ersetzt Stock-Login auf :8080)
```

## Builden

Voraussetzungen: Docker, Python 3. Ein Stock-Image wird nicht mitgeliefert —
leeres `stock/`-Verzeichnis/Datei selbst besorgen:
`ASMB4_FW214_KCMA-D8/KCMA-D8/KCMA8214.ima` (auch ältere 2.14/2.20 gehen —
Pfade/Offsets sind bei allen AST2050/AST2100-Familien gleich).

```bash
./build.sh path/to/KCMA8214.ima
# → work/KCMA8214_mod.ima

python3 tools/flash_image.py 192.168.1.160 work/KCMA8214_mod.ima 8080 --flash
# → verifyimage.asp (IMGCOMPSTATUS:0) → startflash PRESERVECFG=1 → reboot
```

Der Flash geht **nur übers Netz** mit dem exakten Stock-Flow (identische
Upload-Bytes/Auth auf dem Stock-HTTP-Dienst, Port 8080). Das Verifikations- und
Flash-Binary im Image bleibt das Original — wir tauschen nur root/www aus.

## Was beim Build intern passiert

1. `extract_ima.py` schneidet die `$MODULE$`-Regionen aus; `root` ist ein
   uImage (64B-Header wird abgestreift → reines cramfs).
2. `gen_spa.py` inlined `soc_decoder.js`, `ikvm.js`, `app_main.js` in
   `app.html` → `src/spa.inc` (C-Array, landet im bmcweb-Binary) **und**
   `overlay/www/login.asp` (gleiches File auf Stock-:8080).
3. Im Container: `fsck.cramfs --extract` (behält Mods+Symlinks), `cp -a`
   Overlay drüber, GCC für bmcweb/bindhook/kvmproxy, `mkfs.cramfs` neu.
4. `pack_ima.py` schreibt root/www zurück: FMH `used`-Size, CRC32, uImage-
   DataCRC/HeaderCRC, abschließend Gesamt-Checksumme in `ast2100`-FMH.

## Hardware-Voraussetzung für KVM-Video

**"VGA Priority = onboard"** im SR5690-BIOS setzen — der ASP2000 bekommt nur
Signal vom onboard-VGA. Ist eine externe GPU primary, liefert die Konsole nur
schwarze Frames.

## Backup / Recovery

Vor dem ersten Flash unbedingt ein SPI-Dump anfertigen (die Karte lässt sich
über den Stock-Flow NICHT vollständig sichern): SPI-Programmierer am SOIC8 des
AST2050 oder Linux-Live-USB mit `flashrom -p linux_spi` auf dem Host. Damit ist
auch ein hart gebrickter Flash mit dem Programmer wiederherstellbar.

## Constraints / Dinge zu beachten

- `bmcweb`/`kvmproxy` = **static OABI, no libc, kein RW-Segment** (Nur
  `R E`-LOAD; große Buffer auf den Stack — sonst bricht das ohne-RW-Binary).
- bindhook **muss** `--hash-style=both` haben (siehe oben).
- SEL-Clear geht auf dieser Firmware-Version nicht über LAN-IPMI (0xc7) — das
  UI routed es durch `/rpc/clearsel.asp` auf GoAhead.
- Drei Stock-RPCs sind im Firmware-Binary schlicht nicht vorhanden
  (`getdatetime`, `getsessiontime`, `getpmcpfilestat` → "Could not resolve
  function") — Limitation der Stock-`.so`, nicht des Proxys.
- ARM `__aeabi_uidiv` war ein Subtraktions-Loop → SEL-Timestamp-Konvertierung
  45 s; bmcweb nutzt binäre 32-Bit-Division (~0.26 s für 52 Events).
- Tasten gehen physisch durch (US-Keycodes); Host auf deutschem Layout →
  korrekte Zeichen.
- Dass Browser echtes Ctrl+Alt+Del blockieren ist Windows-Seitig — Workaround
  `Strg+Alt+Ende` → sendet CAD (iDRAC-Konvention) + Macro-Button + OSK.

Nur in-house/own-hardware. ASP2000-Decoder-Port abgeleitet von LunarView
(MIT). Keine ASUS-Binaries im Repo — nur eigener Code + Einhänge-Skripte.
