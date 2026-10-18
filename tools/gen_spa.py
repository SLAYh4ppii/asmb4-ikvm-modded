#!/usr/bin/env python3
"""Inline web/*.js into web/app.html -> src/spa.inc (C array) + overlay/www/login.asp.

The app.html template carries three placeholders:
  @@SOC_DECODER@@  -> web/soc_decoder.js  (wrapped in <script>)
  @@IKVM@@         -> web/ikvm.js         (wrapped in <script>)
  @@APP@@          -> web/app_main.js     (already contains its own <script>)
"""
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "web")

def rd(name):
    with open(os.path.join(WEB, name), "rb") as f:
        return f.read().decode("utf-8")

html = rd("app.html")
html = html.replace("@@SOC_DECODER@@", "<script>\n" + rd("soc_decoder.js") + "\n</script>")
html = html.replace("@@IKVM@@", "<script>\n" + rd("ikvm.js") + "\n</script>")
html = html.replace("@@APP@@", rd("app_main.js"))
data = html.encode("utf-8")

with open(os.path.join(ROOT, "src", "spa.inc"), "w") as f:
    f.write("static const char SPA[]={")
    for i in range(0, len(data), 16):
        f.write("\n" + ",".join(str(b) for b in data[i:i+16]) + ",")
    f.write("\n};\n#define SPA_LEN ((int)sizeof(SPA))\n")

with open(os.path.join(ROOT, "overlay", "www", "login.asp"), "wb") as f:
    f.write(data)

print("src/spa.inc + overlay/www/login.asp written, %d bytes" % len(data))
