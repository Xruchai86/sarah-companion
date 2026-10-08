"""Draws the app icons from the REAL core animation (sarah.js) with headless Chromium. Run once; the PNGs are checked in."""
import os, sys
from playwright.sync_api import sync_playwright
HERE = os.path.dirname(os.path.abspath(__file__)); ST = os.path.join(HERE, '..', 'app', 'static')
PAGE = """<!doctype html><body style="margin:0;background:%s"><div id=box style="width:%dpx;height:%dpx;display:flex;align-items:center;justify-content:center;background:%s">
<canvas id=c style="width:%dpx;height:%dpx"></canvas></div>"""
def shot(pw, name, size, inner, bg='#050912', transparent=False, ring=False):
    b = pw.chromium.launch(); pg = b.new_page(viewport={'width': size, 'height': size}, device_scale_factor=1)
    pg.set_content(PAGE % ('transparent' if transparent else bg, size, size, 'transparent' if transparent else bg, inner, inner))
    if ring:
        pg.evaluate("""() => { const c = document.getElementById('c'); c.width = c.height = %d; const x = c.getContext('2d'); x.strokeStyle = '#fff'; x.fillStyle = '#fff'; x.lineWidth = %d;
          x.beginPath(); x.arc(%d, %d, %d, 0, 7); x.stroke(); x.beginPath(); x.arc(%d, %d, %d, 0, 7); x.fill(); }""" % (inner, inner // 9, inner // 2, inner // 2, int(inner * .38), inner // 2, inner // 2, int(inner * .14)))
    else:
        pg.add_script_tag(path=os.path.join(ST, 'sarah.js'))
        pg.evaluate("() => { window.core = new SarahCore(document.getElementById('c'), { state: 'calm' }); }")
        pg.wait_for_timeout(2600)
    pg.locator('#box').screenshot(path=os.path.join(ST, name), omit_background=transparent)
    b.close()
with sync_playwright() as pw:
    shot(pw, 'icon-512.png', 512, 470); shot(pw, 'icon-192.png', 192, 176); shot(pw, 'apple-touch-icon.png', 180, 164)
    shot(pw, 'icon-maskable-512.png', 512, 340)                    # the core stays inside the 80 % safe zone
    shot(pw, 'badge-96.png', 96, 88, transparent=True, ring=True)  # monochrome: the system tints it
print('Icons erzeugt')
