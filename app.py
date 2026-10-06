# app.py — Simple Ban Check API (Vercel-compatible)
import base64
import time
import logging
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import requests

import BanCheck_pb2
import DaNgErProTo_pb2

try:
    from danger_ff_version_updater import get_categories
    VERSION_UPDATER_AVAILABLE = True
except ImportError:
    VERSION_UPDATER_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================
AES_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
AES_IV  = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
CLIENT_ID     = "100067"

FALLBACK_VERSION_DATA = {
    "IND":     {"client_url": "https://client.ind.freefiremobile.com/", "server_url": "https://loginbp.ggpolarbear.com/", "release_version": "OB54", "client_version": "1.126.2"},
    "AMERICA": {"client_url": "https://client.us.freefiremobile.com/",  "server_url": "https://loginbp.ggpolarbear.com/", "release_version": "OB54", "client_version": "1.126.2"},
    "OTHERS":  {"client_url": "https://clientbp.ggpolarbear.com/",      "server_url": "https://loginbp.ggpolarbear.com/", "release_version": "OB54", "client_version": "1.126.2"},
}

REGION_FOR_MAJOR_LOGIN = {
    "IND":     "IND",
    "AMERICA": "US",
    "OTHERS":  "SG",
}

ACCOUNTS = {
    "IND":     {"uid": "7975599901", "password": "B7F06856D60CB0D509D9843AEB442492216098B7452CA5EDB5BD213B0056849D"},
    "AMERICA": {"uid": "7975607162", "password": "7B04A028B5DA44371260D2147762930DF0664F3E5EA305C61A4D144811D7EC91"},
    "OTHERS":  {"uid": "7975609231", "password": "542BC5FD98CAC9A063F3DBAB7DD229183F75703BB1F2381E74680282FB94EABB"},
}

# ============================================================
# VERSION DATA
# ============================================================
_VERSION_LOCK = threading.Lock()

def _load_version_data():
    if VERSION_UPDATER_AVAILABLE:
        try:
            data = get_categories()
            if data and all(k in data for k in ("IND", "AMERICA", "OTHERS")):
                return data
        except Exception as e:
            logger.error(f"[VersionUpdater] failed: {e}")
    return FALLBACK_VERSION_DATA.copy()

VERSION_DATA = _load_version_data()

def refresh_version_data():
    global VERSION_DATA
    new_data = _load_version_data()
    with _VERSION_LOCK:
        VERSION_DATA = new_data

def get_version_config(group: str) -> dict:
    key = (group or "").upper()
    if key not in ("IND", "AMERICA", "OTHERS"):
        key = "OTHERS"
    with _VERSION_LOCK:
        return dict(VERSION_DATA.get(key, VERSION_DATA["OTHERS"]))

# ============================================================
# HELPERS
# ============================================================
def pad_data(data: bytes) -> bytes:
    n = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([n]) * n

def aes_encrypt(data: bytes) -> bytes:
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad_data(data))

def region_to_group(region: str) -> str:
    r = (region or "").upper()
    if r == "IND":
        return "IND"
    if r in ("BR", "US", "NA", "SAC", "AMERICAS"):
        return "AMERICA"
    return "OTHERS"

def unity_headers(group: str, authorization: str = None) -> dict:
    cfg = get_version_config(group)
    h = {
        "User-Agent":       "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept":           "*/*",
        "Accept-Encoding":  "deflate, gzip",
        "X-Ga-Sv":          str(int(time.time())),
        "X-Ga":             "v1 1",
        "ReleaseVersion":   cfg.get("release_version", "OB54"),
        "Content-Type":     "application/x-www-form-urlencoded",
        "X-Unity-Version":  "2018.4.12f1",
    }
    if authorization:
        h["Authorization"] = authorization if authorization.startswith("Bearer ") else f"Bearer {authorization}"
    return h

# ============================================================
# TOKEN CACHE
# ============================================================
TOKEN_CACHE = {}
_TOKEN_LOCK = threading.Lock()

def get_cached_token(group: str):
    with _TOKEN_LOCK:
        e = TOKEN_CACHE.get(group)
        if e and time.time() < e["expires"]:
            return e["token"]
    return None

def set_cached_token(group: str, token: str, ttl: int = 20000):
    with _TOKEN_LOCK:
        TOKEN_CACHE[group] = {"token": token, "expires": time.time() + ttl}

# ============================================================
# OAUTH
# ============================================================
def oauth_get_token(uid: str, password: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = (
        f"uid={uid}&password={password}"
        "&response_type=token&client_type=2"
        f"&client_secret={CLIENT_SECRET}&client_id={CLIENT_ID}"
    )
    headers = {
        "User-Agent":   "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        r = requests.post(url, data=payload, headers=headers, timeout=15)
        if r.status_code != 200:
            logger.error(f"[OAuth] HTTP {r.status_code} for {uid}")
            return None
        d = r.json()
        if not d.get("access_token") or not d.get("open_id"):
            logger.error(f"[OAuth] missing token/open_id: {str(d)[:150]}")
            return None
        return d
    except Exception as e:
        logger.error(f"[OAuth] exception: {e}")
        return None

# ============================================================
# MAJOR LOGIN
# ============================================================
def major_login(access_token: str, open_id: str, group: str, platform: int = 4):
    cfg = get_version_config(group)

    req = DaNgErProTo_pb2.MajorLoginReq()
    req.event_time            = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    req.game_name             = "free fire"
    req.platform_id           = 2
    req.client_version        = cfg.get("client_version", "1.126.2")
    req.client_version_code   = "2024010012"
    req.system_software       = "Android OS 11 / API-30 (RQ3A.210805.001)"
    req.system_hardware       = "Handheld"
    req.device_type           = "Handheld"
    req.telecom_operator      = "Verizon"
    req.network_operator_a    = "Verizon"
    req.network_type          = "WIFI"
    req.network_type_a        = "WIFI"
    req.screen_width          = 1080
    req.screen_height         = 2400
    req.screen_dpi            = "440"
    req.processor_details     = "ARMv8"
    req.cpu_type              = 2
    req.cpu_architecture      = "64"
    req.memory                = 6144
    req.gpu_renderer          = "Adreno (TM) 650"
    req.gpu_version           = "OpenGL ES 3.2 V@1.50"
    req.graphics_api          = "OpenGLES3"
    req.unique_device_id      = "Google|8c8a1f21-1a92-4db8-9605-0ceb7e30e142"
    req.client_ip             = "42.111.19.191"
    req.language              = "en"
    req.open_id               = open_id
    req.open_id_type          = str(platform)
    req.login_open_id_type    = platform
    req.access_token          = access_token
    req.login_by              = 3
    req.platform_sdk_id       = 2
    req.origin_platform_type  = str(platform)
    req.primary_platform_type = str(platform)
    req.region                = REGION_FOR_MAJOR_LOGIN.get(group, "SG")
    req.memory_available.version       = 55
    req.memory_available.hidden_value  = 81
    req.external_storage_total         = 128512
    req.external_storage_available     = 45891
    req.internal_storage_total         = 110731
    req.internal_storage_available     = 27609
    req.game_disk_storage_total        = 26628
    req.game_disk_storage_available    = 20282
    req.external_sdcard_total_storage  = 119234
    req.external_sdcard_avail_storage  = 26730
    req.library_path          = "/data/app/~~random/base.apk"
    req.library_token         = "hash|base.apk"
    req.client_using_version  = "7428b253defc164018c604a1ebbfebdf"
    req.supported_astc_bitset = 16383
    req.analytics_detail      = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    req.loading_time          = 13539
    req.release_channel       = "android"
    req.channel_type          = 3
    req.reg_avatar            = 1
    req.if_push               = 1
    req.is_vpn                = 0
    req.android_engine_init_flag = 110009

    encrypted = aes_encrypt(req.SerializeToString())

    server_url = cfg.get("server_url", "https://loginbp.ggpolarbear.com/")
    if not server_url.endswith("/"):
        server_url += "/"
    url = server_url + "MajorLogin"

    try:
        r = requests.post(url, data=encrypted, headers=unity_headers(group), timeout=20)
        if r.status_code != 200:
            logger.error(f"[MajorLogin/{group}] HTTP {r.status_code} len={len(r.content)}")
            return None

        res = DaNgErProTo_pb2.MajorLoginRes()
        try:
            res.ParseFromString(r.content)
        except Exception:
            pass

        token = None
        if res.ListFields():
            try:
                token = res.token
            except Exception:
                token = None

        if (not token or len(str(token).strip()) < 20) and len(r.content) > 64:
            try:
                res2 = DaNgErProTo_pb2.MajorLoginRes()
                res2.ParseFromString(r.content[64:])
                if res2.ListFields() and res2.token:
                    token = res2.token
            except Exception:
                pass

        if not token:
            logger.error(f"[MajorLogin/{group}] no token in resp")
            return None

        if isinstance(token, (bytes, bytearray)):
            token = token.decode("utf-8", "ignore")
        token = str(token).strip()
        if len(token) < 20:
            return None

        return token

    except Exception as e:
        logger.error(f"[MajorLogin/{group}] exception: {e}")
        return None

def get_jwt(group: str):
    cached = get_cached_token(group)
    if cached:
        return cached
    acc = ACCOUNTS[group]
    oauth = oauth_get_token(acc["uid"], acc["password"])
    if not oauth:
        return None
    token = major_login(oauth["access_token"], oauth["open_id"], group)
    if token:
        set_cached_token(group, token)
    return token

# ============================================================
# BAN CHECK
# ============================================================
def ban_check_single(uid: str, group: str):
    token = get_jwt(group)
    if not token:
        return {"_error": "no_jwt"}

    req = BanCheck_pb2.BanCheckReq()
    req.AccountId    = int(uid)
    req.NeedBanCheck = True

    enc = aes_encrypt(req.SerializeToString())

    cfg = get_version_config(group)
    base = cfg.get("client_url", FALLBACK_VERSION_DATA[group]["client_url"]).rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    url = base + "/GetPlayerPersonalShow"

    try:
        r = requests.post(url, data=enc, headers=unity_headers(group, token), timeout=15)
    except Exception as e:
        logger.error(f"[BanCheck/{group}] exception: {e}")
        return {"_error": f"network: {e}"}

    if r.status_code == 400:
        return {"_error": "not_found", "_code": 400}
    if r.status_code == 403:
        return {"_error": "forbidden", "_code": 403}
    if r.status_code == 429:
        return {"_error": "rate_limited", "_code": 429}
    if r.status_code != 200:
        return {"_error": f"http_{r.status_code}", "_code": r.status_code}

    try:
        res = BanCheck_pb2.BanCheckRes()
        res.ParseFromString(r.content)
        return {"_res": res, "_group": group}
    except Exception as e:
        logger.error(f"[BanCheck/{group}] parse failed: {e}")
        return {"_error": f"parse: {e}"}

def ban_check_all(uid: str):
    results = {}
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {ex.submit(ban_check_single, uid, g): g for g in ACCOUNTS}
        for f in as_completed(futures):
            g = futures[f]
            try:
                results[g] = f.result()
            except Exception as e:
                logger.error(f"[{g}] future err: {e}")
                results[g] = {"_error": str(e)}
    return results

def pick_matching_result(results: dict):
    fallback = None
    for group, r in results.items():
        if not r or "_res" not in r:
            continue
        res = r["_res"]
        basic = res.BasicInfo
        if not basic.Nickname:
            continue
        if fallback is None:
            fallback = (group, res)
        resp_region = (basic.Region or "").upper()
        resp_group  = region_to_group(resp_region)
        if resp_group == group:
            return group, res
    return fallback if fallback else (None, None)

# ============================================================
# ROUTES
# ============================================================
@app.route('/')
def index():
    return jsonify({
        "status": "ok",
        "message": "Ban Check API is running",
        "endpoints": {
            "bancheck": "/bancheck?uid=<UID>",
            "health": "/health",
            "force_version_update": "/force-version-update"
        }
    }), 200

@app.route('/bancheck', methods=['GET'])
def bancheck():
    uid = (request.args.get('uid') or '').strip()
    if not uid:
        return jsonify({"status": "error", "message": "Missing uid"}), 400
    try:
        int(uid)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid uid"}), 400

    results = ban_check_all(uid)
    group, res = pick_matching_result(results)

    if res is None:
        return jsonify({
            "status": "error",
            "message": "Player not found in any region",
            "debug": {g: (r.get("_error") if r else None) for g, r in results.items()}
        }), 404

    basic = res.BasicInfo
    ban   = basic.BanInfo

    return jsonify({
        "status":   "success",
        "uid":      str(basic.AccountId) if basic.AccountId else uid,
        "nickname": basic.Nickname,
        "level":    basic.Level,
        "likes":    basic.Likes,
        "region":   basic.Region,
        "ban_info": {
            "is_banned": bool(ban.IsBanned),
            "ban_time":  int(ban.BanTime),
            "duration":  int(ban.RemainingTime),
        }
    }), 200

@app.route('/health')
def health():
    with _VERSION_LOCK:
        return jsonify({
            "status": "ok",
            "version_updater": VERSION_UPDATER_AVAILABLE,
            "regions": list(VERSION_DATA.keys()),
        }), 200

@app.route('/force-version-update')
def force_version_update():
    try:
        refresh_version_data()
        with _VERSION_LOCK:
            return jsonify({"status": "success", "data": VERSION_DATA}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# NOTE: no app.run() — Vercel/WSGI handles this