#!/usr/bin/env python3
"""
领克 App (v4.2.3) 登录 + 签到脚本

基于 APK / Weex 逆向：
  - 登录网关: https://app-services.lynkco.com.cn
  - 签到接口: POST /up/api/v1/user/sign
  - 鉴权: APPCODE / X-Ca 签名 + header.token

用法示例:
  # 1) 仅用抓包 token 签到（最稳，注意 --token 放在子命令前面）
  python3 lynkco_sign.py --token '你的accessToken' sign
  python3 lynkco_sign.py --token '你的accessToken' sign --status

  # 2) 用 refreshToken 刷新后再签到
  python3 lynkco_sign.py --refresh-token 'xxx' refresh
  python3 lynkco_sign.py sign

  # 3) 交互登录：浏览器弹出极验，你手动点完 → 自动发短信 → 输入验证码 → 登录
  python3 lynkco_sign.py login -m 13800138000
  # 登录后顺便签到
  python3 lynkco_sign.py login -m 13800138000 --sign

  # 4) 只弹出极验页面（调试用）
  python3 lynkco_sign.py captcha

  # 5) 一键：用缓存 token / refresh 签到
  python3 lynkco_sign.py auto

配置文件默认 ~/.lynkco_session.json，也可用 --session 指定。

极验说明:
  发短信接口必须过 GeeTest V4。脚本会在本机起一个临时 HTTP 页，
  自动打开浏览器，你手动完成滑块/点选后，结果回传给脚本继续登录。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import socket
import ssl
import sys
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# 逆向得到的常量（production）
# ---------------------------------------------------------------------------
AUTH_BASE = "https://app-services.lynkco.com.cn"
APPCODE = "3fa3314998bd4195a9fe2df3e85e6a12"
X_CA_KEY = "204644386"
X_CA_SECRET = b"QCl7udM3PB9cOIOwquwPglikFQnzJRsX"
TENANT_ID = "569001643002"
# Weex env: Authentication: AppId=<cep_app_id>
CEP_APP_ID = "59701c08ed454a43a9b"
APP_VERSION = "4.2.3"

# 密码 AES：key/iv 均为 base64(ZGIyMTM5NTYxYzlmZTA2OA==) => db2139561c9fe068
AES_KEY_B64 = "ZGIyMTM5NTYxYzlmZTA2OA=="

# GeeTest V4（发短信用）
GEETEST_CAPTCHA_ID = "c0c2cbf62cbea3fab121d32a6389585a"
GEETEST_API = "https://captcha4.geely.com"

DEFAULT_SESSION = Path.home() / ".lynkco_session.json"
UA = f"okhttp/4.9.3 LynkCo/{APP_VERSION} (Android)"

SSL_CTX = ssl.create_default_context()


def _ok(resp: Dict[str, Any]) -> bool:
    code = str(resp.get("code", ""))
    return code in ("success", "200")


def _print_json(resp: Any) -> None:
    print(json.dumps(resp, ensure_ascii=False, indent=2))


# ---------------------------------------------------------------------------
# HTTP / 签名
# ---------------------------------------------------------------------------
def _ca_sign_headers(
    method: str,
    path_with_query: str,
    content_type: str = "application/json",
    accept: str = "*/*",
) -> Dict[str, str]:
    """阿里云 API 网关 HmacSHA256 签名（Weex buildApiSigature 还原）。"""
    nonce = str(uuid.uuid4())
    ts = str(int(time.time() * 1000))
    signed = {
        "X-Ca-Key": X_CA_KEY,
        "X-Ca-Nonce": nonce,
        "X-Ca-Signature-Method": "HmacSHA256",
        "X-Ca-Timestamp": ts,
    }
    # 与 JS 一致：按插入顺序拼接
    lines = [
        method.upper(),
        accept,
        "",  # Content-MD5
        content_type,
        "",  # Date
    ]
    for k, v in signed.items():
        lines.append(f"{k}:{v}")
    lines.append(path_with_query)
    string_to_sign = "\n".join(lines)
    sig = base64.b64encode(
        hmac.new(X_CA_SECRET, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    ).decode("ascii")
    return {
        **signed,
        "X-Ca-Signature-Headers": "X-Ca-Key,X-Ca-Timestamp,X-Ca-Nonce,X-Ca-Signature-Method",
        "X-Ca-Signature": sig,
        "Accept": accept,
        "Content-Type": content_type,
    }


def request(
    method: str,
    path: str,
    *,
    body: Any = None,
    token: Optional[str] = None,
    use_security: bool = False,
    auth_mode: str = "appcode",  # appcode | ca | both
    extra_headers: Optional[Dict[str, str]] = None,
    base: str = AUTH_BASE,
) -> Dict[str, Any]:
    """发请求。path 以 / 开头；auth_mode 控制网关鉴权方式。"""
    if not path.startswith("/"):
        path = "/" + path
    url = base.rstrip("/") + path

    headers: Dict[str, str] = {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json; charset=utf-8",
        "tenantId": TENANT_ID,
        "Authentication": f"AppId={CEP_APP_ID}",
    }

    if auth_mode in ("appcode", "both"):
        headers["Authorization"] = f"APPCODE {APPCODE}"
        headers["X-Ca-Nonce"] = str(uuid.uuid4())
    if auth_mode in ("ca", "both"):
        # ca 签名头会覆盖部分字段；sendSms 等接口需要
        headers.update(_ca_sign_headers(method, path))

    if use_security:
        headers["use_security"] = "true"
    if token:
        headers["token"] = token
    if extra_headers:
        headers.update(extra_headers)

    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    elif method.upper() in ("POST", "PUT", "PATCH") and data is None:
        data = b"{}"

    req = Request(url, data=data, headers=headers, method=method.upper())
    try:
        with urlopen(req, timeout=30, context=SSL_CTX) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        ca_msg = e.headers.get("X-Ca-Error-Message") if e.headers else None
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"code": "http_error", "message": raw or str(e), "http_status": e.code}
        if ca_msg:
            payload.setdefault("ca_error", ca_msg)
        payload.setdefault("http_status", e.code)
        return payload
    except URLError as e:
        return {"code": "network_error", "message": str(e.reason)}

    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"code": "bad_json", "message": raw[:500]}


def encrypt_password(password: str) -> str:
    """账密登录用 AES-CBC，与 Weex getEncryptPwd 一致。"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ImportError:
        raise SystemExit("账密登录需要 pycryptodome: pip install pycryptodome")

    key = base64.b64decode(AES_KEY_B64)
    iv = key  # 同源 key/iv
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(password.encode("utf-8"), AES.block_size))
    return ct.hex()


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
def load_session(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_session(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[*] session 已保存: {path}")


def extract_tokens(login_data: Dict[str, Any]) -> Dict[str, str]:
    """从登录响应 data 里抽出 token。"""
    data = login_data.get("data") or login_data
    ctd = data.get("centerTokenDto") or data
    token = (
        ctd.get("token")
        or ctd.get("accessToken")
        or data.get("token")
        or data.get("accessToken")
        or ""
    )
    refresh = (
        ctd.get("refreshToken")
        or data.get("refreshToken")
        or ""
    )
    svc = ctd.get("svcToken") or data.get("svcToken") or ""
    return {"token": token, "refreshToken": refresh, "svcToken": svc}


# ---------------------------------------------------------------------------
# GeeTest V4 本地页面（浏览器手动点）
# ---------------------------------------------------------------------------
GEETEST_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <title>领克登录 · 极验 GeeTest V4</title>
  <style>
    :root { color-scheme: light dark; }
    body {
      margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Helvetica Neue", sans-serif;
      background: #0f1115; color: #e8e8e8;
    }
    .card {
      width: min(420px, 92vw); padding: 28px 24px 32px; border-radius: 16px;
      background: #1a1d24; box-shadow: 0 12px 40px rgba(0,0,0,.45);
    }
    h1 { font-size: 18px; margin: 0 0 8px; font-weight: 600; }
    p { margin: 0 0 18px; color: #9aa0a6; font-size: 13px; line-height: 1.5; }
    #box { min-height: 50px; display: flex; justify-content: center; }
    #status { margin-top: 16px; font-size: 13px; color: #9aa0a6; word-break: break-all; }
    #status.ok { color: #3dd68c; }
    #status.err { color: #ff6b6b; }
    button {
      margin-top: 14px; width: 100%; height: 40px; border: 0; border-radius: 10px;
      background: #1ef1c6; color: #131313; font-weight: 600; cursor: pointer;
    }
    button:disabled { opacity: .5; cursor: not-allowed; }
    code { color: #1ef1c6; }
  </style>
  <!-- 优先用吉利极验域 SDK（支持 apiServers） -->
  <script src="https://captcha4.geely.com/www/gt4.js"></script>
</head>
<body>
  <div class="card">
    <h1>完成人机验证</h1>
    <p>这是领克 App 登录发短信前的 <code>GeeTest V4</code>。<br/>点下面按钮，按提示完成验证，页面会自动回传给脚本。</p>
    <div id="box"></div>
    <button id="btn" type="button">开始验证</button>
    <div id="status">准备中…</div>
  </div>
  <script>
    const CFG = __GEETEST_CFG__;
    const statusEl = document.getElementById('status');
    const btn = document.getElementById('btn');
    let captchaObj = null;

    function setStatus(msg, cls) {
      statusEl.className = cls || '';
      statusEl.textContent = msg;
    }

    function postResult(payload) {
      return fetch('/result', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }).then(r => r.json());
    }

    function boot() {
      if (typeof initGeetest4 !== 'function' && typeof initGeetest !== 'function') {
        // 回退官方 CDN
        const s = document.createElement('script');
        s.src = 'https://static.geetest.com/v4/gt4.js';
        s.onload = initCaptcha;
        s.onerror = () => setStatus('极验 SDK 加载失败，请检查网络', 'err');
        document.head.appendChild(s);
      } else {
        initCaptcha();
      }
    }

    function initCaptcha() {
      const config = {
        captchaId: CFG.captchaId,
        product: 'bind',
        language: 'zho',
        protocol: 'https://',
      };
      if (CFG.apiServer) config.apiServers = [CFG.apiServer.replace(/^https?:\/\//, '').replace(/\/$/, '')];
      if (CFG.staticServer) config.staticServers = [CFG.staticServer.replace(/^https?:\/\//, '').replace(/\/$/, '')];
      // 有的版本要完整 host 带协议
      if (CFG.apiServer) {
        config.apiServers = [CFG.apiServer.replace(/\/$/, '')];
      }
      if (CFG.staticServer) {
        config.staticServers = [CFG.staticServer.replace(/\/$/, '')];
      }

      const starter = typeof initGeetest4 === 'function' ? initGeetest4 : initGeetest;
      setStatus('正在初始化极验… captchaId=' + CFG.captchaId);

      starter(config, function (captcha) {
        captchaObj = captcha;
        try { captcha.appendTo('#box'); } catch (e) {}
        setStatus('极验已就绪，点击「开始验证」');
        btn.disabled = false;

        captcha.onSuccess(function () {
          const v = captcha.getValidate() || {};
          setStatus('验证成功，正在回传脚本…', 'ok');
          postResult({
            ok: true,
            captcha_id: v.captcha_id || CFG.captchaId,
            lot_number: v.lot_number,
            captcha_output: v.captcha_output,
            pass_token: v.pass_token,
            gen_time: v.gen_time,
            raw: v
          }).then(() => {
            setStatus('已回传脚本，可以关闭此页面，回到终端继续。', 'ok');
            btn.textContent = '验证完成';
            btn.disabled = true;
          }).catch(err => setStatus('回传失败: ' + err, 'err'));
        });

        captcha.onError(function (e) {
          setStatus('极验错误: ' + JSON.stringify(e), 'err');
        });

        captcha.onClose(function () {
          setStatus('验证被关闭，可重新点击按钮');
        });
      });
    }

    btn.disabled = true;
    btn.addEventListener('click', function () {
      if (!captchaObj) return;
      setStatus('请完成滑块/点选…');
      if (typeof captchaObj.showCaptcha === 'function') captchaObj.showCaptcha();
      else if (typeof captchaObj.verify === 'function') captchaObj.verify();
    });

    boot();
  </script>
</body>
</html>
"""


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def open_geetest_in_browser(
    captcha_id: str,
    api_server: str,
    static_server: str,
    *,
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    本机起临时 HTTP，打开浏览器让用户手动过极验，返回 getValidate() 结果。
    """
    result_box: Dict[str, Any] = {}
    done = threading.Event()
    port = _pick_free_port()

    cfg_json = json.dumps(
        {
            "captchaId": captcha_id,
            "apiServer": api_server,
            "staticServer": static_server,
        },
        ensure_ascii=False,
    )
    html = GEETEST_HTML.replace("__GEETEST_CFG__", cfg_json)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:  # quiet
            return

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path in ("/", "/index.html", "/captcha"):
                body = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            if path == "/result":
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError:
                    payload = {"ok": False, "error": "bad json"}
                result_box.update(payload)
                done.set()
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{port}/"
    print(f"[*] 极验页面: {url}")
    print("[*] 正在打开浏览器，请在页面里手动完成验证…")
    try:
        webbrowser.open(url)
    except Exception as e:  # noqa: BLE001
        print(f"[!] 自动打开浏览器失败: {e}，请手动访问上面的地址", file=sys.stderr)

    if not done.wait(timeout):
        server.shutdown()
        raise TimeoutError(f"等待极验超时（{timeout}s），请重试")

    # 给页面一点时间收到 200
    time.sleep(0.3)
    server.shutdown()

    if not result_box.get("ok"):
        raise RuntimeError(f"极验未成功: {result_box}")
    return result_box


# ---------------------------------------------------------------------------
# 登录
# ---------------------------------------------------------------------------
def geetest_config() -> Dict[str, Any]:
    return request(
        "GET",
        "/auth/v1/security/config?type=GEE_TEST_V4",
        auth_mode="appcode",
    )


def validate_geetest(
    lot_number: str,
    captcha_output: str,
    pass_token: str,
    gen_time: str,
    *,
    scene: str = "mobileChangeSendsms",
) -> Dict[str, Any]:
    """
    POST /auth/v1/security/geeTestV4/validate
    成功时 data 里通常有 certifyId，用作 challenge。
    """
    body = {
        "lotNumber": lot_number,
        "captchaOutput": captcha_output,
        "passToken": pass_token,
        "genTime": gen_time,
        "scene": scene,
    }
    return request(
        "POST",
        "/auth/v1/security/geeTestV4/validate",
        body=body,
        auth_mode="appcode",
        use_security=True,
    )


def solve_geetest_for_login(*, timeout: int = 300) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    """
    完整极验：浏览器手动点 → 服务端 validate → 返回 (certifyId, sliding字段, 原始validate响应)
    """
    cfg_resp = geetest_config()
    if not _ok(cfg_resp):
        raise RuntimeError(f"获取极验配置失败: {cfg_resp}")
    data = cfg_resp.get("data") or {}
    captcha_id = data.get("captchaId") or GEETEST_CAPTCHA_ID
    api_server = data.get("apiServer") or GEETEST_API
    static_server = data.get("staticServer") or f"{GEETEST_API}/www/js/"

    print("[*] 极验配置 captchaId =", captcha_id)
    print("[*] apiServer =", api_server)

    raw = open_geetest_in_browser(
        captcha_id,
        api_server,
        static_server,
        timeout=timeout,
    )
    print("[*] 浏览器极验完成，向领克后端校验…")
    _print_json({k: raw.get(k) for k in ("lot_number", "gen_time", "pass_token") if k in raw})

    vresp = validate_geetest(
        str(raw.get("lot_number") or ""),
        str(raw.get("captcha_output") or ""),
        str(raw.get("pass_token") or ""),
        str(raw.get("gen_time") or ""),
        scene="mobileChangeSendsms",
    )
    print("[*] validate 响应:")
    _print_json(vresp)
    if not _ok(vresp):
        raise RuntimeError(f"极验服务端校验失败: {vresp.get('message') or vresp}")

    vdata = vresp.get("data") or {}
    if isinstance(vdata, dict):
        certify_id = (
            vdata.get("certifyId")
            or vdata.get("challenge")
            or vdata.get("certify_id")
            or ""
        )
    else:
        certify_id = str(vdata or "")

    if not certify_id:
        # 有的环境 data 直接是字符串
        raise RuntimeError(f"validate 成功但没有 certifyId: {vresp}")

    sliding = {
        "lotNumber": raw.get("lot_number"),
        "captchaOutput": raw.get("captcha_output"),
        "passToken": raw.get("pass_token"),
        "genTime": raw.get("gen_time"),
    }
    print("[*] certifyId / challenge =", certify_id)
    return str(certify_id), sliding, vresp


def send_sms(
    mobile: str,
    *,
    challenge: str = "",
    sliding: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    POST /auth/login/sliding/sendSms  （需要 X-Ca 签名）

    sliding: 极验校验相关字段（若有），例如:
      lotNumber / captchaOutput / passToken / genTime 或服务端要求的滑块字段
    challenge: 极验 validate 返回的 certifyId
    """
    body: Dict[str, Any] = {"mobile": mobile}
    if sliding:
        body.update({k: v for k, v in sliding.items() if v is not None})
    if challenge:
        body["challenge"] = challenge
    return request(
        "POST",
        "/auth/login/sliding/sendSms",
        body=body,
        auth_mode="ca",
        use_security=True,
    )


def login_sms(
    mobile: str,
    code: str,
    *,
    device_id: str = "",
    device_model: str = "Pixel 7",
    certify_id: str = "",
    send_certify_header: bool = False,
) -> Dict[str, Any]:
    """
    POST /auth/login/mobileCodeLogin?...  body={}

    App 逻辑（Weex submitXhr）：
      - query: deviceId / hardwareDeviceId / deviceModel / deviceType / appVersion / mobile / verificationCode
      - header: use_security=true
      - certifyId 头：主流程短信登录里通常是空的（极验 challenge 只用于 sendSms，不用于 login）
      - 若带上已消费的极验 certifyId，服务端会报 oneid.account.certify.validate.fail

    默认不传 certifyId；仅当 send_certify_header=True 时才带。
    """
    dev = device_id or str(uuid.uuid4())
    q = {
        "deviceId": dev,
        "hardwareDeviceId": dev,
        "deviceModel": device_model or "unknow",
        "deviceType": "ANDROID",
        "appVersion": APP_VERSION,
        "mobile": mobile,
        "verificationCode": code,
    }
    path = "/auth/login/mobileCodeLogin?" + urlencode(q)
    # 与 App 对齐：始终带 use_security；certifyId 默认不传（空头也不传，避免 validate.fail）
    extra: Dict[str, str] = {"use_security": "true"}
    if send_certify_header and certify_id:
        extra["certifyId"] = certify_id
    return request(
        "POST",
        path,
        body={},
        auth_mode="appcode",
        use_security=True,
        extra_headers=extra,
    )


def login_password(
    username: str,
    password: str,
    *,
    challenge: str = "",
    sliding: Optional[Dict[str, Any]] = None,
    device_id: str = "",
    device_model: str = "Pixel 7",
    certify_id: str = "",
) -> Dict[str, Any]:
    """POST /auth/login/sliding/login?...  账密 + 极验。"""
    q: Dict[str, Any] = {
        "deviceId": device_id or str(uuid.uuid4()),
        "hardwareDeviceId": device_id or "",
        "deviceModel": device_model,
        "deviceType": "ANDROID",
        "appVersion": APP_VERSION,
        "username": username,
        "password": encrypt_password(password),
    }
    if sliding:
        q.update(sliding)
    if challenge:
        q["challenge"] = challenge
    path = "/auth/login/sliding/login?" + urlencode(q)
    extra = {"use_security": "true"}
    if certify_id:
        extra["certifyId"] = certify_id
    return request(
        "POST",
        path,
        body={},
        auth_mode="appcode",
        use_security=True,
        extra_headers=extra,
    )


def refresh_token(refresh: str) -> Dict[str, Any]:
    path = "/auth/login/refresh?" + urlencode({"refreshToken": refresh})
    return request("GET", path, auth_mode="appcode")


def user_info(token: str) -> Dict[str, Any]:
    return request("GET", "/auth/user/info", token=token, auth_mode="appcode")


# ---------------------------------------------------------------------------
# 签到
# ---------------------------------------------------------------------------
def sign_in(token: str) -> Dict[str, Any]:
    """真正的每日签到。"""
    return request(
        "POST",
        "/up/api/v1/user/sign",
        body={},
        token=token,
        auth_mode="appcode",
        use_security=True,
    )


def sign_status(token: str) -> Dict[str, Any]:
    """我的页签到状态。"""
    return request(
        "GET",
        "/up/api/v1/user/sign/day/info",
        token=token,
        auth_mode="appcode",
    )


def continue_days(token: str) -> Dict[str, Any]:
    return request(
        "GET",
        "/up/api/v1/userReward/getContinueDaysAndSignCard",
        token=token,
        auth_mode="appcode",
    )


def sign_calendar(token: str, start_ms: int, end_ms: int) -> Dict[str, Any]:
    return request(
        "POST",
        "/up/api/v1/user/sign/sign/info",
        body={"startDate": start_ms, "endDate": end_ms},
        token=token,
        auth_mode="appcode",
    )


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------
def _require_token(args: argparse.Namespace, session: Dict[str, Any]) -> str:
    token = args.token or session.get("token") or ""
    if not token:
        raise SystemExit("缺少 token。请 --token 传入，或先 login / refresh。")
    return token


def cmd_geetest(args: argparse.Namespace) -> int:
    resp = geetest_config()
    _print_json(resp)
    if _ok(resp) and resp.get("data"):
        d = resp["data"]
        print("\n[*] 浏览器可访问:", d.get("resourcePath"))
        print("[*] captchaId:", d.get("captchaId") or GEETEST_CAPTCHA_ID)
        print("[*] apiServer:", d.get("apiServer") or GEETEST_API)
        print("\n提示: 要手动点极验请用  python3 lynkco_sign.py captcha")
    return 0 if _ok(resp) else 1


def cmd_captcha(args: argparse.Namespace) -> int:
    """打开浏览器做极验，并把 certifyId 打印出来。"""
    try:
        certify_id, sliding, _ = solve_geetest_for_login(timeout=args.timeout)
    except Exception as e:  # noqa: BLE001
        print(f"[!] 极验失败: {e}", file=sys.stderr)
        return 1
    print("\n=== 可直接用于发短信的参数 ===")
    print("challenge/certifyId:", certify_id)
    print("sliding:", json.dumps(sliding, ensure_ascii=False))
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    """
    交互登录：
      1. 浏览器手动过极验
      2. 发短信
      3. 终端输入验证码
      4. 登录保存 session
      5. 可选 --sign
    """
    mobile = args.mobile
    if not mobile or not re_mobile(mobile):
        raise SystemExit("请提供合法手机号: -m 1xxxxxxxxxx")

    print(f"[*] 准备登录手机号: {mobile}")
    # 全程固定 deviceId，避免 send/login 设备不一致
    device_id = args.device_id or str(uuid.uuid4())
    device_model = args.device_model or "Pixel 7"

    try:
        challenge, sliding, _ = solve_geetest_for_login(timeout=args.timeout)
    except Exception as e:  # noqa: BLE001
        print(f"[!] 极验失败: {e}", file=sys.stderr)
        return 1

    print("[*] 发送短信验证码…")
    # challenge 仅用于 sendSms（App 字段名 challenge），不要原样塞进 login 的 certifyId 头
    sms_resp = send_sms(mobile, challenge=challenge)
    if not _ok(sms_resp):
        print("[*] challenge 单独发送失败，带极验字段重试…")
        sms_resp = send_sms(mobile, challenge=challenge, sliding=sliding)
    print("[*] 发短信响应:")
    _print_json(sms_resp)
    if not _ok(sms_resp):
        print("[!] 发短信失败，可能极验场景/字段不匹配，或风控拦截", file=sys.stderr)
        return 1

    code = (args.code or "").strip()
    if not code:
        try:
            code = input("请输入短信验证码: ").strip()
        except EOFError:
            code = ""
    if not code:
        print("[!] 未输入验证码", file=sys.stderr)
        return 1

    print("[*] 提交登录（不传 certifyId 头，与 App 短信登录主路径一致）…")
    login_resp = login_sms(
        mobile,
        code,
        device_id=device_id,
        device_model=device_model,
        send_certify_header=False,
    )
    print("[*] 登录响应:")
    _print_json(login_resp)

    # 兼容：个别环境若明确要求 certifyId，再试一次（一般不应走到这里）
    if not _ok(login_resp) and "certify" in str(login_resp.get("message", "")).lower():
        print("[*] 仍报 certify 相关错误，尝试带 certifyId 头重试…")
        login_resp = login_sms(
            mobile,
            code,
            device_id=device_id,
            device_model=device_model,
            certify_id=challenge,
            send_certify_header=True,
        )
        _print_json(login_resp)

    if not _ok(login_resp):
        msg = str(login_resp.get("message") or "")
        if "certify.validate.fail" in msg:
            print(
                "\n[!] oneid.account.certify.validate.fail 说明：\n"
                "    极验 challenge 只应用于发短信；登录不应再校验同一个 certifyId。\n"
                "    已改为默认不传。若仍失败，请重新跑 login 拿新验证码再试。\n"
                "    也可能是验证码过期/已被使用，请重新收短信。\n",
                file=sys.stderr,
            )
        return 1

    tokens = extract_tokens(login_resp)
    if not tokens.get("token"):
        # 有的响应包在 data.centerTokenDto
        data = login_resp.get("data") or {}
        if isinstance(data, dict) and data.get("secureFlag") == 1:
            tokens = extract_tokens(login_resp)
        if not tokens.get("token"):
            print("[!] 登录成功但未解析到 token，完整 data：", file=sys.stderr)
            _print_json(login_resp.get("data"))
            return 1

    session = load_session(args.session)
    session.update(tokens)
    session["mobile"] = mobile
    session["deviceId"] = device_id
    session["smsChallenge"] = challenge  # 仅记录，非 login header
    session["updatedAt"] = int(time.time())
    save_session(args.session, session)
    print("[*] 登录成功，token 前 16 位:", tokens["token"][:16] + "...")

    if args.sign:
        print("[*] 继续签到…")
        args.token = tokens["token"]
        return cmd_sign(args)
    return 0


def re_mobile(mobile: str) -> bool:
    return bool(mobile) and mobile.isdigit() and len(mobile) == 11 and mobile.startswith("1")


def cmd_send_sms(args: argparse.Namespace) -> int:
    challenge = args.challenge or ""
    sliding = None
    if args.lot_number:
        sliding = {
            "lotNumber": args.lot_number,
            "captchaOutput": args.captcha_output or "",
            "passToken": args.pass_token or "",
            "genTime": args.gen_time or "",
        }

    # --browser：先弹出极验
    if args.browser:
        try:
            challenge, sliding, _ = solve_geetest_for_login(timeout=args.timeout)
        except Exception as e:  # noqa: BLE001
            print(f"[!] 极验失败: {e}", file=sys.stderr)
            return 1

    resp = send_sms(args.mobile, challenge=challenge, sliding=sliding)
    _print_json(resp)
    if not _ok(resp):
        print(
            "\n[!] 发短信失败。推荐用交互登录:\n"
            "    python3 lynkco_sign.py login -m 手机号\n",
            file=sys.stderr,
        )
    return 0 if _ok(resp) else 1


def cmd_login_sms(args: argparse.Namespace) -> int:
    resp = login_sms(
        args.mobile,
        args.code,
        device_id=args.device_id or "",
        device_model=args.device_model,
        certify_id=args.challenge or "",
    )
    _print_json(resp)
    if not _ok(resp):
        return 1
    tokens = extract_tokens(resp)
    if not tokens.get("token"):
        print("[!] 登录成功但未解析到 token，请检查响应结构", file=sys.stderr)
        return 1
    session = load_session(args.session)
    session.update(tokens)
    session["mobile"] = args.mobile
    session["updatedAt"] = int(time.time())
    save_session(args.session, session)
    print("[*] token 前 16 位:", tokens["token"][:16] + "...")
    return 0


def cmd_login_pwd(args: argparse.Namespace) -> int:
    sliding = None
    if args.lot_number:
        sliding = {
            "lotNumber": args.lot_number,
            "captchaOutput": args.captcha_output or "",
            "passToken": args.pass_token or "",
            "genTime": args.gen_time or "",
        }
    resp = login_password(
        args.username,
        args.password,
        challenge=args.challenge or "",
        sliding=sliding,
        device_id=args.device_id or "",
        device_model=args.device_model,
        certify_id=args.challenge or "",
    )
    _print_json(resp)
    if not _ok(resp):
        return 1
    tokens = extract_tokens(resp)
    session = load_session(args.session)
    session.update(tokens)
    session["username"] = args.username
    session["updatedAt"] = int(time.time())
    save_session(args.session, session)
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    session = load_session(args.session)
    refresh = args.refresh_token or session.get("refreshToken") or ""
    if not refresh:
        raise SystemExit("缺少 refreshToken")
    resp = refresh_token(refresh)
    _print_json(resp)
    if not _ok(resp):
        return 1
    tokens = extract_tokens(resp)
    # refresh 接口 data 本身就是 centerTokenDto
    if not tokens.get("token") and isinstance(resp.get("data"), dict):
        tokens = extract_tokens({"data": {"centerTokenDto": resp["data"]}})
    session.update({k: v for k, v in tokens.items() if v})
    if not session.get("refreshToken"):
        session["refreshToken"] = refresh
    session["updatedAt"] = int(time.time())
    save_session(args.session, session)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    session = load_session(args.session)
    token = _require_token(args, session)

    if args.status:
        print("=== 签到状态 day/info ===")
        _print_json(sign_status(token))
        print("=== 连续天数/补签卡 ===")
        _print_json(continue_days(token))
        return 0

    print("=== 发起签到 POST /up/api/v1/user/sign ===")
    resp = sign_in(token)
    _print_json(resp)
    if _ok(resp):
        data = resp.get("data") or {}
        if data.get("todayFirstSign"):
            print("[*] 今日首次签到成功")
        else:
            print("[*] 签到接口成功（可能今日已签过）")
        return 0
    msg = str(resp.get("message", ""))
    if "not.exist" in msg or "login" in msg.lower() or str(resp.get("code")) in ("401", "user-not-login"):
        print("[!] token 无效/过期，请重新 login 或 refresh", file=sys.stderr)
    return 1


def cmd_info(args: argparse.Namespace) -> int:
    session = load_session(args.session)
    token = _require_token(args, session)
    _print_json(user_info(token))
    return 0


def cmd_auto(args: argparse.Namespace) -> int:
    """有 token 直接签；有 refresh 先刷；都没有则提示。"""
    session = load_session(args.session)
    token = args.token or session.get("token")
    refresh = args.refresh_token or session.get("refreshToken")

    if not token and refresh:
        print("[*] 无 accessToken，尝试 refresh...")
        args.refresh_token = refresh
        if cmd_refresh(args) != 0:
            return 1
        session = load_session(args.session)
        token = session.get("token")

    if not token:
        raise SystemExit(
            "没有可用 token。\n"
            "  - 从 Charles/mitmproxy 抓 header `token` 后:\n"
            "      python3 lynkco_sign.py --token 'xxx' sign\n"
            "  - 或完成短信登录:\n"
            "      python3 lynkco_sign.py login-sms -m 手机号 -c 验证码 --challenge certifyId"
        )

    args.token = token
    return cmd_sign(args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="领克 App 登录 + 签到（逆向自 lynkco-64-v4.2.3）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--session",
        type=Path,
        default=DEFAULT_SESSION,
        help=f"会话文件路径 (default: {DEFAULT_SESSION})",
    )
    p.add_argument("--token", help="accessToken（写入 header token）")
    p.add_argument("--refresh-token", dest="refresh_token", help="refreshToken")
    p.add_argument("--device-id", dest="device_id", default="", help="设备 ID")
    p.add_argument("--device-model", dest="device_model", default="Pixel 7")
    p.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="等待浏览器完成极验的秒数 (default: 300)",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("geetest", help="拉取极验配置（不打开浏览器）")
    sub.add_parser("captcha", help="打开浏览器手动过极验，打印 certifyId")

    s = sub.add_parser(
        "login",
        help="交互登录：浏览器极验 → 发短信 → 输入验证码 → 保存 session",
    )
    s.add_argument("-m", "--mobile", required=True, help="手机号")
    s.add_argument("-c", "--code", default="", help="短信验证码（不填则交互输入）")
    s.add_argument("--sign", action="store_true", help="登录成功后立即签到")

    s = sub.add_parser("send-sms", help="发送登录短信（可用 --browser 弹极验）")
    s.add_argument("-m", "--mobile", required=True)
    s.add_argument("--browser", action="store_true", help="先打开浏览器做极验")
    s.add_argument("--challenge", default="", help="极验 certifyId")
    s.add_argument("--lot-number", dest="lot_number", default="")
    s.add_argument("--captcha-output", dest="captcha_output", default="")
    s.add_argument("--pass-token", dest="pass_token", default="")
    s.add_argument("--gen-time", dest="gen_time", default="")

    s = sub.add_parser("login-sms", help="短信验证码登录（已有验证码时）")
    s.add_argument("-m", "--mobile", required=True)
    s.add_argument("-c", "--code", required=True, help="短信验证码")
    s.add_argument("--challenge", default="", help="certifyId（可选）")

    s = sub.add_parser("login-pwd", help="账号密码登录（需极验字段）")
    s.add_argument("-u", "--username", required=True)
    s.add_argument("-p", "--password", required=True)
    s.add_argument("--challenge", default="")
    s.add_argument("--lot-number", dest="lot_number", default="")
    s.add_argument("--captcha-output", dest="captcha_output", default="")
    s.add_argument("--pass-token", dest="pass_token", default="")
    s.add_argument("--gen-time", dest="gen_time", default="")

    sub.add_parser("refresh", help="刷新 accessToken")

    s = sub.add_parser("sign", help="执行签到 / 查看状态")
    s.add_argument("--status", action="store_true", help="只查状态不签到")

    sub.add_parser("info", help="查询用户信息")
    sub.add_parser("auto", help="自动 refresh（如需要）+ 签到")

    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.session = args.session.expanduser()

    dispatch = {
        "geetest": cmd_geetest,
        "captcha": cmd_captcha,
        "login": cmd_login,
        "send-sms": cmd_send_sms,
        "login-sms": cmd_login_sms,
        "login-pwd": cmd_login_pwd,
        "refresh": cmd_refresh,
        "sign": cmd_sign,
        "info": cmd_info,
        "auto": cmd_auto,
    }
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
