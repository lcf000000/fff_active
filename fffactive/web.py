"""激活码生成网页（Flask）。需要环境变量 ADMIN_PASSWORD，以及 FFF_ACTIVE_ED_SEED（标准码）和/或 FFF_ACTIVE_SECRET（紧凑码）。"""
import hmac
import os
import time
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from . import codec


def _clean(v: str) -> str:
    """去掉首尾空白和成对引号（NAS 界面里常见的粘贴误差）。"""
    v = (v or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    return v


def create_app(secret_hex: str = None, admin_password: str = None, data_dir: str = None,
               ed_seed_hex: str = None) -> Flask:
    secret_hex = secret_hex if secret_hex is not None else os.environ.get("FFF_ACTIVE_SECRET", "")
    ed_seed_hex = ed_seed_hex if ed_seed_hex is not None else os.environ.get("FFF_ACTIVE_ED_SEED", "")
    admin_password = admin_password if admin_password is not None else os.environ.get("ADMIN_PASSWORD", "")
    data_dir = Path(data_dir or os.environ.get("DATA_DIR", "data"))
    admin_user = os.environ.get("ADMIN_USER", "admin")
    # 密钥配置有问题时不让进程崩溃（NAS 图形界面看不到日志），而是照常起来，在页面上显示错误横幅。
    # 横幅里只写“哪个变量、出了什么问题”，绝不包含变量的值。
    banners = []
    ed_seed = mac_secret = None
    ed_public_hex = ""
    ed_seed_hex = _clean(ed_seed_hex)
    secret_hex = _clean(secret_hex)
    if not ed_seed_hex:
        banners.append("未设置 FFF_ACTIVE_ED_SEED：请在容器的环境变量里填入 64 位十六进制的 Ed25519 私钥种子"
                       "（可在任意电脑上执行 python3 -c \"import secrets;print(secrets.token_hex(32))\" 生成），保存后重启容器。"
                       "没有它就无法生成标准码，也无法显示 APK 构建所需的公钥。")
    else:
        try:
            ed_seed = codec.parse_ed_seed(ed_seed_hex)
            ed_public_hex = codec.ed_public_from_seed(ed_seed).hex()
        except codec.CodecError:
            ed_seed = None
            banners.append("FFF_ACTIVE_ED_SEED 格式不对：必须正好是 64 位十六进制字符（0-9、a-f，共 32 字节），"
                           "且不要带引号、空格或换行。请修正环境变量后重启容器。")
    if secret_hex:
        try:
            mac_secret = codec.parse_secret(secret_hex)
        except codec.CodecError:
            banners.append("FFF_ACTIVE_SECRET 格式不对：必须正好是 64 位十六进制字符；不需要紧凑码的话请把它留空。紧凑码已被禁用。")
    keys = codec.Keys(ed_seed, mac_secret) if (ed_seed or mac_secret) else None
    modes = keys.modes() if keys else []
    if len(admin_password) < 8 or admin_password in ("change-me", "changeme", "password"):
        raise RuntimeError("ADMIN_PASSWORD 未设置或太弱（至少 8 位，且不能用示例值）")
    data_dir.mkdir(parents=True, exist_ok=True)
    history = data_dir / "history.log"

    app = Flask(__name__)

    def unauthorized():
        return Response("需要登录", 401, {"WWW-Authenticate": 'Basic realm="fff_active"'})

    @app.before_request
    def auth():
        if request.path == "/healthz":
            return None
        a = request.authorization
        if not a or not hmac.compare_digest(a.username or "", admin_user) \
                or not hmac.compare_digest(a.password or "", admin_password):
            time.sleep(0.5)  # 拖慢暴力猜测
            return unauthorized()
        return None

    @app.after_request
    def headers(r):
        r.headers["Cache-Control"] = "no-store"
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["X-Frame-Options"] = "DENY"
        return r

    @app.get("/healthz")
    def healthz():
        return "ok"

    @app.get("/")
    def index():
        return render_template("index.html", modes=modes, banners=banners, ed_public=ed_public_hex)

    @app.post("/api/generate")
    def generate():
        # 自定义请求头：跨站表单提交带不上，用来挡 CSRF（浏览器会自动带 Basic 凭据）
        if request.headers.get("X-Requested-With") != "fff":
            return jsonify(ok=False, error="非法请求"), 400
        if not modes:
            return jsonify(ok=False, error="服务端密钥未正确配置，见页面顶部的红色提示"), 503
        body = request.get_json(silent=True) or {}
        bid = codec.normalize_bid(str(body.get("vin", "")))
        mode = str(body.get("mode") or modes[0])
        try:
            if mode not in modes:
                raise codec.CodecError("该模式未启用（服务端没有配置对应密钥）")
            kind = codec.validate_bid(bid)
            code = codec.generate(keys, bid, mode)
        except codec.CodecError as e:
            return jsonify(ok=False, error=str(e)), 400
        try:
            with history.open("a", encoding="utf-8") as f:
                f.write("%s\t%s\t%s\t%s\t%s\t%s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), mode, kind, bid, code,
                                                  request.headers.get("X-Forwarded-For", request.remote_addr)))
        except OSError:
            pass  # 历史记录写不了不影响出码
        return jsonify(ok=True, code=code, kind=kind, vin=bid, mode=mode, length=len(code))

    @app.get("/api/history")
    def history_view():
        if not history.exists():
            return Response("", mimetype="text/plain; charset=utf-8")
        lines = history.read_text(encoding="utf-8").splitlines()[-200:]
        return Response("\n".join(reversed(lines)), mimetype="text/plain; charset=utf-8")

    return app
