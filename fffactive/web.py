"""激活码生成网页（Flask）。需要环境变量 FFF_ACTIVE_SECRET、ADMIN_PASSWORD。"""
import hmac
import os
import time
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from . import codec


def create_app(secret_hex: str = None, admin_password: str = None, data_dir: str = None) -> Flask:
    secret_hex = secret_hex if secret_hex is not None else os.environ.get("FFF_ACTIVE_SECRET", "")
    admin_password = admin_password if admin_password is not None else os.environ.get("ADMIN_PASSWORD", "")
    data_dir = Path(data_dir or os.environ.get("DATA_DIR", "data"))
    admin_user = os.environ.get("ADMIN_USER", "admin")
    secret = codec.parse_secret(secret_hex)
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
        return render_template("index.html")

    @app.post("/api/generate")
    def generate():
        # 自定义请求头：跨站表单提交带不上，用来挡 CSRF（浏览器会自动带 Basic 凭据）
        if request.headers.get("X-Requested-With") != "fff":
            return jsonify(ok=False, error="非法请求"), 400
        body = request.get_json(silent=True) or {}
        bid = codec.normalize_bid(str(body.get("vin", "")))
        try:
            kind = codec.validate_bid(bid)
            code = codec.generate(secret, bid)
        except codec.CodecError as e:
            return jsonify(ok=False, error=str(e)), 400
        try:
            with history.open("a", encoding="utf-8") as f:
                f.write("%s\t%s\t%s\t%s\t%s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), kind, bid, code,
                                                  request.headers.get("X-Forwarded-For", request.remote_addr)))
        except OSError:
            pass  # 历史记录写不了不影响出码
        return jsonify(ok=True, code=code, kind=kind, vin=bid)

    @app.get("/api/history")
    def history_view():
        if not history.exists():
            return Response("", mimetype="text/plain; charset=utf-8")
        lines = history.read_text(encoding="utf-8").splitlines()[-200:]
        return Response("\n".join(reversed(lines)), mimetype="text/plain; charset=utf-8")

    return app
