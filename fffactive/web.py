"""激活码生成网页（Flask）：多 APP。

  /            选择 APP → 输入 VIN → 生成激活码
  /apps        APP 管理：增加 / 编辑 / 删除（名称 + 唯一 slug + 唯一 Ed25519 公钥 + 产品号）

需要环境变量 ADMIN_PASSWORD。FFF_ACTIVE_ED_SEED（可选）会被自动迁移成默认 APP “zFloatWindow”（产品号 1，码与以前完全一致）；
FFF_ACTIVE_SECRET（可选）只给这个默认 APP 提供紧凑码。其他 APP 都在 /apps 页面里添加，私钥种子存放见 store.py。
"""
import hmac
import os
import time
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from . import codec
from .store import AppError, AppStore, public_view


def _clean(v: str) -> str:
    """去掉首尾空白和成对引号（NAS 界面里常见的粘贴误差）。"""
    v = (v or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    return v


def create_app(secret_hex: str = None, admin_password: str = None, data_dir: str = None,
               ed_seed_hex: str = None, store_key: str = None) -> Flask:
    secret_hex = secret_hex if secret_hex is not None else os.environ.get("FFF_ACTIVE_SECRET", "")
    ed_seed_hex = ed_seed_hex if ed_seed_hex is not None else os.environ.get("FFF_ACTIVE_ED_SEED", "")
    admin_password = admin_password if admin_password is not None else os.environ.get("ADMIN_PASSWORD", "")
    store_key = store_key if store_key is not None else os.environ.get("FFF_ACTIVE_STORE_KEY", "")
    data_dir = Path(data_dir or os.environ.get("DATA_DIR", "data"))
    admin_user = os.environ.get("ADMIN_USER", "admin")
    # 密钥配置有问题时不让进程崩溃（NAS 图形界面看不到日志），而是照常起来，在页面上显示错误横幅。
    # 横幅里只写“哪个变量、出了什么问题”，绝不包含变量的值。
    banners = []
    ed_seed = mac_secret = None
    ed_seed_hex = _clean(ed_seed_hex)
    secret_hex = _clean(secret_hex)
    if ed_seed_hex:
        try:
            ed_seed = codec.parse_ed_seed(ed_seed_hex)
        except codec.CodecError:
            banners.append("FFF_ACTIVE_ED_SEED 格式不对：必须正好是 64 位十六进制字符（0-9、a-f，共 32 字节），"
                           "且不要带引号、空格或换行。请修正环境变量后重启容器（默认 APP zFloatWindow 暂时不可用；其他 APP 不受影响）。")
    if secret_hex:
        try:
            mac_secret = codec.parse_secret(secret_hex)
        except codec.CodecError:
            banners.append("FFF_ACTIVE_SECRET 格式不对：必须正好是 64 位十六进制字符；不需要紧凑码的话请把它留空。紧凑码已被禁用。")
    if len(admin_password) < 8 or admin_password in ("change-me", "changeme", "password"):
        raise RuntimeError("ADMIN_PASSWORD 未设置或太弱（至少 8 位，且不能用示例值）")
    data_dir.mkdir(parents=True, exist_ok=True)
    history = data_dir / "history.log"
    store = AppStore(data_dir, ed_seed, mac_secret, store_key)

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

    def csrf_ok() -> bool:
        # 自定义请求头：跨站表单提交带不上，用来挡 CSRF（浏览器会自动带 Basic 凭据）
        return request.headers.get("X-Requested-With") == "fff"

    def views():
        return [public_view(store, a) for a in store.list()]

    @app.get("/healthz")
    def healthz():
        return "ok"

    @app.get("/")
    def index():
        vs = views()
        return render_template("index.html", apps=vs, banners=banners, any_mac=any("mac" in a["modes"] for a in vs))

    @app.get("/apps")
    def apps_page():
        return render_template("apps.html", apps=views(), banners=banners)

    # ---------------------------------------------------------------- APP 管理 API
    @app.get("/api/apps")
    def api_apps():
        return jsonify(ok=True, apps=views())

    @app.post("/api/apps")
    def api_add_app():
        if not csrf_ok():
            return jsonify(ok=False, error="非法请求"), 400
        b = request.get_json(silent=True) or {}
        mode = str(b.get("mode") or "generate")
        try:
            if mode == "generate":
                rec = store.add_generated(b.get("name"), b.get("slug"), b.get("product", 1))
            elif mode == "import":
                rec = store.add_imported(b.get("name"), b.get("slug"), b.get("product", 1),
                                         b.get("public_key"), b.get("seed"))
            else:
                raise AppError("未知的添加方式")
        except AppError as e:
            return jsonify(ok=False, error=str(e)), 400
        return jsonify(ok=True, app=public_view(store, rec), generated=(mode == "generate")), 201

    @app.put("/api/apps/<slug>")
    def api_update_app(slug):
        if not csrf_ok():
            return jsonify(ok=False, error="非法请求"), 400
        b = request.get_json(silent=True) or {}
        try:
            rec = store.update(slug, name=b.get("name"), new_slug=b.get("slug"), product=b.get("product"))
        except AppError as e:
            return jsonify(ok=False, error=str(e)), 400
        return jsonify(ok=True, app=public_view(store, rec))

    @app.delete("/api/apps/<slug>")
    def api_delete_app(slug):
        if not csrf_ok():
            return jsonify(ok=False, error="非法请求"), 400
        try:
            store.delete(slug)
        except AppError as e:
            return jsonify(ok=False, error=str(e)), 400
        return jsonify(ok=True)

    # ---------------------------------------------------------------- 出码
    @app.post("/api/generate")
    def generate():
        if not csrf_ok():
            return jsonify(ok=False, error="非法请求"), 400
        body = request.get_json(silent=True) or {}
        apps = store.list()
        if not apps:
            return jsonify(ok=False, error="还没有 APP：请先到“APP 管理”添加一个（或设置 FFF_ACTIVE_ED_SEED 使用默认 APP）"), 400
        slug = str(body.get("app") or "").strip().lower()
        rec = store.get(slug) if slug else apps[0]            # 不带 app 的旧请求 → 第一个（默认）APP
        if rec is None:
            return jsonify(ok=False, error="APP 不存在"), 400
        keys = store.keys_for(rec)
        if keys is None:
            return jsonify(ok=False, error="APP “%s”没有可用的私钥（默认 APP 需要环境变量 FFF_ACTIVE_ED_SEED）" % rec["name"]), 503
        modes = keys.modes()
        bid = codec.normalize_bid(str(body.get("vin", "")))
        mode = str(body.get("mode") or modes[0])
        try:
            if mode not in modes:
                raise codec.CodecError("该模式未启用（这个 APP 没有对应密钥）")
            kind = codec.validate_bid(bid)
            code = codec.generate(keys, bid, mode, product=rec["product"])
        except codec.CodecError as e:
            return jsonify(ok=False, error=str(e)), 400
        try:
            with history.open("a", encoding="utf-8") as f:
                f.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
                    time.strftime("%Y-%m-%d %H:%M:%S"), rec["name"], rec["slug"], mode, kind, bid, code,
                    request.headers.get("X-Forwarded-For", request.remote_addr)))
        except OSError:
            pass  # 历史记录写不了不影响出码
        return jsonify(ok=True, code=code, kind=kind, vin=bid, mode=mode, length=len(code),
                       app=rec["slug"], app_name=rec["name"], product=rec["product"])

    @app.get("/api/history")
    def history_view():
        if not history.exists():
            return Response("", mimetype="text/plain; charset=utf-8")
        lines = history.read_text(encoding="utf-8").splitlines()[-200:]
        head = "时间\tAPP\tslug\t模式\t类型\tVIN/机器码\t激活码\tIP"
        return Response(head + "\n" + "\n".join(reversed(lines)), mimetype="text/plain; charset=utf-8")

    return app
