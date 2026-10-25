"""多 APP 存储：每个 APP = 名称 + 唯一 slug + 唯一 Ed25519 公钥 + 产品号，私钥种子保存在服务端数据卷。

私钥怎么来（为什么界面要求“私钥种子”）
  Ed25519 的私钥种子**不能**从公钥推出来；只有公钥是生成不了激活码的。所以一个 APP 要能出码，服务器必须持有它的种子。两种途径：
  (1) 自动生成密钥对：服务器自己生成种子并保存，页面只显示公钥（给 APK 构建用），种子**永远不再显示**；
  (2) 手动输入：用户一次性提交“公钥 + 对应的私钥种子”，服务器核对“种子推出的公钥 == 填的公钥”才保存，之后同样不再显示。
  环境变量 FFF_ACTIVE_ED_SEED 对应的“默认 APP”（zFloatWindow）不落盘：种子始终从环境变量读取。

种子怎么存
  DATA_DIR/seeds/<id>.seed，文件权限 0600，目录 0700；设置了 FFF_ACTIVE_STORE_KEY 时额外用 AES-256-GCM 加密
  （key = SHA256("fff-active/store/v1|" + FFF_ACTIVE_STORE_KEY)），这样数据卷被拷走也读不出种子。公开信息在 DATA_DIR/apps.json。
  多个 gunicorn worker 共享同一数据卷：每次请求重新读 apps.json，写入用文件锁 + 原子替换。
"""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import codec

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,31}$")
DEFAULT_SLUG = "zfloatwindow"
DEFAULT_NAME = "zFloatWindow"
SRC_ENV = "env"
SRC_GENERATED = "generated"
SRC_IMPORTED = "imported"
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class AppError(ValueError):
    """用户可见的校验错误（中文）。"""


def _clean_text(s: str, what: str, maxlen: int) -> str:
    s = re.sub(r"\s+", " ", (s or "")).strip()
    if not s:
        raise AppError("%s不能为空" % what)
    if len(s) > maxlen:
        raise AppError("%s最长 %d 个字符" % (what, maxlen))
    if any(ord(c) < 32 for c in s):
        raise AppError("%s含有非法字符" % what)
    return s


def check_slug(slug: str) -> str:
    slug = (slug or "").strip().lower()
    if not SLUG_RE.match(slug):
        raise AppError("标识（slug）只能用小写字母、数字和连字符，2–32 位，且以字母或数字开头")
    return slug


def check_product(v) -> int:
    try:
        n = int(str(v).strip()) if str(v).strip() != "" else codec.PRODUCT_ZFLOAT
    except ValueError as e:
        raise AppError("产品号必须是 1–255 的整数") from e
    if not 1 <= n <= 255:
        raise AppError("产品号必须是 1–255 的整数")
    return n


def check_public_hex(h: str) -> str:
    h = (h or "").strip().strip("\"'").strip()
    if not HEX64.match(h):
        raise AppError("公钥必须是 64 位十六进制（32 字节 Ed25519 公钥）")
    h = h.lower()
    if set(h) == {"0"}:
        raise AppError("全零不是有效公钥（那是 APK 构建的占位值）")
    return h


class AppStore:
    def __init__(self, data_dir, env_seed: bytes = None, env_mac_secret: bytes = None, store_key: str = ""):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.seed_dir = self.dir / "seeds"
        self.seed_dir.mkdir(exist_ok=True)
        try:
            os.chmod(self.seed_dir, 0o700)
        except OSError:
            pass
        self.file = self.dir / "apps.json"
        self.lock_file = self.dir / ".apps.lock"
        self.env_seed = env_seed
        self.env_pub_hex = codec.ed_public_from_seed(env_seed).hex() if env_seed else ""
        self.env_mac_secret = env_mac_secret
        self._aes = AESGCM(hashlib.sha256(b"fff-active/store/v1|" + store_key.encode()).digest()) if store_key else None
        self._migrate_env()

    # ------------------------------------------------------------ 文件层
    @contextlib.contextmanager
    def _locked(self):
        with open(self.lock_file, "a+") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

    def _read(self) -> list:
        try:
            return json.loads(self.file.read_text(encoding="utf-8")).get("apps", [])
        except FileNotFoundError:
            return []
        except (ValueError, OSError):
            raise RuntimeError("apps.json 损坏，请检查数据卷（不会自动覆盖）")

    def _write(self, apps: list) -> None:
        fd, tmp = tempfile.mkstemp(dir=str(self.dir), prefix=".apps.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "apps": apps}, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.file)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _seed_path(self, app_id: str) -> Path:
        return self.seed_dir / ("%s.seed" % app_id)

    def _save_seed(self, app_id: str, seed: bytes) -> None:
        if self._aes:
            nonce = secrets.token_bytes(12)
            data = "enc1:" + base64.b64encode(nonce + self._aes.encrypt(nonce, seed, app_id.encode())).decode()
        else:
            data = "hex:" + seed.hex()
        p = self._seed_path(app_id)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(data + "\n")
        os.chmod(p, 0o600)

    def _load_seed(self, app_id: str):
        try:
            data = self._seed_path(app_id).read_text().strip()
        except OSError:
            return None
        try:
            if data.startswith("enc1:"):
                if not self._aes:
                    return None
                raw = base64.b64decode(data[5:])
                return self._aes.decrypt(raw[:12], raw[12:], app_id.encode())
            if data.startswith("hex:"):
                return bytes.fromhex(data[4:])
        except Exception:
            return None
        return None

    # ------------------------------------------------------------ 迁移
    def _migrate_env(self) -> None:
        """环境变量 FFF_ACTIVE_ED_SEED → 默认 APP（zFloatWindow，产品号 1，码与以前完全一致）。种子不落盘。"""
        if not self.env_seed:
            return
        with self._locked():
            apps = self._read()
            if any(a["ed_public"] == self.env_pub_hex for a in apps):
                return
            slug = DEFAULT_SLUG
            if any(a["slug"] == slug for a in apps):
                slug = "%s-env" % DEFAULT_SLUG
            name = DEFAULT_NAME
            if any(a["name"].lower() == name.lower() for a in apps):
                name = "%s (env)" % DEFAULT_NAME
            apps.insert(0, {"id": "env-" + self.env_pub_hex[:8], "name": name, "slug": slug, "product": codec.PRODUCT_ZFLOAT,
                            "ed_public": self.env_pub_hex, "source": SRC_ENV,
                            "created": time.strftime("%Y-%m-%d %H:%M:%S")})
            self._write(apps)

    # ------------------------------------------------------------ 查询
    def list(self) -> list:
        return self._read()

    def get(self, slug: str):
        slug = (slug or "").strip().lower()
        for a in self._read():
            if a["slug"] == slug:
                return a
        return None

    def keys_for(self, app: dict):
        """该 APP 的生成端密钥；缺少私钥时返回 None。"""
        seed = None
        if app["source"] == SRC_ENV:
            if self.env_seed and self.env_pub_hex == app["ed_public"]:
                seed = self.env_seed
        else:
            seed = self._load_seed(app["id"])
        if seed is None:
            return None
        if codec.ed_public_from_seed(seed).hex() != app["ed_public"]:
            return None
        mac = self.env_mac_secret if app["source"] == SRC_ENV else None
        return codec.Keys(ed_seed=seed, mac_secret=mac)

    def has_key(self, app: dict) -> bool:
        return self.keys_for(app) is not None

    def modes(self, app: dict) -> list:
        k = self.keys_for(app)
        return k.modes() if k else []

    # ------------------------------------------------------------ 修改
    def _check_unique(self, apps, name, slug, pub, skip_id=None):
        for a in apps:
            if a["id"] == skip_id:
                continue
            if a["slug"] == slug:
                raise AppError("标识（slug）“%s”已被 APP “%s”使用" % (slug, a["name"]))
            if a["name"].lower() == name.lower():
                raise AppError("名称“%s”已存在" % name)
            if pub and a["ed_public"] == pub:
                raise AppError("这个公钥已属于 APP “%s”：每个 APP 必须使用唯一的公钥" % a["name"])

    def add_generated(self, name: str, slug: str, product=1) -> dict:
        name = _clean_text(name, "名称", 40)
        slug = check_slug(slug)
        product = check_product(product)
        seed = secrets.token_bytes(32)
        pub = codec.ed_public_from_seed(seed).hex()
        return self._add(name, slug, product, pub, seed, SRC_GENERATED)

    def add_imported(self, name: str, slug: str, product, public_hex: str, seed_hex: str) -> dict:
        name = _clean_text(name, "名称", 40)
        slug = check_slug(slug)
        product = check_product(product)
        pub = check_public_hex(public_hex)
        s = (seed_hex or "").strip().strip("\"'").strip()
        if not HEX64.match(s):
            raise AppError("私钥种子必须是 64 位十六进制（32 字节）")
        seed = bytes.fromhex(s)
        if codec.ed_public_from_seed(seed).hex() != pub:
            # 不透露任何一方的值
            raise AppError("这个私钥种子推不出你填的公钥，两者不是一对。请确认公钥与种子来自同一个密钥对")
        return self._add(name, slug, product, pub, seed, SRC_IMPORTED)

    def _add(self, name, slug, product, pub, seed, source) -> dict:
        with self._locked():
            apps = self._read()
            self._check_unique(apps, name, slug, pub)
            rec = {"id": secrets.token_hex(4), "name": name, "slug": slug, "product": product,
                   "ed_public": pub, "source": source, "created": time.strftime("%Y-%m-%d %H:%M:%S")}
            self._save_seed(rec["id"], seed)
            apps.append(rec)
            self._write(apps)
            return rec

    def update(self, slug: str, name=None, new_slug=None, product=None) -> dict:
        with self._locked():
            apps = self._read()
            cur = next((a for a in apps if a["slug"] == (slug or "").lower()), None)
            if cur is None:
                raise AppError("APP 不存在")
            n = _clean_text(name, "名称", 40) if name is not None else cur["name"]
            s = check_slug(new_slug) if new_slug is not None else cur["slug"]
            p = check_product(product) if product is not None else cur["product"]
            if cur["source"] == SRC_ENV and p != cur["product"]:
                raise AppError("默认 APP 的产品号固定为 %d（它的码必须与已发布的 zFloatWindow 完全一致）" % cur["product"])
            self._check_unique(apps, n, s, None, skip_id=cur["id"])
            cur.update(name=n, slug=s, product=p)
            self._write(apps)
            return dict(cur)

    def delete(self, slug: str) -> None:
        with self._locked():
            apps = self._read()
            cur = next((a for a in apps if a["slug"] == (slug or "").lower()), None)
            if cur is None:
                raise AppError("APP 不存在")
            if cur["source"] == SRC_ENV and self.env_seed and self.env_pub_hex == cur["ed_public"]:
                raise AppError("这个 APP 的私钥来自环境变量 FFF_ACTIVE_ED_SEED：先在容器里删除该变量并重启，再删除它")
            apps = [a for a in apps if a["id"] != cur["id"]]
            self._write(apps)
            try:
                self._seed_path(cur["id"]).unlink()
            except OSError:
                pass


def public_view(store: AppStore, a: dict) -> dict:
    """给页面/API 的视图：只有公开信息 + 是否持有私钥。绝不含种子。"""
    return {"id": a["id"], "name": a["name"], "slug": a["slug"], "product": a["product"],
            "ed_public": a["ed_public"], "source": a["source"], "created": a.get("created", ""),
            "has_key": store.has_key(a), "modes": store.modes(a)}
