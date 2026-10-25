import base64
import json
import os
import stat
import tempfile
import unittest

from fffactive import codec
from fffactive.store import AppError, AppStore
from fffactive.web import create_app

PW = "test-password-123"
SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"   # RFC 8032 测试私钥（公开）
OTHER_SEED_HEX = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
PUB = codec.ed_public_from_seed(bytes.fromhex(SEED_HEX)).hex()
OTHER_PUB = codec.ed_public_from_seed(bytes.fromhex(OTHER_SEED_HEX)).hex()
VIN = "LSJA24U62JG269181"
HERE = os.path.dirname(os.path.abspath(__file__))


def hdr():
    h = {"Authorization": "Basic " + base64.b64encode(("admin:" + PW).encode()).decode(), "X-Requested-With": "fff"}
    return h


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.st = AppStore(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_generated_app_has_unique_key_and_protected_seed(self):
        a = self.st.add_generated("CarMediaBridge", "carmediabridge", 2)
        b = self.st.add_generated("Other", "other")
        self.assertNotEqual(a["ed_public"], b["ed_public"])
        self.assertEqual(a["product"], 2)
        self.assertEqual(b["product"], 1)                              # 默认产品号 = zFloatWindow 现用的 1
        seed = self.st._load_seed(a["id"])
        self.assertEqual(codec.ed_public_from_seed(seed).hex(), a["ed_public"])
        mode = stat.S_IMODE(os.stat(self.st._seed_path(a["id"])).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.st.seed_dir).st_mode), 0o700)
        # 种子绝不进入 apps.json
        self.assertNotIn(seed.hex(), (self.st.dir / "apps.json").read_text())
        self.assertIsNotNone(self.st.keys_for(a))

    def test_import_requires_matching_seed(self):
        a = self.st.add_imported("X", "xapp", 1, OTHER_PUB.upper(), OTHER_SEED_HEX)
        self.assertEqual(a["ed_public"], OTHER_PUB)                    # 规范化为小写
        with self.assertRaises(AppError) as cm:
            self.st.add_imported("Y", "yapp", 1, PUB, OTHER_SEED_HEX)  # 种子与公钥不是一对
        self.assertNotIn(OTHER_SEED_HEX, str(cm.exception))
        self.assertNotIn(PUB, str(cm.exception))
        self.assertEqual(len(self.st.list()), 1)                       # 失败不留痕
        self.assertEqual(os.listdir(self.st.seed_dir), ["%s.seed" % a["id"]])
        for bad_pub in ("", "xyz", "ab" * 31, "0" * 64):
            with self.assertRaises(AppError):
                self.st.add_imported("Z", "zapp", 1, bad_pub, SEED_HEX)
        for bad_seed in ("", "12", "zz" * 32):
            with self.assertRaises(AppError):
                self.st.add_imported("Z", "zapp", 1, PUB, bad_seed)

    def test_uniqueness(self):
        self.st.add_imported("A", "app-a", 1, PUB, SEED_HEX)
        with self.assertRaises(AppError):
            self.st.add_imported("B", "app-b", 1, PUB, SEED_HEX)       # 重复公钥
        with self.assertRaises(AppError):
            self.st.add_generated("C", "app-a")                         # 重复 slug
        with self.assertRaises(AppError):
            self.st.add_generated("a", "app-c")                         # 重复名称（不区分大小写）
        for bad in ("", "A", "-x", "a", "x" * 33, "a b", "中文"):
            with self.assertRaises(AppError):
                self.st.add_generated("N%s" % bad, bad)
        for bad in (0, 256, "x", -1):
            with self.assertRaises(AppError):
                self.st.add_generated("P", "papp", bad)
        self.assertEqual(len(self.st.list()), 1)
        self.assertEqual(self.st.add_generated("Upper", "UPPER-case")["slug"], "upper-case")   # slug 自动转小写

    def test_update_and_delete(self):
        a = self.st.add_generated("A", "app-a", 3)
        self.st.add_generated("B", "app-b")
        u = self.st.update("app-a", name="A2", new_slug="app-a2", product=5)
        self.assertEqual((u["name"], u["slug"], u["product"], u["ed_public"]), ("A2", "app-a2", 5, a["ed_public"]))
        with self.assertRaises(AppError):
            self.st.update("app-a2", new_slug="app-b")
        self.assertIsNotNone(self.st.keys_for(self.st.get("app-a2")))   # 改 slug 不丢私钥
        self.st.delete("app-a2")
        self.assertIsNone(self.st.get("app-a2"))
        self.assertFalse(self.st._seed_path(a["id"]).exists())          # 私钥随之删除
        with self.assertRaises(AppError):
            self.st.delete("app-a2")

    def test_seed_encryption_at_rest(self):
        st = AppStore(self.tmp.name + "/enc", store_key="correct horse")
        a = st.add_imported("A", "app-a", 1, PUB, SEED_HEX)
        raw = st._seed_path(a["id"]).read_text()
        self.assertTrue(raw.startswith("enc1:"))
        self.assertNotIn(SEED_HEX, raw)
        self.assertEqual(st._load_seed(a["id"]), bytes.fromhex(SEED_HEX))
        wrong = AppStore(self.tmp.name + "/enc", store_key="wrong")
        self.assertIsNone(wrong.keys_for(wrong.get("app-a")))          # 密钥不对 → 读不出，不崩溃
        nokey = AppStore(self.tmp.name + "/enc")
        self.assertIsNone(nokey.keys_for(nokey.get("app-a")))

    def test_env_migration_default_app(self):
        st = AppStore(self.tmp.name + "/m", env_seed=bytes.fromhex(SEED_HEX))
        apps = st.list()
        self.assertEqual(len(apps), 1)
        d = apps[0]
        self.assertEqual((d["name"], d["slug"], d["product"], d["ed_public"], d["source"]),
                         ("zFloatWindow", "zfloatwindow", 1, PUB, "env"))
        self.assertEqual(os.listdir(st.seed_dir), [])                   # 环境变量种子不落盘
        AppStore(self.tmp.name + "/m", env_seed=bytes.fromhex(SEED_HEX))  # 重启：不重复迁移
        self.assertEqual(len(st.list()), 1)
        with self.assertRaises(AppError):
            st.delete("zfloatwindow")                                   # 环境变量还在 → 不能删
        with self.assertRaises(AppError):
            st.update("zfloatwindow", product=2)                        # 产品号固定
        st.update("zfloatwindow", name="zFloat 悬浮窗")                  # 改名可以
        # 去掉环境变量后：记录还在但没有私钥，可以删除
        st2 = AppStore(self.tmp.name + "/m")
        self.assertFalse(st2.has_key(st2.get("zfloatwindow")))
        st2.delete("zfloatwindow")
        # 别的 APP 已经占了 slug/名称/同一公钥时的迁移
        st3 = AppStore(self.tmp.name + "/n")
        st3.add_generated("zFloatWindow", "zfloatwindow")
        st3 = AppStore(self.tmp.name + "/n", env_seed=bytes.fromhex(SEED_HEX))
        self.assertEqual([a["slug"] for a in st3.list()], ["zfloatwindow-env", "zfloatwindow"])


class WebAppsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app("", PW, self.tmp.name, SEED_HEX)
        self.c = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def post(self, url, body, method="post", headers=None):
        return getattr(self.c, method)(url, json=body, headers=headers or hdr())

    def test_apps_page_and_api_never_show_seed(self):
        r = self.post("/api/apps", {"mode": "generate", "name": "CarMediaBridge", "slug": "carmediabridge", "product": 2})
        self.assertEqual(r.status_code, 201)
        j = r.get_json()
        pub = j["app"]["ed_public"]
        self.assertTrue(j["generated"])
        self.assertEqual(len(pub), 64)
        seed = AppStore(self.tmp.name)._load_seed(j["app"]["id"]).hex()
        for url in ("/", "/apps", "/api/apps", "/api/history"):
            body = self.c.get(url, headers=hdr()).get_data(as_text=True)
            self.assertNotIn(seed, body)
            self.assertNotIn(SEED_HEX, body)
        self.assertNotIn(seed, r.get_data(as_text=True))
        page = self.c.get("/apps", headers=hdr()).get_data(as_text=True)
        self.assertIn(pub, page)                      # 公钥随时可见
        self.assertIn(PUB, page)                      # 默认 APP 的公钥也在
        self.assertIn("复制公钥", page)
        self.assertIn("自动生成密钥对", page)
        self.assertIn("手动输入公钥", page)
        self.assertIn('type="password"', page)        # 种子输入框是 password 类型

    def test_import_mode_and_rejections(self):
        ok = self.post("/api/apps", {"mode": "import", "name": "B", "slug": "bapp", "public_key": OTHER_PUB, "seed": OTHER_SEED_HEX})
        self.assertEqual(ok.status_code, 201)
        self.assertFalse(ok.get_json()["generated"])
        bad = self.post("/api/apps", {"mode": "import", "name": "C", "slug": "capp", "public_key": PUB.replace(PUB[0], "f", 1) if PUB[0] != "f" else "e" + PUB[1:], "seed": OTHER_SEED_HEX})
        self.assertEqual(bad.status_code, 400)
        self.assertNotIn(OTHER_SEED_HEX, bad.get_data(as_text=True))
        dup = self.post("/api/apps", {"mode": "import", "name": "D", "slug": "dapp", "public_key": OTHER_PUB, "seed": OTHER_SEED_HEX})
        self.assertEqual(dup.status_code, 400)
        self.assertIn("唯一", dup.get_json()["error"])
        self.assertEqual(self.post("/api/apps", {"mode": "weird", "name": "E", "slug": "eapp"}).status_code, 400)

    def test_csrf_and_auth(self):
        body = {"mode": "generate", "name": "X", "slug": "xapp"}
        noh = {k: v for k, v in hdr().items() if k != "X-Requested-With"}
        self.assertEqual(self.post("/api/apps", body, headers=noh).status_code, 400)
        self.assertEqual(self.post("/api/apps", body, headers={"X-Requested-With": "fff"}).status_code, 401)
        self.assertEqual(self.c.get("/apps").status_code, 401)
        self.assertEqual(self.c.get("/api/apps").status_code, 401)
        self.assertEqual(self.post("/api/apps/zfloatwindow", {"name": "n"}, method="put", headers=noh).status_code, 400)
        self.assertEqual(self.c.delete("/api/apps/zfloatwindow", headers=noh).status_code, 400)

    def test_edit_delete(self):
        self.post("/api/apps", {"mode": "generate", "name": "A", "slug": "app-a"})
        r = self.post("/api/apps/app-a", {"name": "A2", "slug": "app-a2", "product": 7}, method="put")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["app"]["product"], 7)
        self.assertEqual(self.c.delete("/api/apps/app-a2", headers=hdr()).status_code, 200)
        self.assertEqual(self.c.delete("/api/apps/app-a2", headers=hdr()).status_code, 400)
        self.assertEqual(self.c.delete("/api/apps/zfloatwindow", headers=hdr()).status_code, 400)   # 环境变量默认 APP

    def test_generate_per_app_and_history_records_app_name(self):
        a = self.post("/api/apps", {"mode": "generate", "name": "CarMediaBridge", "slug": "carmediabridge", "product": 2}).get_json()["app"]
        g = self.post("/api/generate", {"app": "carmediabridge", "vin": VIN}).get_json()
        self.assertTrue(g["ok"])
        self.assertEqual((g["app"], g["app_name"], g["product"], g["length"]), ("carmediabridge", "CarMediaBridge", 2, 86))
        pub = bytes.fromhex(a["ed_public"])
        codec.verify(g["code"], VIN, ed_public=pub, product=2)           # 该 APP 的公钥 + 产品号 2 验过
        with self.assertRaises(codec.CodecError):
            codec.verify(g["code"], VIN, ed_public=pub, product=1)       # 产品号不对
        with self.assertRaises(codec.CodecError):
            codec.verify(g["code"], VIN, ed_public=bytes.fromhex(PUB), product=2)   # 不是默认 APP 的码
        d = self.post("/api/generate", {"app": "zfloatwindow", "vin": VIN}).get_json()
        self.assertNotEqual(d["code"], g["code"])
        codec.verify(d["code"], VIN, ed_public=bytes.fromhex(PUB), product=1)
        hist = self.c.get("/api/history", headers=hdr()).get_data(as_text=True)
        self.assertIn("CarMediaBridge", hist)
        self.assertIn("zFloatWindow", hist)
        self.assertEqual(self.post("/api/generate", {"app": "nope", "vin": VIN}).status_code, 400)
        self.assertEqual(self.post("/api/generate", {"app": "carmediabridge", "vin": VIN, "mode": "mac"}).status_code, 400)

    def test_default_app_codes_unchanged_and_match_zfloatwindow_format(self):
        """默认 APP（来自 FFF_ACTIVE_ED_SEED）出的码必须与改动前逐字符一致，并符合 zFloatWindow 验证的消息格式。"""
        with open(os.path.join(HERE, "vectors.tsv"), encoding="utf-8") as f:
            vecs = [l.split("\t") for l in f.read().splitlines() if l and not l.startswith("#") and l.startswith("ed\t")]
        self.assertGreaterEqual(len(vecs), 4)
        for _, _pub, bid, product, code in vecs:                         # vectors.tsv 是改动前提交的，用同一个测试种子
            for body in ({"vin": bid}, {"app": "zfloatwindow", "vin": bid}):   # 不带 app 的旧请求 = 默认 APP
                g = self.post("/api/generate", body).get_json()
                self.assertEqual(g["code"], code)
                self.assertEqual(g["product"], 1)
        self.assertEqual(codec._ed_msg(VIN, 1), b"fff-active/v2/ed|\x01" + VIN.encode())   # zFloatWindow ActivationCodec.edMsg 的格式

    def test_two_workers_share_the_volume(self):
        """gunicorn 多 worker：另一个进程新增的 APP，这个进程马上能用。"""
        other = create_app("", PW, self.tmp.name, SEED_HEX).test_client()
        r = other.post("/api/apps", json={"mode": "generate", "name": "W", "slug": "wapp"}, headers=hdr())
        self.assertEqual(r.status_code, 201)
        self.assertTrue(self.post("/api/generate", {"app": "wapp", "vin": VIN}).get_json()["ok"])

    def test_cli(self):
        import contextlib
        import io
        from fffactive import cli
        env = {"DATA_DIR": self.tmp.name, "FFF_ACTIVE_ED_SEED": SEED_HEX}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            self.post("/api/apps", {"mode": "import", "name": "B", "slug": "bapp", "product": 2, "public_key": OTHER_PUB, "seed": OTHER_SEED_HEX})
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["--app", "bapp", VIN]), 0)
            codec.verify(out.getvalue().strip(), VIN, ed_public=bytes.fromhex(OTHER_PUB), product=2)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["--app", "bapp", "--pubkey"]), 0)
                self.assertEqual(cli.main(["--pubkey"]), 0)
            self.assertEqual(out.getvalue().split(), [OTHER_PUB, PUB])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["--list"]), 0)
            self.assertIn("bapp", out.getvalue())
            self.assertNotIn(OTHER_SEED_HEX, out.getvalue())
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
