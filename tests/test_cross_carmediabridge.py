"""CarMediaBridge 验签代码（ActivationCodec.java + Ed25519.java，原样编译）↔ 本生成器，双向对拍（产品号 2，抛弃型测试密钥）。

方向 1：生成器（经网页 API，APP 条目 = CarMediaBridge）出的码 → APK 侧验签通过；换 VIN / 换产品号 / 篡改 / 别的密钥必须失败。
方向 2：APK 侧（JDK Ed25519 + APK 的 edMsg）签出的码 → Python codec.verify 通过。
另有 tests/vectors_carmediabridge.tsv（公开测试密钥）的静态向量。
APK 源码目录：环境变量 CMB_SRC，或默认 ../CarMediaBridge/CarMediaBridge/app/src/main/java/com/carmediabridge/license；
找不到就用 tests/java/vendor 里的拷贝（并在两者都存在时断言它们逐字节相同，防止漂移）。需要 javac/java。"""
import base64
import filecmp
import os
import random
import shutil
import subprocess
import tempfile
import unittest

from fffactive import codec
from fffactive.web import create_app

HERE = os.path.dirname(os.path.abspath(__file__))
LIVE = os.environ.get("CMB_SRC", os.path.join(os.path.dirname(os.path.dirname(HERE)), "CarMediaBridge", "CarMediaBridge",
                                              "app", "src", "main", "java", "com", "carmediabridge", "license"))
VENDOR = os.path.join(HERE, "java", "vendor")
NAMES = ["ActivationCodec.java", "Ed25519.java"]
PW = "test-password-123"
VIN = "LSJA24U62JG269181"


def find(tool):
    jh = os.environ.get("JAVA_HOME")
    if jh and os.path.exists(os.path.join(jh, "bin", tool)):
        return os.path.join(jh, "bin", tool)
    return shutil.which(tool)


def hdr():
    return {"Authorization": "Basic " + base64.b64encode(("admin:" + PW).encode()).decode(), "X-Requested-With": "fff"}


@unittest.skipUnless(find("javac"), "没有 javac")
class CrossCarMediaBridgeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = LIVE if all(os.path.exists(os.path.join(LIVE, n)) for n in NAMES) else VENDOR
        cls.src = src
        cls.tmp = tempfile.mkdtemp()
        subprocess.check_call([find("javac"), "-encoding", "UTF-8", "-d", cls.tmp, *[os.path.join(src, n) for n in NAMES],
                               os.path.join(HERE, "java", "com", "carmediabridge", "license", "CrossCheckCmb.java")])
        cls.java = find("java")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_java(self, *args):
        return subprocess.check_output([self.java, "-cp", self.tmp, "com.carmediabridge.license.CrossCheckCmb", *args], text=True).strip()

    def test_vendored_copy_matches_live_source(self):
        if not all(os.path.exists(os.path.join(LIVE, n)) for n in NAMES):
            self.skipTest("没有 CarMediaBridge 源码，只用 vendor 拷贝")
        for n in NAMES:
            self.assertTrue(filecmp.cmp(os.path.join(LIVE, n), os.path.join(VENDOR, n), shallow=False),
                            "tests/java/vendor/%s 与 CarMediaBridge 源码不一致，请重新拷贝" % n)

    def test_static_vectors(self):
        self.assertIn("vectors OK 4", self.run_java("vectors", os.path.join(HERE, "vectors_carmediabridge.tsv")))

    def test_generator_to_apk_via_web_app_entry(self):
        with tempfile.TemporaryDirectory() as d:
            c = create_app("", PW, d, "").test_client()
            seed = bytes(random.Random(42).getrandbits(8) for _ in range(32))           # 抛弃型测试密钥
            pub = codec.ed_public_from_seed(seed).hex()
            r = c.post("/api/apps", json={"mode": "import", "name": "CarMediaBridge", "slug": "carmediabridge", "product": 2,
                                          "public_key": pub, "seed": seed.hex()}, headers=hdr())
            self.assertEqual(r.status_code, 201)
            rnd = random.Random(1)
            alphabet = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
            for _ in range(6):
                vin = "".join(rnd.choice(alphabet) for _ in range(17))
                code = c.post("/api/generate", json={"app": "carmediabridge", "vin": vin}, headers=hdr()).get_json()["code"]
                self.assertEqual(self.run_java("verify", pub, vin, code), "OK")
                self.assertEqual(self.run_java("verify", pub, vin.lower(), code[:40] + " " + code[40:]), "OK")
                other = "".join(rnd.choice(alphabet) for _ in range(17))
                self.assertTrue(self.run_java("verify", pub, other, code).startswith("FAIL"))          # 换 VIN
                self.assertTrue(self.run_java("verify", pub, vin, code, "1").startswith("FAIL"))       # APK 期望产品号 1（别的 APP）
                i = rnd.randrange(86)
                bad = code[:i] + ("A" if code[i] != "A" else "B") + code[i + 1:]
                self.assertTrue(self.run_java("verify", pub, vin, bad).startswith("FAIL"))             # 篡改
                self.assertTrue(self.run_java("verify", pub, vin, code.lower()).startswith("FAIL"))    # 区分大小写
            # 生成端若用错产品号（默认 1）出的码，CarMediaBridge（产品号 2）必须拒绝
            wrong = codec.generate(codec.Keys(ed_seed=seed), VIN, "ed", product=1)
            self.assertTrue(self.run_java("verify", pub, VIN, wrong).startswith("FAIL"))
            # 默认 APP（zFloatWindow，别的公钥）的码在 CarMediaBridge 里无效
            zc = codec.generate(codec.Keys(ed_seed=bytes(range(32))), VIN, "ed", product=2)
            self.assertTrue(self.run_java("verify", pub, VIN, zc).startswith("FAIL"))

    def test_generated_keypair_mode_to_apk(self):
        """“自动生成密钥对”：公钥给 APK 构建，服务器用保存的种子出码，APK 侧验过。"""
        with tempfile.TemporaryDirectory() as d:
            c = create_app("", PW, d, "").test_client()
            j = c.post("/api/apps", json={"mode": "generate", "name": "CarMediaBridge", "slug": "carmediabridge", "product": 2},
                       headers=hdr()).get_json()
            pub = j["app"]["ed_public"]
            code = c.post("/api/generate", json={"app": "carmediabridge", "vin": VIN}, headers=hdr()).get_json()["code"]
            self.assertEqual(self.run_java("verify", pub, VIN, code), "OK")

    def test_apk_signed_codes_verify_in_python(self):
        rnd = random.Random(5)
        seed = bytes(rnd.getrandbits(8) for _ in range(32))
        pub = codec.ed_public_from_seed(seed)
        alphabet = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
        for vin in ["".join(rnd.choice(alphabet) for _ in range(17)) for _ in range(6)] + ["MCABCDEFGH23456723"]:
            code = self.run_java("sign", seed.hex(), vin)
            self.assertEqual(codec.verify(code, vin, ed_public=pub, product=2), "ed")
            self.assertEqual(code, codec.generate(codec.Keys(ed_seed=seed), vin, "ed", product=2))   # Ed25519 确定性：两边逐字符相同
            with self.assertRaises(codec.CodecError):
                codec.verify(code, vin, ed_public=pub, product=1)


if __name__ == "__main__":
    unittest.main()
