"""跨语言：把 APK 里的 ActivationCodec.java + Ed25519.java 原样编译，和 Python 实现互相校验。
需要 javac/java（PATH 或 JAVA_HOME）和 APK 源码目录（环境变量 ZFW_SRC，或默认 ../zFloatWindow/app/src/main/java/com/fff/zfloatwindow）。
找不到就跳过。"""
import os
import random
import shutil
import subprocess
import tempfile
import unittest

from fffactive import codec

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.environ.get("ZFW_SRC", os.path.join(os.path.dirname(os.path.dirname(HERE)), "zFloatWindow", "app", "src",
                                             "main", "java", "com", "fff", "zfloatwindow"))
FILES = [os.path.join(SRC, "ActivationCodec.java"), os.path.join(SRC, "Ed25519.java")]


def find(tool):
    jh = os.environ.get("JAVA_HOME")
    if jh and os.path.exists(os.path.join(jh, "bin", tool)):
        return os.path.join(jh, "bin", tool)
    return shutil.which(tool)


@unittest.skipUnless(find("javac") and all(os.path.exists(f) for f in FILES), "没有 javac 或找不到 APK 源码")
class CrossJavaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        subprocess.check_call([find("javac"), "-encoding", "UTF-8", "-d", cls.tmp, *FILES,
                               os.path.join(HERE, "java", "com", "fff", "zfloatwindow", "CrossCheck.java")])
        cls.java = find("java")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_java(self, *args):
        return subprocess.check_output([self.java, "-cp", self.tmp, "com.fff.zfloatwindow.CrossCheck", *args],
                                       text=True).strip()

    def test_vectors(self):
        self.assertIn("vectors OK", self.run_java("vectors", os.path.join(HERE, "vectors.tsv")))

    def test_rfc8032(self):
        self.assertIn("rfc8032 OK", self.run_java("rfc8032"))

    def test_python_ed_codes_verify_in_java(self):
        rnd = random.Random(7)
        alphabet = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
        seed = bytes(rnd.getrandbits(8) for _ in range(32))
        keys = codec.Keys(ed_seed=seed)
        pub = codec.ed_public_from_seed(seed).hex()
        for _ in range(12):
            vin = "".join(rnd.choice(alphabet) for _ in range(17))
            code = codec.generate(keys, vin, "ed")
            self.assertEqual(len(code), 86)
            self.assertEqual(self.run_java("verify", "ed", pub, vin, code), "OK")
            other = "".join(rnd.choice(alphabet) for _ in range(17))
            self.assertTrue(self.run_java("verify", "ed", pub, other, code).startswith("FAIL"))
            i = rnd.randrange(86)
            bad = code[:i] + ("A" if code[i] != "A" else "B") + code[i + 1:]
            self.assertTrue(self.run_java("verify", "ed", pub, vin, bad).startswith("FAIL"))
        # 别的私钥签的码必须被拒绝
        other_keys = codec.Keys(ed_seed=bytes(rnd.getrandbits(8) for _ in range(32)))
        forged = codec.generate(other_keys, "LSJA24U62JG269181", "ed")
        self.assertTrue(self.run_java("verify", "ed", pub, "LSJA24U62JG269181", forged).startswith("FAIL"))

    def test_ed_code_with_dash_and_underscore_kept(self):
        """真实 keygen 产出的、同时含 '-' 和 '_' 的 86 位码：APK 侧不能把它们当分隔符去掉；只去空白。"""
        seed = bytes(range(1, 33))
        keys = codec.Keys(ed_seed=seed)
        pub = codec.ed_public_from_seed(seed).hex()
        found = None
        for i in range(5000):
            vin = "LSJA24U62JG%06d" % i
            code = codec.generate(keys, vin, "ed")
            if "-" in code and "_" in code:
                found = (vin, code)
                break
        self.assertIsNotNone(found)
        vin, code = found
        self.assertEqual(self.run_java("verify", "ed", pub, vin, code), "OK")
        self.assertEqual(self.run_java("verify", "ed", pub, vin.lower(), code), "OK")   # VIN 大小写不敏感
        # 复制粘贴时被换行/空格拆开：去空白后仍有效
        self.assertEqual(self.run_java("verify", "ed", pub, vin, code[:30] + " " + code[30:60] + "\n" + code[60:]), "OK")
        # 去掉 '-' 或把 '_' 换掉就不是同一个码了（长度不对/校验失败）
        self.assertTrue(self.run_java("verify", "ed", pub, vin, code.replace("-", "")).startswith("FAIL"))
        self.assertTrue(self.run_java("verify", "ed", pub, vin, code.replace("_", "")).startswith("FAIL"))

    def test_python_mac_codes_verify_in_java(self):
        rnd = random.Random(8)
        alphabet = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
        sec_hex = "a1" * 32
        keys = codec.Keys(mac_secret=codec.parse_secret(sec_hex))
        for _ in range(12):
            vin = "".join(rnd.choice(alphabet) for _ in range(17))
            code = codec.generate(keys, vin, "mac")
            self.assertEqual(self.run_java("verify", "mac", sec_hex, vin, code), "OK")
            self.assertEqual(self.run_java("verify", "mac", sec_hex, vin, code.replace("-", "").lower()), "OK")
            other = "".join(rnd.choice(alphabet) for _ in range(17))
            self.assertTrue(self.run_java("verify", "mac", sec_hex, other, code).startswith("FAIL"))

    def test_java_mac_codes_verify_in_python(self):
        sec_hex = "b2" * 32
        keys = codec.Keys(mac_secret=codec.parse_secret(sec_hex))
        for vin in ["LSJA24U62JG269181", "LVVDB11B6CD123456", "MCABCDEFGH23456723"]:
            code = self.run_java("genmac", sec_hex, vin)
            self.assertEqual(code, codec.generate(keys, vin, "mac"))
            codec.verify(code, vin, mac_secret=keys.mac_secret)


if __name__ == "__main__":
    unittest.main()
