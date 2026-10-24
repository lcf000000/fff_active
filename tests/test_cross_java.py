"""跨语言：把 APK 里的 ActivationCodec.java 原样编译，和 Python 实现互相校验。
需要 javac/java（PATH 或 JAVA_HOME）和 ActivationCodec.java（环境变量 ZFW_CODEC，或默认 ../zFloatWindow/...）。
找不到就跳过。"""
import os
import random
import shutil
import subprocess
import tempfile
import unittest

from fffactive import codec

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(os.path.dirname(os.path.dirname(HERE)), "zFloatWindow", "app", "src", "main", "java",
                       "com", "fff", "zfloatwindow", "ActivationCodec.java")
CODEC_JAVA = os.environ.get("ZFW_CODEC", DEFAULT)


def find(tool):
    jh = os.environ.get("JAVA_HOME")
    if jh and os.path.exists(os.path.join(jh, "bin", tool)):
        return os.path.join(jh, "bin", tool)
    return shutil.which(tool)


@unittest.skipUnless(find("javac") and os.path.exists(CODEC_JAVA), "没有 javac 或找不到 ActivationCodec.java")
class CrossJavaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        subprocess.check_call([find("javac"), "-encoding", "UTF-8", "-d", cls.tmp, CODEC_JAVA,
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

    def test_python_codes_verify_in_java(self):
        rnd = random.Random(7)
        alphabet = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
        sec_hex = "a1" * 32
        sec = codec.parse_secret(sec_hex)
        for _ in range(25):
            vin = "".join(rnd.choice(alphabet) for _ in range(17))
            code = codec.generate(sec, vin)
            self.assertEqual(self.run_java("verify", sec_hex, vin, code), "OK")
            other = "".join(rnd.choice(alphabet) for _ in range(17))
            self.assertTrue(self.run_java("verify", sec_hex, other, code).startswith("FAIL"))
            bad = code[:10] + ("A" if code[10] != "A" else "B") + code[11:]
            self.assertTrue(self.run_java("verify", sec_hex, vin, bad).startswith("FAIL"))

    def test_java_codes_verify_in_python(self):
        sec_hex = "b2" * 32
        sec = codec.parse_secret(sec_hex)
        for vin in ["LSJA24U62JG269181", "LVVDB11B6CD123456", "MCABCDEFGH23456723"]:
            code = self.run_java("gen", sec_hex, vin)
            codec.verify(sec, code, vin)
            with self.assertRaises(codec.CodecError):
                codec.verify(sec, code, "LSJA24U62JG269999")


if __name__ == "__main__":
    unittest.main()
