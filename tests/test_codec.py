import os
import unittest

from fffactive import codec

HERE = os.path.dirname(os.path.abspath(__file__))
SECRET = codec.parse_secret("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
OTHER = codec.parse_secret("ff" * 32)
VIN = "LSJA24U62JG269181"


class CodecTest(unittest.TestCase):
    def test_roundtrip_and_format(self):
        code = codec.generate(SECRET, VIN)
        groups = code.split("-")
        self.assertEqual(len(groups), 17)
        self.assertTrue(all(len(g) == 5 for g in groups))
        self.assertRegex(code, r"^[A-Z2-7\-]+$")
        r = codec.verify(SECRET, code, VIN)
        self.assertEqual(r["product"], codec.PRODUCT_ZFLOAT)

    def test_lenient_input(self):
        code = codec.generate(SECRET, VIN)
        messy = " " + code.lower().replace("-", " ") + "\n"
        codec.verify(SECRET, messy, VIN.lower())

    def test_wrong_vin(self):
        code = codec.generate(SECRET, VIN)
        with self.assertRaises(codec.CodecError):
            codec.verify(SECRET, code, "LSJA24U62JG269182")

    def test_wrong_secret(self):
        code = codec.generate(SECRET, VIN)
        with self.assertRaises(codec.CodecError):
            codec.verify(OTHER, code, VIN)

    def test_tamper_every_char(self):
        code = codec.generate(SECRET, VIN).replace("-", "")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        bad = 0
        for i in range(len(code)):
            c = alphabet[(alphabet.index(code[i]) + 1) % 32]
            t = code[:i] + c + code[i + 1:]
            try:
                codec.verify(SECRET, t, VIN)
            except codec.CodecError:
                bad += 1
        # 最后一个字符只有 1 个有效位（85*5=425 > 424 bit），改它可能不影响结果；其余必须全部失败
        self.assertGreaterEqual(bad, len(code) - 1)

    def test_nonce_random(self):
        self.assertNotEqual(codec.generate(SECRET, VIN), codec.generate(SECRET, VIN))

    def test_bid_validation(self):
        for bad in ["", "LSJA24U62JG26918", "LSJA24U62JG2691811", "LSJA24U62JG26918I", "LSJA24U62JG26918O",
                    "LSJA24U62JG26918Q", "11111111111111111", "lsja24u62jg26918!"]:
            with self.assertRaises(codec.CodecError, msg=bad):
                codec.validate_bid(codec.normalize_bid(bad))
        self.assertEqual(codec.validate_bid(VIN), "vin")
        self.assertEqual(codec.validate_bid("MCABCDEFGH23456723"), "mc")

    def test_secret_parsing(self):
        for bad in ["", "zz", "00" * 31, "00" * 33]:
            with self.assertRaises(codec.CodecError):
                codec.parse_secret(bad)

    def test_vectors_reproduce(self):
        n = 0
        with open(os.path.join(HERE, "vectors.tsv")) as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                sec, bid, product, issued, nonce, code = line.rstrip("\n").split("\t")
                s = codec.parse_secret(sec)
                self.assertEqual(codec.generate(s, bid, int(product), int(issued), bytes.fromhex(nonce)), code)
                self.assertEqual(codec.verify(s, code, bid)["issued"], int(issued))
                n += 1
        self.assertGreaterEqual(n, 5)


if __name__ == "__main__":
    unittest.main()
