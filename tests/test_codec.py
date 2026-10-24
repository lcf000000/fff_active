import os
import unittest

from fffactive import codec

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")  # RFC 8032 测试私钥（公开）
PUB = codec.ed_public_from_seed(SEED)
SECRET = codec.parse_secret("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
KEYS = codec.Keys(SEED, SECRET)
VIN = "LSJA24U62JG269181"


class CodecTest(unittest.TestCase):
    def test_public_key_matches_rfc8032(self):
        self.assertEqual(PUB.hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    def test_ed_format_and_roundtrip(self):
        code = codec.generate(KEYS, VIN, "ed")
        self.assertEqual(len(code), 86)
        self.assertRegex(code, r"^[A-Za-z0-9_\-]{86}$")
        self.assertEqual(codec.classify(code), "ed")
        self.assertEqual(codec.verify(code, VIN, ed_public=PUB), "ed")

    def test_ed_deterministic(self):
        self.assertEqual(codec.generate(KEYS, VIN, "ed"), codec.generate(KEYS, VIN.lower(), "ed"))

    def test_mac_format_and_roundtrip(self):
        code = codec.generate(KEYS, VIN, "mac")
        self.assertEqual(len(code), 23)
        self.assertRegex(code, r"^[A-Z2-7]{5}(-[A-Z2-7]{5}){3}$")
        self.assertEqual(codec.classify(code), "mac")
        self.assertEqual(codec.verify(code, VIN, mac_secret=SECRET), "mac")
        self.assertEqual(codec.generate(KEYS, VIN, "mac"), code)  # 确定性

    def test_lenient_input(self):
        code = codec.generate(KEYS, VIN, "mac")
        messy = " " + code.lower().replace("-", " ") + "\n"
        codec.verify(messy, VIN.lower(), mac_secret=SECRET)
        ed = codec.generate(KEYS, VIN, "ed")
        codec.verify(ed[:40] + " \n" + ed[40:], VIN, ed_public=PUB)

    def test_wrong_vin(self):
        for mode in ("ed", "mac"):
            code = codec.generate(KEYS, VIN, mode)
            with self.assertRaises(codec.CodecError):
                codec.verify(code, "LSJA24U62JG269182", ed_public=PUB, mac_secret=SECRET)

    def test_wrong_product(self):
        for mode in ("ed", "mac"):
            code = codec.generate(KEYS, VIN, mode, product=2)
            with self.assertRaises(codec.CodecError):
                codec.verify(code, VIN, ed_public=PUB, mac_secret=SECRET)

    def test_wrong_key(self):
        other_seed = bytes([7]) * 32
        forged = codec.generate(codec.Keys(other_seed), VIN, "ed")
        with self.assertRaises(codec.CodecError):
            codec.verify(forged, VIN, ed_public=PUB)
        mac = codec.generate(KEYS, VIN, "mac")
        with self.assertRaises(codec.CodecError):
            codec.verify(mac, VIN, mac_secret=codec.parse_secret("ff" * 32))

    def test_tamper_ed_every_position(self):
        code = codec.generate(KEYS, VIN, "ed")
        for i in range(len(code)):
            c = "A" if code[i] != "A" else "B"
            t = code[:i] + c + code[i + 1:]
            try:
                codec.verify(t, VIN, ed_public=PUB)
            except codec.CodecError:
                continue
            # 末位只有 4 个有效 bit，改它可能解出相同字节（base64 非规范编码）；Java 端同样按字节验，这里只允许最后一位例外
            self.assertEqual(i, len(code) - 1)

    def test_tamper_mac_every_position(self):
        code = codec.generate(KEYS, VIN, "mac").replace("-", "")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        bad = 0
        for i in range(len(code)):
            t = code[:i] + alphabet[(alphabet.index(code[i]) + 1) % 32] + code[i + 1:]
            try:
                codec.verify(t, VIN, mac_secret=SECRET)
            except codec.CodecError:
                bad += 1
        self.assertGreaterEqual(bad, len(code) - 1)   # 96 bit → 20 字符，末位有 4 个多余 bit

    def test_unsupported_kind(self):
        with self.assertRaises(codec.CodecError):
            codec.verify(codec.generate(KEYS, VIN, "mac"), VIN, ed_public=PUB)
        with self.assertRaises(codec.CodecError):
            codec.verify(codec.generate(KEYS, VIN, "ed"), VIN, mac_secret=SECRET)

    def test_garbage(self):
        for g in ["", "hello", "A" * 19, "A" * 85, "!" * 86]:
            self.assertIsNone(codec.classify(g), g)

    def test_mode_without_key(self):
        with self.assertRaises(codec.CodecError):
            codec.generate(codec.Keys(SEED), VIN, "mac")
        with self.assertRaises(codec.CodecError):
            codec.generate(codec.Keys(mac_secret=SECRET), VIN, "ed")
        with self.assertRaises(codec.CodecError):
            codec.Keys()

    def test_bid_validation(self):
        for bad in ["", "LSJA24U62JG26918", "LSJA24U62JG2691811", "LSJA24U62JG26918I", "LSJA24U62JG26918O",
                    "LSJA24U62JG26918Q", "11111111111111111", "lsja24u62jg26918!"]:
            with self.assertRaises(codec.CodecError, msg=bad):
                codec.validate_bid(codec.normalize_bid(bad))
        self.assertEqual(codec.validate_bid(VIN), "vin")
        self.assertEqual(codec.validate_bid("MCABCDEFGH23456723"), "mc")

    def test_key_parsing(self):
        for bad in ["zz", "00" * 31, "00" * 33]:
            with self.assertRaises(codec.CodecError):
                codec.parse_secret(bad)
            with self.assertRaises(codec.CodecError):
                codec.parse_ed_seed(bad)

    def test_vectors_reproduce(self):
        n = 0
        with open(os.path.join(HERE, "vectors.tsv")) as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                mode, key, bid, product, code = line.rstrip("\n").split("\t")
                if mode == "ed":
                    self.assertEqual(codec.verify(code, bid, ed_public=bytes.fromhex(key), product=int(product)), "ed")
                    self.assertEqual(codec.generate(KEYS, bid, "ed"), code)
                else:
                    self.assertEqual(codec.verify(code, bid, mac_secret=bytes.fromhex(key), product=int(product)), "mac")
                    self.assertEqual(codec.generate(KEYS, bid, "mac"), code)
                n += 1
        self.assertGreaterEqual(n, 10)


if __name__ == "__main__":
    unittest.main()
