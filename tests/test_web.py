import base64
import tempfile
import unittest

from fffactive import codec
from fffactive.web import create_app

SECRET_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PUB = codec.ed_public_from_seed(bytes.fromhex(SEED_HEX))
PW = "test-password-123"
VIN = "LSJA24U62JG269181"


def auth(pw=PW):
    return {"Authorization": "Basic " + base64.b64encode(("admin:" + pw).encode()).decode()}


class WebTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app(SECRET_HEX, PW, self.tmp.name, SEED_HEX)
        self.c = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def post(self, vin, headers=None, mode=None):
        h = {"X-Requested-With": "fff"}
        h.update(auth())
        h.update(headers or {})
        return self.c.post("/api/generate", json={"vin": vin, "mode": mode} if mode else {"vin": vin}, headers=h)

    def test_requires_auth(self):
        self.assertEqual(self.c.get("/").status_code, 401)
        self.assertEqual(self.c.get("/", headers=auth("wrong-password")).status_code, 401)
        self.assertEqual(self.c.post("/api/generate", json={"vin": VIN}).status_code, 401)
        self.assertEqual(self.c.get("/healthz").status_code, 200)

    def test_index(self):
        r = self.c.get("/", headers=auth())
        self.assertEqual(r.status_code, 200)
        self.assertIn("生成激活码".encode(), r.data)

    def test_generate_validates_with_codec(self):
        r = self.post(VIN.lower())
        self.assertEqual(r.status_code, 200)
        j = r.get_json()
        self.assertTrue(j["ok"])
        self.assertEqual(j["mode"], "ed")          # 默认标准码
        self.assertEqual(j["length"], 86)
        codec.verify(j["code"], VIN, ed_public=PUB)
        m = self.post(VIN, mode="mac").get_json()
        self.assertEqual(m["length"], 23)
        codec.verify(m["code"], VIN, mac_secret=codec.parse_secret(SECRET_HEX))
        hist = self.c.get("/api/history", headers=auth()).get_data(as_text=True)
        self.assertIn(VIN, hist)

    def test_mode_not_configured(self):
        app = create_app("", PW, self.tmp.name, SEED_HEX)          # 只配了 Ed25519
        c = app.test_client()
        h = {"X-Requested-With": "fff", **auth()}
        self.assertEqual(c.post("/api/generate", json={"vin": VIN}, headers=h).status_code, 200)
        self.assertEqual(c.post("/api/generate", json={"vin": VIN, "mode": "mac"}, headers=h).status_code, 400)
        self.assertNotIn("紧凑码（HMAC".encode(), c.get("/", headers=auth()).data)
        with self.assertRaises(Exception):
            create_app("", PW, self.tmp.name, "")                    # 两个密钥都没有 → 拒绝启动

    def test_machine_code(self):
        j = self.post("MC-ABCD-EFGH-2345-6723").get_json()
        self.assertTrue(j["ok"])
        self.assertEqual(j["kind"], "mc")

    def test_invalid_vin(self):
        for v in ["", "123", "LSJA24U62JG26918I"]:
            r = self.post(v)
            self.assertEqual(r.status_code, 400)
            self.assertFalse(r.get_json()["ok"])

    def test_csrf_header_required(self):
        r = self.c.post("/api/generate", json={"vin": VIN}, headers=auth())
        self.assertEqual(r.status_code, 400)

    def test_weak_password_refused(self):
        with self.assertRaises(RuntimeError):
            create_app(SECRET_HEX, "change-me", self.tmp.name)
        with self.assertRaises(RuntimeError):
            create_app(SECRET_HEX, "", self.tmp.name)


if __name__ == "__main__":
    unittest.main()
