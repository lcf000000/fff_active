import base64
import tempfile
import unittest

from fffactive import codec
from fffactive.web import create_app

SECRET_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
PW = "test-password-123"
VIN = "LSJA24U62JG269181"


def auth(pw=PW):
    return {"Authorization": "Basic " + base64.b64encode(("admin:" + pw).encode()).decode()}


class WebTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app(SECRET_HEX, PW, self.tmp.name)
        self.c = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def post(self, vin, headers=None):
        h = {"X-Requested-With": "fff"}
        h.update(auth())
        h.update(headers or {})
        return self.c.post("/api/generate", json={"vin": vin}, headers=h)

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
        codec.verify(codec.parse_secret(SECRET_HEX), j["code"], VIN)
        hist = self.c.get("/api/history", headers=auth()).get_data(as_text=True)
        self.assertIn(VIN, hist)

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
