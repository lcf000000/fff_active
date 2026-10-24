"""
激活码格式 v2（与 zFloatWindow 的 ActivationCodec.java / Ed25519.java 一致，见 SPEC.md）。

码里**不含 VIN 和时间**：APP 自己知道 VIN，校验时把 VIN 和产品号重新拼出来验。
同一个 VIN + 产品号 → 码是确定的（Ed25519 签名是确定性的；紧凑码是 HMAC），重装/清数据后同一个码还能再激活。

  标准码（ed，默认）：Ed25519 签名 64 字节，base64url（无填充）= 86 字符，区分大小写，不加分隔符
      msg = "fff-active/v2/ed|" + product(1 字节) + bid
  紧凑码（mac）    ：HMAC-SHA256 截断 12 字节，base32（A-Z2-7）= 20 字符，显示成 5-5-5-5
      key = SHA256("fff-active/v2/hmac|" + secret(32 字节)),  msg = "fff-active/v2/mac|" + product + bid
  bid = 17 位 VIN（A-HJ-NPR-Z0-9）或机器码 "MC"+16 位 base32
"""
import base64
import hashlib
import hmac as _hmac
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PRODUCT_ZFLOAT = 1
MODE_ED = "ed"
MODE_MAC = "mac"
VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
MC_RE = re.compile(r"^MC[A-Z2-7]{16}$")
ED_CODE_RE = re.compile(r"^[A-Za-z0-9_\-]{86}$")
MAC_CODE_RE = re.compile(r"^[A-Z2-7]{20}$")
MAC_BYTES = 12


class CodecError(ValueError):
    pass


def _hex32(name: str, hex_str: str) -> bytes:
    try:
        raw = bytes.fromhex((hex_str or "").strip())
    except ValueError as e:
        raise CodecError("%s 不是合法的十六进制" % name) from e
    if len(raw) != 32:
        raise CodecError("%s 必须是 64 位十六进制（32 字节）" % name)
    return raw


def parse_secret(hex_str: str) -> bytes:
    return _hex32("FFF_ACTIVE_SECRET", hex_str)


def parse_ed_seed(hex_str: str) -> bytes:
    return _hex32("FFF_ACTIVE_ED_SEED", hex_str)


def ed_public_from_seed(seed: bytes) -> bytes:
    k = Ed25519PrivateKey.from_private_bytes(seed)
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Keys:
    """生成端持有的密钥：ed_seed（Ed25519 私钥种子）和/或 mac_secret（紧凑码对称密钥）。"""

    def __init__(self, ed_seed: bytes = None, mac_secret: bytes = None):
        if ed_seed is None and mac_secret is None:
            raise CodecError("至少要配置 FFF_ACTIVE_ED_SEED 或 FFF_ACTIVE_SECRET 之一")
        self.ed_seed = ed_seed
        self.mac_secret = mac_secret

    @classmethod
    def from_hex(cls, ed_seed_hex: str = "", mac_secret_hex: str = ""):
        return cls(parse_ed_seed(ed_seed_hex) if (ed_seed_hex or "").strip() else None,
                   parse_secret(mac_secret_hex) if (mac_secret_hex or "").strip() else None)

    def modes(self):
        return ([MODE_ED] if self.ed_seed else []) + ([MODE_MAC] if self.mac_secret else [])


def normalize_bid(s: str) -> str:
    return re.sub(r"[\s\-_]", "", (s or "")).upper()


def validate_bid(bid: str) -> str:
    """返回 'vin' 或 'mc'，不合法抛 CodecError。"""
    if VIN_RE.match(bid):
        if len(set(bid)) == 1:
            raise CodecError("VIN 不合法（全部字符相同）")
        return "vin"
    if MC_RE.match(bid):
        return "mc"
    raise CodecError("请输入 17 位 VIN（大写字母和数字，不含 I、O、Q）或 MC 开头的机器码")


def _ed_msg(bid: str, product: int) -> bytes:
    return b"fff-active/v2/ed|" + bytes([product]) + bid.encode("ascii")


def _mac_key(secret: bytes) -> bytes:
    return hashlib.sha256(b"fff-active/v2/hmac|" + secret).digest()


def _mac_tag(secret: bytes, bid: str, product: int) -> bytes:
    msg = b"fff-active/v2/mac|" + bytes([product]) + bid.encode("ascii")
    return _hmac.new(_mac_key(secret), msg, hashlib.sha256).digest()[:MAC_BYTES]


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b32enc(b: bytes) -> str:
    return base64.b32encode(b).decode("ascii").rstrip("=")


def group(s: str, n: int = 5) -> str:
    return "-".join(s[i:i + n] for i in range(0, len(s), n))


def generate(keys: Keys, bid: str, mode: str = MODE_ED, product: int = PRODUCT_ZFLOAT) -> str:
    bid = normalize_bid(bid)
    validate_bid(bid)
    if mode == MODE_ED:
        if not keys.ed_seed:
            raise CodecError("未配置 Ed25519 私钥（FFF_ACTIVE_ED_SEED）")
        sig = Ed25519PrivateKey.from_private_bytes(keys.ed_seed).sign(_ed_msg(bid, product))
        return b64u(sig)
    if mode == MODE_MAC:
        if not keys.mac_secret:
            raise CodecError("未配置紧凑码密钥（FFF_ACTIVE_SECRET）")
        return group(b32enc(_mac_tag(keys.mac_secret, bid, product)))
    raise CodecError("未知模式 %s" % mode)


def classify(code: str):
    """按长度/字符集判断码的类型，返回 'ed' / 'mac' / None。"""
    c = re.sub(r"\s", "", code or "")
    if ED_CODE_RE.match(c):
        return MODE_ED
    m = re.sub(r"[\s\-]", "", code or "").upper()
    if MAC_CODE_RE.match(m):
        return MODE_MAC
    return None


def verify(code: str, bid: str, ed_public: bytes = None, mac_secret: bytes = None, product: int = PRODUCT_ZFLOAT) -> str:
    """校验通过返回类型（'ed'/'mac'），否则抛 CodecError。"""
    bid = normalize_bid(bid)
    validate_bid(bid)
    kind = classify(code)
    if kind == MODE_ED:
        if ed_public is None:
            raise CodecError("此配置不接受标准码")
        sig = b64u_dec(re.sub(r"\s", "", code))
        try:
            Ed25519PublicKey.from_public_bytes(ed_public).verify(sig, _ed_msg(bid, product))
        except InvalidSignature as e:
            raise CodecError("校验失败：激活码有误，或不是这个 VIN 的") from e
        return MODE_ED
    if kind == MODE_MAC:
        if mac_secret is None:
            raise CodecError("此配置不接受紧凑码")
        tag = _mac_tag(mac_secret, bid, product)
        given = re.sub(r"[\s\-]", "", code).upper()
        if not _hmac.compare_digest(group(b32enc(tag)).replace("-", ""), given):
            raise CodecError("校验失败：激活码有误，或不是这个 VIN 的")
        return MODE_MAC
    raise CodecError("激活码格式错误")
