"""
激活码格式 v1（与 zFloatWindow 的 ActivationCodec.java 逐字节一致，见 SPEC.md）。

  bid      = 17 位 VIN（A-Z0-9，无 I/O/Q）或机器码 "MC"+16 位 base32
  bidHash  = SHA256("fff-active/v1/bid|" + bid)[:16]
  明文(24B)= 'F' 'A' | product(1) | flags(1) | issued(uint32 BE, unix 秒) | bidHash(16)
  key      = SHA256("fff-active/v1/aes|" + secret(32 字节))
  blob(53B)= 0x01 | nonce(12) | AES-256-GCM(明文) 密文(24) | tag(16)   AAD = 0x01 + "fff-active"
  code     = base32(blob, 无填充, 字母表 A-Z2-7) = 85 字符，每 5 个一组用 '-' 连接（17 组）
"""
import base64
import hashlib
import os
import re
import struct
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 0x01
PRODUCT_ZFLOAT = 1
AAD = bytes([VERSION]) + b"fff-active"
VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
MC_RE = re.compile(r"^MC[A-Z2-7]{16}$")
BLOB_LEN = 1 + 12 + 24 + 16


class CodecError(ValueError):
    pass


def parse_secret(hex_str: str) -> bytes:
    hex_str = (hex_str or "").strip()
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError as e:
        raise CodecError("FFF_ACTIVE_SECRET 不是合法的十六进制") from e
    if len(raw) != 32:
        raise CodecError("FFF_ACTIVE_SECRET 必须是 64 位十六进制（32 字节）")
    return raw


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


def bid_hash(bid: str) -> bytes:
    return hashlib.sha256(b"fff-active/v1/bid|" + bid.encode("ascii")).digest()[:16]


def derive_key(secret: bytes) -> bytes:
    return hashlib.sha256(b"fff-active/v1/aes|" + secret).digest()


def b32enc(b: bytes) -> str:
    return base64.b32encode(b).decode("ascii").rstrip("=")


def b32dec(s: str) -> bytes:
    s = s + "=" * (-len(s) % 8)
    return base64.b32decode(s)


def group(s: str, n: int = 5) -> str:
    return "-".join(s[i:i + n] for i in range(0, len(s), n))


def generate(secret: bytes, bid: str, product: int = PRODUCT_ZFLOAT, issued: int = None,
             nonce: bytes = None) -> str:
    bid = normalize_bid(bid)
    validate_bid(bid)
    issued = int(time.time()) if issued is None else issued
    nonce = os.urandom(12) if nonce is None else nonce
    plain = b"FA" + bytes([product, 0]) + struct.pack(">I", issued) + bid_hash(bid)
    ct = AESGCM(derive_key(secret)).encrypt(nonce, plain, AAD)  # 密文 24 + tag 16
    blob = bytes([VERSION]) + nonce + ct
    assert len(blob) == BLOB_LEN
    return group(b32enc(blob))


def verify(secret: bytes, code: str, bid: str):
    """校验通过返回 dict(product, issued)，否则抛 CodecError。"""
    bid = normalize_bid(bid)
    validate_bid(bid)
    s = re.sub(r"[^A-Za-z2-7]", "", code or "").upper()
    try:
        blob = b32dec(s)
    except Exception as e:
        raise CodecError("激活码格式错误") from e
    if len(blob) != BLOB_LEN or blob[0] != VERSION:
        raise CodecError("激活码格式错误")
    try:
        plain = AESGCM(derive_key(secret)).decrypt(blob[1:13], blob[13:], AAD)
    except InvalidTag as e:
        raise CodecError("校验失败（激活码被改动，或不是用这套密钥生成的）") from e
    if plain[:2] != b"FA":
        raise CodecError("校验失败（magic 不符）")
    if plain[8:24] != bid_hash(bid):
        raise CodecError("激活码与本机识别码不匹配")
    return {"product": plain[2], "issued": struct.unpack(">I", plain[4:8])[0]}
