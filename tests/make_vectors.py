"""生成 tests/vectors.tsv（用公开的测试密钥，固定 nonce/issued，可复现）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fffactive import codec  # noqa: E402

TEST_SECRET_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"  # 仅测试用，非真实密钥
BIDS = ["LSJA24U62JG269181", "LVVDB11B6CD123456", "L6T7844Z0LN012345", "MCABCDEFGH23456723", "1HGCM82633A004352"]


def main():
    secret = codec.parse_secret(TEST_SECRET_HEX)
    out = ["# secretHex\tbid\tproduct\tissued\tnonceHex\tcode   （测试密钥，公开）"]
    for i, bid in enumerate(BIDS):
        nonce = bytes((i * 17 + j) & 0xFF for j in range(12))
        issued = 1790000000 + i * 86400
        code = codec.generate(secret, bid, codec.PRODUCT_ZFLOAT, issued, nonce)
        out.append("\t".join([TEST_SECRET_HEX, bid, "1", str(issued), nonce.hex(), code]))
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.tsv")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print("wrote", path)


if __name__ == "__main__":
    main()
