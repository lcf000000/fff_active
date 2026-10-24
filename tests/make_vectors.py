"""生成 tests/vectors.tsv（用公开的测试密钥，确定性可复现；Ed25519 签名本身是确定性的）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fffactive import codec  # noqa: E402

TEST_SECRET_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"  # 仅测试用，非真实密钥
TEST_ED_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"  # RFC 8032 测试私钥，公开
BIDS = ["LSJA24U62JG269181", "LVVDB11B6CD123456", "L6T7844Z0LN012345", "MCABCDEFGH23456723", "1HGCM82633A004352"]


def main():
    keys = codec.Keys.from_hex(TEST_ED_SEED_HEX, TEST_SECRET_HEX)
    pub = codec.ed_public_from_seed(keys.ed_seed).hex()
    out = ["# mode\tkeyHex(ed=公钥 / mac=密钥)\tbid\tproduct\tcode   （测试密钥，公开）"]
    for bid in BIDS:
        out.append("\t".join(["ed", pub, bid, "1", codec.generate(keys, bid, "ed")]))
        out.append("\t".join(["mac", TEST_SECRET_HEX, bid, "1", codec.generate(keys, bid, "mac")]))
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.tsv")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print("wrote", path)


if __name__ == "__main__":
    main()
