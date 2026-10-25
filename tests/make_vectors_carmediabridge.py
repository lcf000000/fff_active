"""生成 tests/vectors_carmediabridge.tsv：CarMediaBridge（产品号 2）的测试向量，用公开的 RFC 8032 测试种子（仅测试，非真实密钥），可确定性复现。
格式（制表符分隔）：公钥hex  bid  产品号  激活码。文档见 docs/CARMEDIABRIDGE_VECTORS.md。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fffactive import codec  # noqa: E402

TEST_SEED_HEX = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"   # RFC 8032 §7.1 TEST 2 私钥，公开
BIDS = ["LSJA24U62JG269181", "LVVDB11B6CD123456", "L6T7844Z0LN012345", "MCABCDEFGH23456723"]
PRODUCT = 2


def main():
    keys = codec.Keys(ed_seed=bytes.fromhex(TEST_SEED_HEX))
    pub = codec.ed_public_from_seed(keys.ed_seed).hex()
    out = ["# publicKeyHex\tbid\tproduct\tcode   （CarMediaBridge 产品号 2；测试密钥 = RFC 8032 TEST 2，公开，非真实密钥）"]
    for bid in BIDS:
        out.append("\t".join([pub, bid, str(PRODUCT), codec.generate(keys, bid, "ed", product=PRODUCT)]))
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors_carmediabridge.tsv")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print("wrote", path)


if __name__ == "__main__":
    main()
