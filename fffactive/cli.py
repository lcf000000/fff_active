"""命令行：
  python -m fffactive.cli <VIN|机器码> [ed|mac]     出码（默认 ed；读 FFF_ACTIVE_ED_SEED / FFF_ACTIVE_SECRET）
  python -m fffactive.cli --pubkey                  由 FFF_ACTIVE_ED_SEED 打印 Ed25519 公钥（构建 APK 用 FFF_ACTIVE_ED_PUBLIC）
"""
import os
import sys

from . import codec


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        keys = codec.Keys.from_hex(os.environ.get("FFF_ACTIVE_ED_SEED", ""), os.environ.get("FFF_ACTIVE_SECRET", ""))
        if argv == ["--pubkey"]:
            if not keys.ed_seed:
                raise codec.CodecError("未设置 FFF_ACTIVE_ED_SEED")
            print(codec.ed_public_from_seed(keys.ed_seed).hex())
            return 0
        if len(argv) not in (1, 2):
            print(__doc__, file=sys.stderr)
            return 2
        print(codec.generate(keys, argv[0], argv[1] if len(argv) == 2 else codec.MODE_ED))
    except codec.CodecError as e:
        print("错误：%s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
