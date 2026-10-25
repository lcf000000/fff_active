"""命令行：
  python -m fffactive.cli <VIN|机器码> [ed|mac]            默认 APP（FFF_ACTIVE_ED_SEED / FFF_ACTIVE_SECRET，产品号 1）出码
  python -m fffactive.cli --pubkey                          默认 APP 的 Ed25519 公钥
  python -m fffactive.cli --list                            列出 DATA_DIR 里的 APP（名称/slug/产品号/公钥，不含私钥）
  python -m fffactive.cli --app <slug> <VIN|机器码>          用 DATA_DIR 里该 APP 的密钥和产品号出码
  python -m fffactive.cli --app <slug> --pubkey             该 APP 的公钥
"""
import os
import sys

from . import codec
from .store import AppError, AppStore


def _store():
    seed_hex = os.environ.get("FFF_ACTIVE_ED_SEED", "").strip()
    sec_hex = os.environ.get("FFF_ACTIVE_SECRET", "").strip()
    return AppStore(os.environ.get("DATA_DIR", "data"),
                    codec.parse_ed_seed(seed_hex) if seed_hex else None,
                    codec.parse_secret(sec_hex) if sec_hex else None,
                    os.environ.get("FFF_ACTIVE_STORE_KEY", ""))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        slug = None
        if "--app" in argv:
            i = argv.index("--app")
            if i + 1 >= len(argv):
                print(__doc__, file=sys.stderr)
                return 2
            slug = argv[i + 1]
            del argv[i:i + 2]
        if argv == ["--list"]:
            for a in _store().list():
                print("%s\t%s\tproduct=%d\t%s" % (a["slug"], a["name"], a["product"], a["ed_public"]))
            return 0
        if slug is not None:
            st = _store()
            rec = st.get(slug)
            if rec is None:
                raise codec.CodecError("APP 不存在：%s" % slug)
            if argv == ["--pubkey"]:
                print(rec["ed_public"])
                return 0
            keys = st.keys_for(rec)
            if keys is None:
                raise codec.CodecError("APP %s 没有可用的私钥" % slug)
            if len(argv) not in (1, 2):
                print(__doc__, file=sys.stderr)
                return 2
            print(codec.generate(keys, argv[0], argv[1] if len(argv) == 2 else codec.MODE_ED, product=rec["product"]))
            return 0
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
    except (codec.CodecError, AppError) as e:
        print("错误：%s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
