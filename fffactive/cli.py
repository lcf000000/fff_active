"""命令行出码：python -m fffactive.cli <VIN|机器码>   （读取环境变量 FFF_ACTIVE_SECRET）"""
import os
import sys

from . import codec


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("用法：python -m fffactive.cli <VIN|机器码>", file=sys.stderr)
        return 2
    try:
        secret = codec.parse_secret(os.environ.get("FFF_ACTIVE_SECRET", ""))
        print(codec.generate(secret, argv[0]))
    except codec.CodecError as e:
        print("错误：%s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
