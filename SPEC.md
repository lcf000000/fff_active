# 激活码格式 v1（zFloatWindow ↔ fff_active）

两边实现必须逐字节一致：Python 见 `fffactive/codec.py`，APK 侧见 zFloatWindow 的 `ActivationCodec.java`。
`tests/vectors.tsv` 是固定 nonce 的测试向量（**测试密钥，公开**），两边都要能复现；
`tests/test_cross_java.py` 会把 APK 里的 `ActivationCodec.java` 原样编译，和 Python 互相校验。

| 项 | 定义 |
|---|---|
| 绑定识别码 bid | 17 位 VIN（`[A-HJ-NPR-Z0-9]{17}`，大写，不全相同）；或机器码 `MC` + 16 位 base32（`[A-Z2-7]`）。生成/校验前先去掉空格、`-`、`_` 并转大写 |
| bidHash | `SHA256("fff-active/v1/bid|" + bid)[:16]`（码里不放 VIN 明文） |
| 明文（24 字节） | `'F' 'A'` ‖ product(1) ‖ flags(1，目前 0) ‖ issued(uint32 大端，unix 秒) ‖ bidHash(16)；product=1 表示 zFloatWindow |
| 密钥 | `SHA256("fff-active/v1/aes|" + secret)`，secret = `FFF_ACTIVE_SECRET` 十六进制解码后的 32 字节 |
| 加密 | AES-256-GCM，nonce 12 字节随机，tag 16 字节，AAD = `0x01` ‖ `"fff-active"` |
| blob（53 字节） | `0x01`(版本) ‖ nonce(12) ‖ 密文(24) ‖ tag(16) |
| 码 | blob 的 base32（RFC 4648 字母表 A-Z2-7，无填充）= 85 个字符，每 5 个一组用 `-` 连接，共 17 组（101 字符） |
| 校验 | 去掉非 `[A-Za-z2-7]` 字符 → 大写 → base32 解码 → 长度 53、版本 1 → AES-GCM 解密（失败=被改动/密钥不符）→ magic `FA` → bidHash 与本机识别码一致 |

字母表里没有 0/1/8/9，所以不会有 0/O、1/I 混淆。码里有签发时间 `issued`，目前 APP 只读不判（车机时钟不可靠）。

## 机器码（仅 APP 侧生成，生成器只负责接受）
`"MC" + base32(SHA256("fff-active/v1/mc|" + 稳定设备标识)[:10])`（16 个字符）。
稳定设备标识取 `persist.device.sn`、`ro.serialno`、`ro.boot.serialno` 中非空者（`k=v|k=v` 拼接），全空才退到 `ANDROID_ID`。
界面显示为 `MC-XXXX-XXXX-XXXX-XXXX`。
