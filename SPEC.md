# 激活码格式 v2（zFloatWindow ↔ fff_active）

两边实现必须一致：Python 见 `fffactive/codec.py`，APK 侧见 zFloatWindow 的 `ActivationCodec.java` + `Ed25519.java`。
`tests/vectors.tsv` 是测试向量（**测试密钥，公开**），`tests/test_cross_java.py` 把 APK 里的这两个类原样编译，和 Python 互相校验，
并跑 RFC 8032 官方向量。

**码里不含 VIN、不含时间。** APP 自己知道 VIN，校验时用“当前 VIN + 产品号”重新拼出消息再验；同一 VIN → 码固定不变
（Ed25519 签名是确定性的，HMAC 也是），所以重装/清数据后同一个码还能再次离线激活。

| 项 | 定义 |
|---|---|
| bid（绑定识别码） | 17 位 VIN（`[A-HJ-NPR-Z0-9]{17}`，大写，不全相同）；或机器码 `MC` + 16 位 base32（`[A-Z2-7]`）。生成/校验前去掉空白、`-`、`_` 并转大写 |
| product | 1 字节，1 = zFloatWindow |
| **标准码 `ed`**（默认） | `msg = "fff-active/v2/ed|" ‖ product(1) ‖ bid(ASCII)`；`code = base64url(Ed25519_sign(seed, msg))`，去掉 `=` 填充 → **86 字符**，区分大小写，无分隔符。APP 内只有公钥 |
| **紧凑码 `mac`** | `key = SHA256("fff-active/v2/hmac|" ‖ secret(32 字节))`；`tag = HMAC-SHA256(key, "fff-active/v2/mac|" ‖ product ‖ bid)[:12]`；`code = base32(tag)`（RFC 4648，A-Z2-7，无填充）= **20 字符**，显示为 `XXXXX-XXXXX-XXXXX-XXXXX`（23 字符）。APP 内要有 secret |
| 识别类型 | 去空白后 86 字符且全在 `[A-Za-z0-9_-]` → ed；否则去掉 `-`/空白、转大写后 20 字符且全在 `[A-Z2-7]` → mac；其余 = 格式错误。**ed 码里的 `-`、`_` 是数据，不能删** |
| 校验 | ed：Ed25519 严格验签（S < L，R/A 为合法点）；mac：常量时间比较 96 位标签 |

## 机器码（仅 APP 侧生成，生成器只负责接受）
`"MC" + base32(SHA256("fff-active/v1/mc|" + 稳定设备标识)[:10])`（16 个字符）。
稳定设备标识取 `persist.device.sn`、`ro.serialno`、`ro.boot.serialno` 中非空者（`k=v|k=v` 拼接），全空才退到 `ANDROID_ID`。
界面显示为 `MC-XXXX-XXXX-XXXX-XXXX`。（机器码绑定车机而不是车；仅在读不到 VIN 时使用。）

## 多 APP 扩展（不改变码格式）
码格式 v2 本身不变；每个 APP 有自己的 Ed25519 密钥对和**产品号**（签名消息里的 1 字节）。
默认 APP zFloatWindow：产品号 1，消息 `"fff-active/v2/ed|\x01" + bid`，与之前逐字节相同。
CarMediaBridge：产品号 2。别的 APP 的码即使 VIN 相同，在公钥或产品号不同的 APP 里都验不过。
