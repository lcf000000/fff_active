# CarMediaBridge 测试向量

文件：`tests/vectors_carmediabridge.tsv`（由 `tests/make_vectors_carmediabridge.py` 确定性生成；Ed25519 签名是确定性的）。

| 项 | 值 |
|---|---|
| 产品号 | **2**（zFloatWindow = 1） |
| 签名消息 | `"fff-active/v2/ed|"` ‖ `产品号(1 字节)` ‖ `bid(ASCII)` |
| 码 | `base64url(签名 64 字节)`，无填充，86 字符，区分大小写 |
| bid | 17 位 VIN（大写，无 I/O/Q）或机器码 `MC`+16 位 base32 |
| 测试种子 | `4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb`（RFC 8032 §7.1 TEST 2，**公开，仅测试**） |
| 测试公钥 | `3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c` |

列：`公钥hex ⇥ bid ⇥ 产品号 ⇥ 激活码`。

验证方式：
* Python：`codec.verify(code, bid, ed_public=bytes.fromhex(pub), product=2)`；
* CarMediaBridge（Java，`com.carmediabridge.license.ActivationCodec.verify(pub, code, bid, 2)`）；
* 两侧用同一个消息格式，所以同一个 (公钥, bid, 产品号) 的码逐字符相同；换 VIN、换产品号（如 1）、改任意字符、改大小写都必须失败。

自动测试：`tests/test_cross_carmediabridge.py`（编译 APK 里的验签类，双向对拍），以及 CarMediaBridge 仓库的 `LicenseLogicTest`（JDK 自带 Ed25519 签名 ↔ 纯 Java 验签）。
