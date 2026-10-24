# fff_active：zFloatWindow 激活码生成器

给 zFloatWindow（≥0.7.0）生成**离线激活码**的小网页服务。输入车辆 VIN（或 APP 显示的机器码）→ 生成激活码 → 把码发给用户，用户粘贴到 APP 设置页的“授权”卡片里点“激活”即可，**APP 全程不联网**。

- 码格式：AES-256-GCM 加密的小载荷（魔数、产品号、签发时间、VIN 的 hash），base32 编码，每 5 位一组用 `-` 连接，共 17 组。详见 [SPEC.md](SPEC.md)。
- 不需要数据库；可选的历史记录写在 `data/history.log`。
- 栈：Python 3.12 + Flask + cryptography，gunicorn 运行，Docker 部署。

## 部署（Docker）

```bash
git clone https://github.com/lcf000000/fff_active.git
cd fff_active
cp .env.example .env
# 生成密钥（64 位十六进制）并填进 .env 的 FFF_ACTIVE_SECRET；再设置 ADMIN_PASSWORD
python3 -c "import secrets;print(secrets.token_hex(32))"
vi .env
docker compose up -d --build
# 浏览器打开 http://服务器IP:8080 ，用户名 admin（可用 ADMIN_USER 改），密码就是 ADMIN_PASSWORD
```

### 环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `FFF_ACTIVE_SECRET` | 是 | 64 位十六进制（32 字节）。**必须和 APK 构建时用的是同一个值**，否则 APP 校验不过 |
| `ADMIN_PASSWORD` | 是 | 网页 HTTP Basic 登录密码，至少 8 位，不能是 `change-me` 之类的示例值（否则服务拒绝启动） |
| `ADMIN_USER` | 否 | 登录用户名，默认 `admin` |
| `DATA_DIR` | 否 | 历史记录目录，默认 `data`（Docker 里是 `/data`，compose 已挂载 `./data`） |

## 使用

1. 用户在 APP 设置页顶部“授权”卡片里看到 **VIN**（读不到时显示 **机器码** `MC-XXXX-XXXX-XXXX-XXXX`），发给你。
2. 你在网页里粘贴 VIN / 机器码（页面会即时检查格式：VIN 必须 17 位、大写字母数字、不含 I/O/Q），点“生成激活码”，点“复制”。
3. 把码发给用户；用户粘贴到 APP 里点“激活”。激活码与 VIN（或机器码）绑定：换一辆车用不了。
4. 页面上的“历史记录”链接可以看最近 200 条（时间、类型、VIN、码、来源 IP）。

命令行也可以出码：

```bash
FFF_ACTIVE_SECRET=<64位hex> python -m fffactive.cli LSJA24U62JG269181
```

示例（**仅示意**，用的是公开的测试密钥 + 测试 VIN，不是真实密钥）：

```
AEAAC-AQDAQ-CQMBY-IBEFA-XAXWK-6EDIK-N5VNX-TMLD7-UCYOX-IUUER-7ODQB-MHKVU-3KGZ6-3ORIJ-RNLGO-QEJRM-5AND2
```

## 测试

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -t . -v
```

- `test_codec.py`：往返、容错输入、错 VIN/错密钥、逐字符篡改、VIN 校验、测试向量复现。
- `test_web.py`：登录、CSRF 头、生成结果能被 codec 校验、非法 VIN、弱密码拒绝启动。
- `test_cross_java.py`：把 zFloatWindow 里的 `ActivationCodec.java`（APK 实际用的类）原样编译，和 Python **互相**校验（Python 出的码 Java 验、Java 出的码 Python 验、测试向量逐字符一致）。需要 `javac`，并通过环境变量 `ZFW_CODEC` 指向 `ActivationCodec.java`（默认找 `../zFloatWindow/app/src/main/java/com/fff/zfloatwindow/ActivationCodec.java`），找不到就跳过。

## 安全说明（请读）

- **AES 是对称加密：能生成码的密钥必须同时放在 APP 里**。APK 里的密钥做了拆分+掩码混淆，但这只是提高门槛，**有逆向能力的人能把密钥提出来并自己造码**。这是“离线 + AES”方案固有的局限，不是实现 bug。
- 想真正防“造码”：改用**非对称签名（如 Ed25519）**——生成器持有私钥，APP 里只放公钥，提出公钥也造不了码。代价是码更长（签名 64 字节 + 载荷 ≈ 120 字符），且 Android 9（API 28）自带的 JCE 没有 Ed25519，APP 需要内置一个小的验签实现。本仓库默认按需求用 AES，未实现该变体；如需要可以在 SPEC 的 v2 里加。
- 真实的 `FFF_ACTIVE_SECRET` 只放在服务器的 `.env` 和你本机构建 APK 的未入库文件里。`.env`、`data/`、`secrets/` 已在 `.gitignore`。**泄漏密钥 = 任何人都能造码**；泄漏后只能换密钥并重新发版（旧码全部作废）。
- 网页用 HTTP Basic 登录，**务必放在 HTTPS 反向代理后面**（Caddy/Nginx），否则密码明文传输。登录失败有 0.5 s 延迟；生成接口要求自定义请求头防 CSRF。
- 激活码里不含 VIN 明文（只有 16 字节 hash），但历史记录文件里有 VIN 和码，注意保护 `data/`。
- 同一个 VIN 可以生成多次，每次的码不同（随机 nonce），都有效；本服务没有“吊销”（离线方案做不到）。
