# fff_active：多 APP 激活码生成器

给多个 APP（zFloatWindow ≥0.7.0、CarMediaBridge 等）生成**离线永久激活码**的小网页服务。**先选 APP → 再输入车辆 VIN（或 APP 显示的机器码）→ 生成激活码** → 发给用户，用户粘贴到 APP 里的“授权/激活”卡片点“激活”即可，**APP 全程不联网**。激活码与 VIN 绑定，永久有效；清数据/重装后用同一个码可以再次激活。

- **两种码，可选**（详见 [SPEC.md](SPEC.md)）：

  | 类型 | 长度 | 防伪造 | 说明 |
  |---|---|---|---|
  | **标准码（Ed25519，默认）** | **86 字符**（无分隔符，区分大小写） | **强**：私钥只在本服务，APK 里只有公钥 | 提取 APK 也造不了码 |
  | **紧凑码（HMAC）** | **20 字符**（显示 23 字符 `XXXXX-XXXXX-XXXXX-XXXXX`） | **弱**：对称密钥必须编进 APK | 短、好发；有逆向能力的人能提出密钥自己造码；APK 要用 `-PfffActiveMode=mac`（或 `both`）构建 |

- **多 APP**：每个 APP = 名称 + 唯一标识（slug）+ **唯一的 Ed25519 公钥** + 产品号；在网页 **APP 管理**（`/apps`）里增加/编辑/删除，公钥随时可复制。旧的环境变量 `FFF_ACTIVE_ED_SEED` 自动迁移成默认 APP **zFloatWindow**（产品号 1，出的码与改动前逐字符一致）。
- 码里**不含 VIN 和时间**，同一 VIN 每次生成结果相同（确定性）。
- 不需要数据库：APP 列表在 `data/apps.json`，私钥种子在 `data/seeds/`（见下），历史记录在 `data/history.log`（含 APP 名称）。
- 栈：Python 3.12 + Flask + cryptography，gunicorn 运行，Docker 部署。

## 部署（Docker）

```bash
git clone https://github.com/lcf000000/fff_active.git
cd fff_active
cp .env.example .env
# 1) 生成 Ed25519 私钥种子（64 位十六进制），填进 .env 的 FFF_ACTIVE_ED_SEED
python3 -c "import secrets;print(secrets.token_hex(32))"
# 2) （可选）要紧凑码，再生成一个 FFF_ACTIVE_SECRET；不要就留空
# 3) 设置 ADMIN_PASSWORD
vi .env
docker compose up -d --build
# 浏览器打开 http://服务器IP:8080 ，用户名 admin（可用 ADMIN_USER 改），密码就是 ADMIN_PASSWORD
# 4) 登录后打开“APP 管理”，每个 APP 都显示它的 Ed25519 公钥（构建 APK 用），点“复制公钥”即可（无需命令行）
```

### NAS 图形界面部署（群晖 Container Manager / 威联通 / 飞牛 / Portainer 等）
不需要命令行，也不需要 `docker compose`：

1. 获取镜像：在 NAS 的 Docker 界面里用本仓库构建镜像（Dockerfile 在仓库根目录；多数 NAS 支持“从 Git/Dockerfile 构建”，或先在任意电脑上 `docker build` 后导出再导入）。
2. 创建容器，**端口**：容器端口 `8080` → 映射一个 NAS 上的端口（例如 8080）。
3. **环境变量**（在 NAS 容器界面的“环境变量/Environment”里逐条填；值不要加引号）：
   - `FFF_ACTIVE_ED_SEED`：可选。64 位十六进制私钥种子；设置后自动成为默认 APP zFloatWindow（沿用旧部署）。**新 APP 不需要它**，直接在网页“APP 管理”里添加。
   - `FFF_ACTIVE_STORE_KEY`：可选但推荐。任意口令；设置后网页添加的 APP 的私钥种子在数据卷里用 AES-256-GCM 加密保存（不设则以 0600 权限明文存放）。**设了就不要再改**，否则已存种子读不出来。
   - `ADMIN_PASSWORD`：登录密码，至少 8 位（必填）。
   - `ADMIN_USER`：可选，默认 `admin`。
   - `FFF_ACTIVE_SECRET`：可选，只有要“紧凑码”才填；不要就别建这一项或留空。
4. **卷（存储空间）**：只用环境变量的默认 APP 时可以不挂卷（只是历史记录会丢）。**要在网页里添加 APP，必须把一个 NAS 目录挂到容器的 `/data`**（该目录需要容器内用户 uid 10001 可写）——APP 列表和私钥种子都在里面，**请备份整个目录**：种子丢了，已发布 APK 里的公钥就再也出不了码。
5. 启动容器，浏览器打开 `http://NAS地址:映射端口`，输入用户名/密码。**“APP 管理”页会显示每个 APP 的 Ed25519 公钥**（带“复制公钥”按钮）——填进对应 APK 的构建参数（zFloatWindow：`FFF_ACTIVE_ED_PUBLIC`；CarMediaBridge：`-PlicensePubKeyHex` / `package_custom_id.sh --pubkey`）。
6. 如果页面顶部出现**红色提示**，说明环境变量没设对（例如 `FFF_ACTIVE_ED_SEED` 不是 64 位十六进制）；提示里只会写变量名和问题，不会显示任何值。按提示改好环境变量、重启容器即可（其他 APP 不受影响）。
7. **HTTPS**：网页用 HTTP Basic 登录，密码是明文传输的。如果要从外网访问，务必放在 HTTPS 反向代理后面（NAS 自带的反向代理/Caddy/Nginx 均可），不要把 8080 直接暴露到公网；只在内网用也建议别开端口转发。
8. 页面上只会显示**公钥**；私钥种子（`FFF_ACTIVE_ED_SEED`、网页里创建/导入的 APP 的种子）和 `FFF_ACTIVE_SECRET` 在任何页面、接口、日志里都不会出现（创建后也**不能再查看**）；请备份数据卷，丢了就只能换密钥、重新发版。

### 构建 APK 需要的东西（zFloatWindow 仓库）
- 标准码（默认 `ed` 模式）：构建时提供 `FFF_ACTIVE_ED_PUBLIC`（登录网页后页面上显示的公钥，64 位小写 hex，也可用 `python -m fffactive.cli --pubkey` 得到；它是公钥，不是秘密）。
- 紧凑码：`-PfffActiveMode=mac`（只认紧凑码）或 `both`，并提供与服务端相同的 `FFF_ACTIVE_SECRET`。
- 取值来源优先级：`-P<名字>` > 环境变量 > 文件（`-PfffActiveEnv=路径` / 环境变量 `FFF_ACTIVE_ENV` / `<仓库>/secrets/fff_active.env`，每行 `KEY=value`，该目录已 gitignore）。缺少所需密钥时构建直接失败。

### 环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `FFF_ACTIVE_ED_SEED` | 否 | Ed25519 私钥种子，64 位十六进制 → 自动迁移成默认 APP zFloatWindow（产品号 1，种子不落盘，始终读环境变量）。**只放服务器**，不要进 APK、不要提交。格式不对时服务照常启动，页面顶部显示红色提示（该默认 APP 不可用，其他 APP 不受影响） |
| `FFF_ACTIVE_STORE_KEY` | 否（推荐） | 加密网页里创建/导入的私钥种子的口令（AES-256-GCM）。不设则种子以 0600 权限存放；设了不要再改 |
| `FFF_ACTIVE_SECRET` | 紧凑码必填 | 64 位十六进制。和 APK 构建时用的是同一个值。留空则网页不提供紧凑码；**只给默认 APP（zFloatWindow）**，其他 APP 只有标准码 |
| `ADMIN_PASSWORD` | 是 | 网页 HTTP Basic 登录密码，至少 8 位，不能是 `change-me` 之类（否则拒绝启动） |
| `ADMIN_USER` | 否 | 登录用户名，默认 `admin` |
| `DATA_DIR` | 否 | 数据目录（`apps.json`、`seeds/`、`history.log`），默认 `data`（Docker 里是 `/data`，compose 已挂载 `./data`） |

只配 `FFF_ACTIVE_ED_SEED`（不配紧凑码）完全可用；一个环境变量密钥都不配也行，直接在网页里添加 APP。没有任何 APP 时生成按钮不可用并提示去“APP 管理”添加（不会崩溃退出）；只有 `ADMIN_PASSWORD` 缺失/太弱才会拒绝启动。

## APP 管理（添加新 APP，例如 CarMediaBridge）

“APP 管理”页（`/apps`）：列表显示每个 APP 的名称、slug、产品号、**公钥（可随时复制）**、来源，并可编辑（名称/slug/产品号）和删除。公钥创建后不可改（换密钥请新建 APP）。**每个 APP 的公钥必须唯一**，重复的公钥/slug/名称会被拒绝。

**为什么需要私钥种子**：Ed25519 的私钥**不能**由公钥推出来，而生成激活码必须用私钥签名——只有公钥是出不了码的。所以添加 APP 时有两种方式（表单里二选一）：

1. **自动生成密钥对（推荐）**：服务器生成新的密钥对，把私钥种子存进数据卷（`data/seeds/<id>.seed`，权限 0600；设了 `FFF_ACTIVE_STORE_KEY` 则 AES-256-GCM 加密），页面只显示**公钥**和“复制公钥”按钮。把公钥填进该 APP 的 APK 构建参数即可。
2. **手动输入公钥 + 私钥种子**：你已经有一对密钥（比如 APK 已经按某个公钥发布了）。一次性提交公钥和对应的种子（种子框是 password 类型，不回显），服务器核对“**种子推出的公钥 = 你填的公钥**”，对不上就拒绝（且不泄漏任何一方的值），通过后同样存进数据卷。

两种方式下，**种子创建后都不会再在任何页面/接口中显示**。表单里还有**产品号**（1–255，默认 1 = zFloatWindow 现用的值）：它是签名消息的一部分（`"fff-active/v2/ed|" + 产品号(1字节) + VIN`），必须和该 APK 里写死的一致；CarMediaBridge 用 **2**。

接入 CarMediaBridge 的步骤：

1. 登录网页 → APP 管理 → 添加：名称 `CarMediaBridge`，slug `carmediabridge`，产品号 `2`，选“自动生成密钥对” → 复制公钥。
2. 用公钥构建 APK：`package_custom_id.sh --pubkey <公钥> …`（或 `./gradlew assembleRelease -PlicensePubKeyHex=<公钥>`，详见 CarMediaBridge `docs/LICENSING.md`）。
3. 生成激活码页面：选 CarMediaBridge → 输入车辆 VIN → 生成 → 复制 → 用户粘贴到 CarMediaBridge 的激活卡片。

## 使用（生成激活码）

1. 用户在 APP 的激活卡片里看到 **VIN**（读不到时显示 **机器码** `MC-XXXX-XXXX-XXXX-XXXX`），发给你。
2. 你在网页里**选择 APP**，粘贴 VIN / 机器码（页面即时检查格式：VIN 必须 17 位、大写字母数字、不含 I/O/Q），点“生成激活码”，点“复制”。（只有默认 APP 且配了 `FFF_ACTIVE_SECRET` 时才出现“紧凑码”选项。）
3. 把码发给用户；用户粘贴到 APP 里点“激活”。激活码与 VIN（或机器码）和 **APP（公钥+产品号）** 绑定：换一辆车、或拿别的 APP 的码都用不了。
4. “历史记录”链接可看最近 200 条（时间、**APP 名称**、slug、类型、VIN、码、来源 IP；升级前的旧记录没有 APP 两列，格式不同）。

命令行也可以出码：

```bash
FFF_ACTIVE_ED_SEED=<64位hex> python -m fffactive.cli LSJA24U62JG269181          # 标准码
FFF_ACTIVE_SECRET=<64位hex>  python -m fffactive.cli LSJA24U62JG269181 mac      # 紧凑码
FFF_ACTIVE_ED_SEED=<64位hex> python -m fffactive.cli --pubkey                   # 打印默认 APP 公钥
DATA_DIR=data python -m fffactive.cli --list                                    # 列出网页里添加的 APP（名称/slug/产品号/公钥）
DATA_DIR=data python -m fffactive.cli --app carmediabridge LSJA24U62JG269181    # 用该 APP 的密钥+产品号出码
DATA_DIR=data python -m fffactive.cli --app carmediabridge --pubkey
```

示例（**仅示意**：公开的测试密钥 + 测试 VIN `LSJA24U62JG269181`，不是真实密钥）：

```
标准码（86）：n2Xux9Ht302nhl1yyLJta1EJn67hDI9NHZ5Q2D9gZBfOlCiFPf5qSbcO_NijvQVkuuXv5CXexbsi_zpPXtNfCA
紧凑码（23）：I754G-OQF2J-OZ3N4-WUZDA
```

## 测试

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -t . -v
```

- `test_codec.py`：两种码的往返/格式/确定性、容错输入、错 VIN/错产品号/错密钥、逐字符篡改、类型不被支持、VIN 校验、测试向量复现。
- `test_apps.py`：APP 存储（自动生成/手动导入、种子与公钥必须配对、唯一性校验、种子文件 0600 且不进 apps.json、静态加密、改名/删除、环境变量默认 APP 迁移且种子不落盘）、网页 API（CRUD、CSRF、鉴权、任何页面/接口都不出现种子）、按 APP 出码且历史记录含 APP 名、**默认 APP 的码与改动前提交的 `vectors.tsv` 逐字符一致**并符合 zFloatWindow 的消息格式、多 worker 共享数据卷、CLI。
- `test_cross_carmediabridge.py`：把 CarMediaBridge 的 `ActivationCodec.java` + `Ed25519.java` 原样编译（`CMB_SRC` 或默认 `../CarMediaBridge/...`，找不到用 `tests/java/vendor/` 拷贝，两者都有时断言逐字节相同），与本生成器**双向**校验（产品号 2，抛弃型测试密钥）：网页里的 CarMediaBridge APP 条目出的码 APK 侧验过、换 VIN/换产品号/篡改/大小写/别的密钥必须失败；APK 侧签的码 Python 验过且逐字符相同；静态向量 `tests/vectors_carmediabridge.tsv`（见 [docs/CARMEDIABRIDGE_VECTORS.md](docs/CARMEDIABRIDGE_VECTORS.md)）。
- `test_web.py`：登录、默认 APP 公钥显示（且不泄漏私钥/紧凑码密钥）、环境变量种子无效时的错误横幅（缺失不再是错误）、只配种子可用、CSRF 头、两种模式生成的码都能被 codec 校验、模式未配置时拒绝、非法 VIN、弱密码拒绝启动。
- `test_cross_java.py`：把 zFloatWindow 里的 `ActivationCodec.java` + `Ed25519.java`（APK 实际用的类）原样编译，和 Python **互相**校验：Python 出的 Ed25519/HMAC 码 Java 验、Java 出的紧凑码 Python 验、测试向量、**RFC 8032 官方 Ed25519 向量**、篡改/换 VIN/换产品号/换私钥必须失败。需要 `javac`，并通过 `ZFW_SRC` 指向 APK 源码目录（默认找 `../zFloatWindow/app/src/main/java/com/fff/zfloatwindow`），找不到就跳过。

## 安全说明（请读）

- **标准码（Ed25519）**：私钥只在本服务，APK 里只有公钥，提取 APK 也无法造码——这是默认和推荐。代价是码长 86 字符，需要复制粘贴（页面有“复制”按钮），Android 9 的 JCE 没有 Ed25519，所以 APK 内置了一个纯 Java 验签实现（已用 RFC 8032 向量和 Python 交叉验证）。
- **紧凑码（HMAC）**：对称密钥必须同时放在 APK 里。APK 里的密钥做了拆分+掩码混淆，但这只是提高门槛，**有逆向能力的人能把密钥提出来并自己造码**。想要“短码”就要接受这个权衡；只用 `ed` 模式构建的 APK 里没有任何对称密钥。
- 真实密钥只放在服务器的 `.env` 和你本机构建 APK 的未入库文件里。`.env`、`data/`、`secrets/` 已在 `.gitignore`。**私钥泄漏 = 任何人都能造码**；泄漏后只能换密钥并重新发版（旧码全部作废）。
- 网页用 HTTP Basic 登录，**务必放在 HTTPS 反向代理后面**（Caddy/Nginx），否则密码明文传输。登录失败有 0.5 s 延迟；生成接口要求自定义请求头防 CSRF。
- `data/` 里有**所有 APP 的私钥种子**（`seeds/`）、VIN 和码：务必保护并备份。种子文件 0600（容器内 uid 10001 才能读）；建议设置 `FFF_ACTIVE_STORE_KEY` 加密。数据卷丢失 = 这些 APP 无法再出码。
- 同一个 VIN 每次生成的码相同；本服务没有“吊销”（离线方案做不到）。
- 离线方案无法阻止“同一个码被用在同一辆车的多台设备”之外的复制，但码绑定 VIN，换车无效。
