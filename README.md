# fff_active：zFloatWindow 激活码生成器

给 zFloatWindow（≥0.7.0）生成**离线永久激活码**的小网页服务。输入车辆 VIN（或 APP 显示的机器码）→ 生成激活码 → 发给用户，用户粘贴到 APP 设置页的“授权”卡片点“激活”即可，**APP 全程不联网**。激活码与 VIN 绑定，永久有效；清数据/重装后用同一个码可以再次激活。

- **两种码，可选**（详见 [SPEC.md](SPEC.md)）：

  | 类型 | 长度 | 防伪造 | 说明 |
  |---|---|---|---|
  | **标准码（Ed25519，默认）** | **86 字符**（无分隔符，区分大小写） | **强**：私钥只在本服务，APK 里只有公钥 | 提取 APK 也造不了码 |
  | **紧凑码（HMAC）** | **20 字符**（显示 23 字符 `XXXXX-XXXXX-XXXXX-XXXXX`） | **弱**：对称密钥必须编进 APK | 短、好发；有逆向能力的人能提出密钥自己造码；APK 要用 `-PfffActiveMode=mac`（或 `both`）构建 |

- 码里**不含 VIN 和时间**，同一 VIN 每次生成结果相同（确定性）。
- 不需要数据库；可选的历史记录写在 `data/history.log`。
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
# 4) 登录后页面最下方的“Ed25519 公钥”就是构建 APK 要的 FFF_ACTIVE_ED_PUBLIC，点“复制公钥”即可（无需命令行）
```

### NAS 图形界面部署（群晖 Container Manager / 威联通 / 飞牛 / Portainer 等）
不需要命令行，也不需要 `docker compose`：

1. 获取镜像：在 NAS 的 Docker 界面里用本仓库构建镜像（Dockerfile 在仓库根目录；多数 NAS 支持“从 Git/Dockerfile 构建”，或先在任意电脑上 `docker build` 后导出再导入）。
2. 创建容器，**端口**：容器端口 `8080` → 映射一个 NAS 上的端口（例如 8080）。
3. **环境变量**（在 NAS 容器界面的“环境变量/Environment”里逐条填；值不要加引号）：
   - `FFF_ACTIVE_ED_SEED`：64 位十六进制私钥种子（必填）。
   - `ADMIN_PASSWORD`：登录密码，至少 8 位（必填）。
   - `ADMIN_USER`：可选，默认 `admin`。
   - `FFF_ACTIVE_SECRET`：可选，只有要“紧凑码”才填；不要就别建这一项或留空。
4. **卷（存储空间）不是必须的**：不挂卷也能正常出码，只是“历史记录”在容器重建后会丢。想保留历史就把一个 NAS 目录挂到容器的 `/data`（该目录需要容器内用户 uid 10001 可写）。
5. 启动容器，浏览器打开 `http://NAS地址:映射端口`，输入用户名/密码。**页面上会直接显示 Ed25519 公钥**（带“复制公钥”按钮）——把它填进 APK 构建的 `FFF_ACTIVE_ED_PUBLIC`。
6. 如果页面顶部出现**红色提示**，说明环境变量没设对（例如没填 `FFF_ACTIVE_ED_SEED`，或不是 64 位十六进制）；提示里只会写变量名和问题，不会显示任何值。按提示改好环境变量、重启容器即可。
7. **HTTPS**：网页用 HTTP Basic 登录，密码是明文传输的。如果要从外网访问，务必放在 HTTPS 反向代理后面（NAS 自带的反向代理/Caddy/Nginx 均可），不要把 8080 直接暴露到公网；只在内网用也建议别开端口转发。
8. 页面上只会显示**公钥**，私钥种子（`FFF_ACTIVE_ED_SEED`）和 `FFF_ACTIVE_SECRET` 在任何页面、接口、日志里都不会出现；请自己妥善保存私钥种子，丢了就只能换密钥、重新发版。

### 构建 APK 需要的东西（zFloatWindow 仓库）
- 标准码（默认 `ed` 模式）：构建时提供 `FFF_ACTIVE_ED_PUBLIC`（登录网页后页面上显示的公钥，64 位小写 hex，也可用 `python -m fffactive.cli --pubkey` 得到；它是公钥，不是秘密）。
- 紧凑码：`-PfffActiveMode=mac`（只认紧凑码）或 `both`，并提供与服务端相同的 `FFF_ACTIVE_SECRET`。
- 取值来源优先级：`-P<名字>` > 环境变量 > 文件（`-PfffActiveEnv=路径` / 环境变量 `FFF_ACTIVE_ENV` / `<仓库>/secrets/fff_active.env`，每行 `KEY=value`，该目录已 gitignore）。缺少所需密钥时构建直接失败。

### 环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `FFF_ACTIVE_ED_SEED` | 标准码必填 | Ed25519 私钥种子，64 位十六进制。**只放服务器**，不要进 APK、不要提交。缺失或格式不对时服务照常启动，但页面顶部显示红色错误提示、不能出码 |
| `FFF_ACTIVE_SECRET` | 紧凑码必填 | 64 位十六进制。和 APK 构建时用的是同一个值。留空则网页不提供紧凑码 |
| `ADMIN_PASSWORD` | 是 | 网页 HTTP Basic 登录密码，至少 8 位，不能是 `change-me` 之类（否则拒绝启动） |
| `ADMIN_USER` | 否 | 登录用户名，默认 `admin` |
| `DATA_DIR` | 否 | 历史记录目录，默认 `data`（Docker 里是 `/data`，compose 已挂载 `./data`） |

只配 `FFF_ACTIVE_ED_SEED`（不配紧凑码）完全可用。没有任何有效密钥时页面会显示红色提示并禁用生成按钮（不会崩溃退出，方便在 NAS 界面里排查）；只有 `ADMIN_PASSWORD` 缺失/太弱才会拒绝启动。

## 使用

1. 用户在 APP 设置页顶部“授权”卡片里看到 **VIN**（读不到时显示 **机器码** `MC-XXXX-XXXX-XXXX-XXXX`），发给你。
2. 你在网页里粘贴 VIN / 机器码（页面即时检查格式：VIN 必须 17 位、大写字母数字、不含 I/O/Q），选择码类型，点“生成激活码”，点“复制”。
3. 把码发给用户；用户粘贴到 APP 里点“激活”。激活码与 VIN（或机器码）绑定：换一辆车用不了。
4. “历史记录”链接可看最近 200 条（时间、类型、VIN、码、来源 IP）。

命令行也可以出码：

```bash
FFF_ACTIVE_ED_SEED=<64位hex> python -m fffactive.cli LSJA24U62JG269181          # 标准码
FFF_ACTIVE_SECRET=<64位hex>  python -m fffactive.cli LSJA24U62JG269181 mac      # 紧凑码
FFF_ACTIVE_ED_SEED=<64位hex> python -m fffactive.cli --pubkey                   # 打印公钥
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
- `test_web.py`：登录、公钥显示（且不泄漏私钥/紧凑码密钥）、密钥缺失/无效时的错误横幅、只配种子可用、CSRF 头、两种模式生成的码都能被 codec 校验、模式未配置时拒绝、非法 VIN、弱密码拒绝启动。
- `test_cross_java.py`：把 zFloatWindow 里的 `ActivationCodec.java` + `Ed25519.java`（APK 实际用的类）原样编译，和 Python **互相**校验：Python 出的 Ed25519/HMAC 码 Java 验、Java 出的紧凑码 Python 验、测试向量、**RFC 8032 官方 Ed25519 向量**、篡改/换 VIN/换产品号/换私钥必须失败。需要 `javac`，并通过 `ZFW_SRC` 指向 APK 源码目录（默认找 `../zFloatWindow/app/src/main/java/com/fff/zfloatwindow`），找不到就跳过。

## 安全说明（请读）

- **标准码（Ed25519）**：私钥只在本服务，APK 里只有公钥，提取 APK 也无法造码——这是默认和推荐。代价是码长 86 字符，需要复制粘贴（页面有“复制”按钮），Android 9 的 JCE 没有 Ed25519，所以 APK 内置了一个纯 Java 验签实现（已用 RFC 8032 向量和 Python 交叉验证）。
- **紧凑码（HMAC）**：对称密钥必须同时放在 APK 里。APK 里的密钥做了拆分+掩码混淆，但这只是提高门槛，**有逆向能力的人能把密钥提出来并自己造码**。想要“短码”就要接受这个权衡；只用 `ed` 模式构建的 APK 里没有任何对称密钥。
- 真实密钥只放在服务器的 `.env` 和你本机构建 APK 的未入库文件里。`.env`、`data/`、`secrets/` 已在 `.gitignore`。**私钥泄漏 = 任何人都能造码**；泄漏后只能换密钥并重新发版（旧码全部作废）。
- 网页用 HTTP Basic 登录，**务必放在 HTTPS 反向代理后面**（Caddy/Nginx），否则密码明文传输。登录失败有 0.5 s 延迟；生成接口要求自定义请求头防 CSRF。
- 历史记录文件里有 VIN 和码，注意保护 `data/`。
- 同一个 VIN 每次生成的码相同；本服务没有“吊销”（离线方案做不到）。
- 离线方案无法阻止“同一个码被用在同一辆车的多台设备”之外的复制，但码绑定 VIN，换车无效。
