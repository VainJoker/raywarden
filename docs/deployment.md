# Raywarden：从零部署到首次使用

本文对应当前源码，更新于 2026-11-18。推荐通过 GitHub Actions 部署，默认使用 workers.dev，先跑通一个 V1 账户，再联调邮件、推送或 V2。操作对象是**新建的生产 D1 和 R2**；已有旧迁移历史的数据库不能直接照抄建库步骤。

## 先理解部署结果

浏览器的 Web Vault 和 Rust/WASM API 一起由 Cloudflare Worker 提供。D1 保存账户、密文和服务端签名密钥；R2 保存附件和文件 Send；NotifyDo 处理通知连接，HeavyDo 承担部分计算。你不需要准备 VPS、Node 服务、独立 SQLite 服务器或公开的 R2 下载站。

部署完成不等于已经创建账户。部署先建立表和服务，随后只有持有初始化令牌、使用配置邮箱的人才能创建唯一账户；主密码及客户端加密材料仍由 Bitwarden 客户端生成。

## 第一步：准备仓库和 Cloudflare 账户

1. 将当前项目完整保存到你自己的 GitHub 仓库，启用 Actions。不要只上传 `src/`：三个 workflow、`.github/actions/setup/`、锁文件、脚本、SQL、前端覆盖源文件和 Wrangler 配置都要在仓库里。`build/`、`node_modules/`、`.tools/`、`.dev.vars` 和生成的 `static/web-vault/` 不需要提交。
2. 在 Cloudflare 选择实际部署使用的账户，记下 **Account ID**。以下 Worker、D1 和 R2 必须属于同一账户。
3. 在 **Workers & Pages** 中确认账户已配置 workers.dev 子域名。例如账户子域名是 `my-vault`、Worker 名是 `raywarden`，最终地址为 `https://raywarden.my-vault.workers.dev`。不需要提前创建一个空 Worker。[workers.dev 官方说明](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/)
4. 在 **R2** 页面完成账户开通流程，并查看当前套餐和用量规则；R2 需要订阅开通，包含免费用量，但超额用量可能收费。[R2 开通说明](https://developers.cloudflare.com/r2/get-started/)

作用：先确定资源所属账户和公网入口，避免部署时把资源绑定到另一个账户。当前方案可使用 workers.dev；长期使用自定义域名可减少地址变动，并避免更换地址影响 Passkey。

## 第二步：创建空数据库与私有存储桶

在 Cloudflare Dashboard 创建：

| 资源 | 示例名称 | 创建后记录 |
| --- | --- | --- |
| D1 数据库 | `warden-db` | 数据库名称和 Database ID（UUID） |
| R2 存储桶 | `warden-attachments` | bucket 名称 |

D1 此时保持空库，**不要导入 `sql/schema.sql`**。R2 保持私有，不启用公开访问，也不需要创建 S3 Access Key。应用通过 Worker binding 访问 R2，文件下载仍经过 API 授权。

作用：数据库迁移将在 workflow 中按顺序执行，Wrangler 同时维护迁移历史；快照只用于阅读和评审。资源需要自己先创建，项目的 `resources` 步骤只核对身份，不会自动创建或替换资源。[D1 入门](https://developers.cloudflare.com/d1/get-started/)

## 第三步：修改生产配置

编辑仓库根目录 `wrangler.jsonc`：

```jsonc
"name": "raywarden", // 你的 Worker 名；workers.dev 使用标准 DNS label
"workers_dev": true,
"d1_databases": [{
  "binding": "warden-db", // 保持代码使用的 binding 名
  "database_name": "warden-db", // 改成第二步创建的名称
  "database_id": "填入第二步的真实 UUID",
  "migrations_dir": "sql/migrations"
}],
"r2_buckets": [{
  "binding": "ATTACHMENTS_BUCKET", // 保持不变
  "bucket_name": "warden-attachments" // 改成第二步的真实名称
}]
```

以上只是需要核对的字段片段，保留文件里其他内容。尤其保留 DO binding、DO `migrations`、`assets.run_worker_first`、crons 和 `secrets.required`。资源名称可以自选，binding 名不能随意修改。不要沿用仓库中另一个账户的 Database ID。

当前生产不需要 `routes`。如果使用已经托管在 Cloudflare 的自定义域名，可额外配置：

```jsonc
"workers_dev": false,
"routes": [{ "pattern": "vault.example.com", "custom_domain": true }]
```

域名必须属于当前账户的有效 zone，不能与该 hostname 的已有 DNS 配置冲突。脚本目前只接受一个明确的 custom-domain 主机名。修改后部署工具会将其作为公共 origin；未配置路由时则查询账户 workers.dev 子域名。每次部署自动将这个 origin 写入 Worker 的 `DOMAIN` Secret，不需要 GitHub `DOMAIN` Secret，也不需要预先在 Dashboard 输入它。[Custom Domains 官方说明](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)

作用：让资源、健康检查、客户端公开地址和 Passkey 的 origin 指向同一个环境。`DOMAIN` 是完整 origin，例如 `https://vault.example.com`，不含 `/api`、其他路径、查询参数或凭据。域名是公开服务地址，存为 Secret 不会让域名对访客不可见。

## 第四步：配置部署凭据和所有者身份

在 Cloudflare 的 API Tokens 页面创建部署 Token。以官方 **Edit Cloudflare Workers** 模板为起点，限制为第二步所在账户，核对本项目实际需要的权限：

- Worker 创建/发布、设置、Secrets、定时任务和 DO：Workers 的编辑权限。
- D1：编辑权限；workflow 需要执行迁移，只有绑定权限不够。
- R2：至少允许读取 bucket 元数据供 `resources` 核对；模板的 Workers R2 Storage 权限可用于该路径。
- 使用自定义域名时，额外授予对应 zone 的 Workers Routes 编辑及 Zone 读取权限。

Cloudflare 的权限名称可能随界面更新，首次创建 Worker 的 Token 还必须覆盖“创建”操作，不能仅限于一个尚不存在的 Worker。不要使用 Global API Key。以[官方 Actions 配置](https://developers.cloudflare.com/workers/ci-cd/external-cicd/github-actions/)和[当前权限说明](https://developers.cloudflare.com/workers/authorization/workers/)为准；缺权限时按失败的资源检查项补充，不必授予全部账户权限。

生成独立的初始化令牌，例如在本地运行：

```bash
openssl rand -hex 32
```

将输出保存到密码管理器。它用于证明你有权初始化这个实例，**不是主密码**，不参与保险库加密。服务端接受 32–512 个字符，拒绝首尾空白和控制字符；推荐使用上述随机十六进制值。

在 GitHub 仓库 **Settings → Environments** 新建 `production`，然后在该环境配置四个 Secrets（也可使用同名 repository Secrets；同名环境值优先）。当前 workflow 使用命名环境；私有仓库的环境功能需要支持它的 GitHub 计划，公开仓库也可使用；环境权限和保护规则以[GitHub 官方说明](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)为准：

| GitHub Secret | 填什么 | 用途 |
| --- | --- | --- |
| `CLOUDFLARE_API_TOKEN` | 上面的 API Token | workflow 访问 Cloudflare |
| `CLOUDFLARE_ACCOUNT_ID` | Account ID，32 位十六进制 | 明确选中账户，避免自动选择歧义 |
| `ALLOWED_EMAILS` | 你的一个完整邮箱，如 `owner@example.com` | 初始化唯一所有者；不接受列表、通配符或空值 |
| `OWNER_SETUP_TOKEN` | 刚生成的随机值 | 授权首次开户 |

不要把这些值写到仓库或普通 GitHub Variables。前两个仅供部署工具使用；后两个通过临时 secrets-file 与 Worker 代码一起上传，Cloudflare 将它们保存为 Worker Secrets。文件不进入 artifact，成功或失败都会清理；未提供的已有 Secret 会由 Wrangler 保留。[随代码上传 Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)

作用：解决“Worker 尚未创建，但部署又要求提前有 Secret”的首部署问题。无需先运行 `wrangler secret put`，也不用手工提供 `JWT_SECRET` / `JWT_REFRESH_SECRET`；服务端 JWT 密钥由空库首次请求持久化到 D1。

## 第五步：执行首次 workflow

在四个 Secrets 和生产配置准备好后，把完整代码推入 `main`。也可进入 **Actions → Integration → Run workflow**，选择 `main` 手动触发。

流水线依次执行：

| 阶段 | 做什么 | 为什么需要 |
| --- | --- | --- |
| Integration check | 格式、Rust/JS/SQL 测试、WASM 检查和 clippy | 先发现源码和迁移回归 |
| release 构建 | 下载固定 Web Vault、Worker dry-run、真实 workerd 回归 | 确认发布产物可以加载和处理请求 |
| artifact | 保存编译模块、Web Vault、锁文件及文件摘要 | 后续部署复用这一份已验证产物 |
| production 资源检查 | 核对账户、D1 的 ID/名称及 R2 bucket | 发现误配时停止，不创建替代资源 |
| D1 migration | 原生 migrations apply，首次执行 `0001`–`0010` | 建立表、索引和迁移历史 |
| Worker 发布 | `--no-bundle` 上传产物，同时上传 Secrets | 不在部署阶段重复编译；DO 类迁移由 Wrangler 管理 |
| health | 请求所选公开入口的 `/api/alive` | 确认部署后的 Worker 和 D1 可用 |

预期 Integration 的 check 和 deploy 都通过。`coverage.yml` 单独统计覆盖率；PR 只执行检查和构建，不部署。无需再配置一套 Cloudflare Git 仓库自动构建，否则一次推送可能被两条链路部署。

注意：`main` 的 Integration 成功后会自动写生产 D1 并发布 Worker。如果给 GitHub `production` 环境设置了审核人，部署会按你设置的规则等待审核。

## 第六步：创建唯一账户

1. 打开刚部署的 `https://<你的入口>/setup`。必须从你实际使用的同一入口开始，别在 workers.dev 和自定义域名之间切换。
2. 在页面中输入第四步的 `OWNER_SETUP_TOKEN`。页面通过同源 POST 发送，不把令牌放进 URL。
3. 空库校验通过后，浏览器得到约 10 分钟有效的 HttpOnly、SameSite=Strict 初始化 cookie，跳转到 Web Vault 的 `/#/signup`。
4. 使用 `ALLOWED_EMAILS` 中配置的邮箱，在客户端设置强主密码并完成注册。账户加密密钥由客户端生成，不能通过手工 SQL 插入用户替代。
5. 注册成功后正常登录。账户已存在时，所有注册别名和初始化接口都会拒绝再建账户，数据库唯一索引也会阻止并发创建第二个账户。普通访客的 `/api/config` 一直声明关闭注册。

作用：把“部署者授权开户”和“使用主密码加密保险库”分开。隐藏按钮或只校验邮箱都无法证明开户者是你。初始化 cookie 仅授权开户，不能当作 API access token。超时未完成时重新访问 `/setup`；完成开户后令牌不具备登录、改密或解密能力。

首次部署保持 `REQUIRE_EMAIL_VERIFICATION=false`，不需要邮件通道。若主动开启邮件验证，必须先配置并验收投递服务，再按客户端要求完成验证码。不要打开当前 Web Vault 不兼容的 V2 注册或强制升级 flag：固定 Web Vault 为 `2026.7.0`，V2 账户要求普通客户端 `2026.10.1+`、桌面端 `2026.10.2+`。

可以在完成开户后移除 GitHub 中的 `OWNER_SETUP_TOKEN`，并在 Cloudflare 删除同名 Worker Secret，停止签发新的初始化授权。此前签发的授权最多再有效 10 分钟；只要已有账户，空库检查始终拒绝开户。删除 Worker Secret 会立即产生部署；这是可选运维操作，不是登录所需步骤。保留 `ALLOWED_EMAILS` 和 D1 的 `jwt_keys`，不要用删表或删密钥的方式“重置”实例。

## 第七步：验收基础功能

把下面的示例地址替换为实际入口：

```bash
vault_url='https://raywarden.my-vault.workers.dev'
curl --fail-with-body -sS -w '\nHTTP %{http_code}\n' "$vault_url/api/alive"
curl --fail-with-body -sS -w '\nHTTP %{http_code}\n' "$vault_url/api/config"
curl -sS -o /dev/null -w 'Unauthenticated sync: HTTP %{http_code}\n' "$vault_url/api/sync"
```

预期 alive/config 为 200，未登录的 sync 为 401。config 的 `environment.api`、`identity`、`vault` 都应指向同一个公网入口。alive 只证明 Worker 与数据库可查询，不代表登录、解密或附件已经验收。

随后在浏览器完成实际使用检查：

1. 登录，创建文件夹和一个测试登录项，保存后刷新并解锁，确认能读取原内容。
2. 在扩展中选择自托管环境，服务器地址填写入口 origin（不加 `/api`），使用同一账户登录；双向修改并手动同步。
3. 如需附件、Send 或 2FA，分别上传下载测试文件、创建与访问测试 Send、启用 TOTP 后登出重登，并保存恢复码。涉及邮件、Telegram、企业微信或移动推送的功能需单独配置并验收真实投递。
4. 在无痕窗口确认普通注册无法创建账户，`/setup` 也不能再次开户。

这些操作才构成你这套云端环境的基础验收。仓库内自动测试使用隔离 workerd/SQLite 和模拟 R2、外部通道，不会替你证明真实浏览器、远程 D1、DNS、扩展或外发邮件已通过。

本轮另用真实 Chromium、固定 Web Vault 和临时 HTTPS Worker 验证了开户、登录、创建登录项、刷新解锁、退出重登，并逐值确认原用户名和密码能正确解密。固定前端退出时出现过短暂的空账户/organizations 控制台错误，随后正常回到登录页，重登与数据读取通过；作为前端兼容问题保留记录。该测试使用临时本地 D1/R2，不是你的云端验收。

## 更新、重试与备份

日常更新推送 `main`，走同一 Integration → artifact → production 链路。后续 SQL 从 `0011_*.sql` 追加，不修改已经应用的文件。`sql/schema.sql` 不参与部署。后续未提供邮箱或初始化令牌环境值时，现有 Worker Secret 保留；`DOMAIN` 每次根据选定入口更新。

需要改邮箱时，先更新部署用的 `ALLOWED_EMAILS` 为新目标并部署，再在已登录客户端完成改邮箱及验证；现有改邮箱接口同样检查白名单。只改 Secret 不会改名或覆盖账户，也不会绕过主密码和密钥重包裹。

若 check 成功、部署阶段失败，修正权限或 Secrets 后可进入 **Actions → Deploy to Cloudflare → Run workflow**：选择来源分支，填写原 Integration URL `/actions/runs/<run_id>` 中的数字。来源必须是同仓库、同一所选分支、已完成且最新 check 成功的 Integration；整个运行因 deploy 失败而显示失败也可重试。产物保留 14 天，过期需重新运行 Integration。配置或源码变动则重新构建，不能拿旧产物搭配新配置上传。

### 在 feat 分支请求部署

默认分支尚无工作流时，使用提交标记：`main` 保持自动部署；`feat` 与 `feat/**` 的普通 push 只检查，**这次 push 的最后一个提交消息以 `[deploy]` 开头**时，Integration 检查成功后调用同一 commit 的 `cloudflare.yaml`，部署本次产物。相对路径复用工作流取调用者的同一 commit，因此这条路径可直接从 feat 分支运行。[GitHub 复用规则](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)

1. 将本次 workflow 改动提交到 feat 分支，部署请求使用例如 `[deploy] test feat deployment` 作为提交消息，再推送。
2. 打开 **Actions → Integration → 本次 feat 运行**，等待 check 完成，随后在运行详情中查看 **Deploy to Cloudflare** 作业。这里查看的是 Integration 调用的部署作业。
3. 若代码已经提交，可在当前 feat 分支用空提交发起一次新请求：

```bash
git commit --allow-empty -m "[deploy] test feat deployment"
git push origin HEAD
```

空提交会为新的 SHA 执行完整 CI。标记匹配不区分大小写，但须从消息第一个字符开始；多个提交一起推送时，以最后一个提交为准。保持 CI 启用，不同时使用 `[skip ci]` 等跳过标记。检查或产物上传失败时不会进入部署；部署失败可在该次 Integration 运行中重试失败的作业。

若 `production` 环境的 Deployment branches/tags 只允许 main，在仓库 **Settings → Environments → production** 中把对应 feat 分支加入允许列表；已有审批规则继续生效。[环境部署分支规则](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)

默认分支将来包含 `workflow_dispatch` 工作流后，仍可使用按钮入口：先取得同分支已完成且 check 成功的 Integration run ID，再进入 **Actions → Deploy to Cloudflare → Run workflow**，Branch 选择同一 feat 分支并填写 `run_id`。[GitHub 手动运行说明](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)

两种入口都使用 `wrangler.jsonc` 中的生产 Worker、D1 和 R2。所有分支共用部署并发锁；每次检出并校验指定 Integration 的 commit 与产物，分支后来有新提交不会替换已选产物。

已有迁移会跳过，但手动重试仍可能执行新的待执行迁移、上传 Worker 并检查健康，**不会回滚数据库**。发布旧 Worker 版本同样不等于恢复旧 D1 结构。

开始存放正式密码前，先安排备份：完整 D1（包括 `jwt_keys`、迁移历史）与 R2 对象需要一致保留，备份按敏感材料加密存放，并演练恢复。当前项目没有完整的 D1+R2 自动备份/恢复链路；详见[备份现状与恢复边界](db-backup-recovery.md)。

| 失败位置 | 优先检查 |
| --- | --- |
| resources 提示 ID/名称不符 | 数据库是否属于目标账户、ID 与名称是否同一资源，勿新建同名资源掩盖误配 |
| workers.dev 子域名缺失 | 在账户 Workers & Pages 设置子域名；API Token 是否可读对应账户 Workers 设置 |
| first deploy 缺 ALLOWED_EMAILS | GitHub Secret 名称、production 环境、是否为空；不要改为公开注册绕过 |
| migration 报表已存在 | 是否误用了旧迁移历史库或手动导入过 schema；停止并制定数据迁移方案 |
| 0010 唯一索引失败 | 已有多个用户；数据保留，先审查账户来源，不自动删除或合并 |
| `/setup` 拒绝授权 | 库是否已开户、令牌是否完整、配置邮箱是否单一、是否使用同一 origin、cookie 是否允许 |
| 页面可开但登录异常 | `/api/config` 地址、客户端版本、D1 日志；V2 账户不要使用固定旧版 Web Vault |
| workers.dev 健康检查403/1010 | 确认请求到达 Worker；平台的域名安全检查可能拦截自动客户端，必要时改用自定义域名 |

## 本地运行

本地开发直接运行：

```bash
just dev
```

仅启动开发服务时直接 `just dev`，无需先手动 setup 或 ui-download。它使用 `wrangler.local.jsonc`、`--local` 和 `.wrangler/local`，先按需准备 Node 依赖、Rust/WASM 工具链和固定 worker-build；前端版本与入口 HTML 可用时离线更新覆盖资源，缺失或不匹配时下载固定版本，随后迁移本地库并启动 `https://localhost:8787`。首次缺失项需要联网，任一步失败立即停止，不会访问生产 D1/R2。已有本地旧历史也不会自动清空或转换，发生迁移冲突时保留数据，改用全新工作副本/独立状态做新基线测试。

本地 DOMAIN 和虚构邮箱 `owner@example.test` 已由 vars 提供；浏览页面、检查 API 不必创建环境文件。**首次创建本地账户**时，在 Git 忽略的 `.dev.vars` 中增加一个自己的随机值（已有文件只追加该项，不覆盖其他配置）：

```dotenv
OWNER_SETUP_TOKEN="替换为 openssl rand -hex 32 的输出"
```

重启 `just dev`，访问 `https://localhost:8787/setup`，输入相同值，使用 `owner@example.test` 注册。固定 Web Vault 拒绝 HTTP API（包括 localhost），本地配置用 `dev.local_protocol=https` 与同源 DOMAIN 配套。Wrangler 的本地开发证书需要浏览器仅针对 localhost 信任；也可用受本机信任的证书配置 Wrangler。生产使用平台正式证书，不使用该开发证书。本地密钥和数据库独立，不使用 GitHub/线上 Secrets。

## 工具与构建

本机需要 rustup、Node.js 22.13+、npm 10+、Bash、just、Python 3；前端下载另用 curl、tar、find、awk。CI 使用 `.node-version` 固定的 Node 24，并安装 package.json 固定的 just。`rust-toolchain.toml` 管理 nightly、rustfmt/clippy 和 `wasm32-unknown-unknown` target，Rustup 会按文件安装 target，不只 `just setup` 能配置它。

`just setup` 复用 Justfile 的 `setup-node`、`setup-rust`、`setup-worker-build` 并执行 `cargo fetch --locked`。已就绪的依赖直接复用，缺失或过期时原生安装；setup-deploy 只准备 Node 依赖。Node 安装成功后才记录 package/lock 内容及 Node ABI 标记，重复检查时还验证 Wrangler 可运行；Rust 检查固定 channel、WASM target 与 rustfmt/clippy；worker-build 检查实际二进制版本。Justfile 优先使用原生 rustup 代理并清除继承的 `RUSTUP_TOOLCHAIN`，不修改用户默认工具链。worker SDK 0.9 对应 worker-build 0.9.0；Wrangler 固定 4.163.0，旧 workerd 不具备 SDK 所需 tracing API。首次 release 还会下载匹配的 wasm-bindgen、wasm-opt 和 esbuild，缓存位于 `.tools/cache`。

| 命令 | 行为 |
| --- | --- |
| `just ci` | 格式、JS/SQL/Rust 测试、WASM 检查、clippy；不部署 |
| `just ui` / `ui-offline` / `ui-download` / `ui-archive <文件>` | 按需下载准备 / 仅离线准备 / 强制下载固定 Web Vault / 从归档导入 |
| `just build` | release WASM 编译，不执行迁移或上传 |
| `just test-worker` | 对已编译 WASM 运行隔离 workerd 回归，不监听端口、无外网和应用数据 |
| `just schema` / `test-sql` | 从迁移生成结构快照 / 检查一致性及 SQL 行为 |
| `just db-migrate` | 默认 local，仅执行本地待迁移文件 |
| `just dry-run` / `artifact` / `artifact-check` | 生成生产 bundle / 记录摘要 / 校验摘要，不上传 |
| `just resources` / `health` | 使用部署凭据进行云端资源核对 / 公共健康检查 |
| `just db-migrate production` / `deploy-worker` | 分别写入真实生产 D1 / 发布真实 Worker |
| `just deploy` | 构建、校验、资源检查、生产迁移、上传、健康检查的完整真实部署 |
| `just clean` | 清理生成产物和缓存，保留本地持久数据、环境文件、node_modules 及安装工具 |

本地手动部署需要在受保护的进程环境中提供同样四个 Secrets，再运行 `just deploy`；不要把值作为 shell 参数写入历史。推荐使用上述 GitHub 流程，避免维护第二套发布方式。主动更新依赖用 `just lock` 或原生 Cargo/npm，审查真实锁文件并重新跑完整检查；setup/CI 不会替你重写锁。

## 目录与脚本职责

| 文件/目录 | 职责 |
| --- | --- |
| `Justfile` | 命令编排、工具安装、测试、构建和明确的本地/生产选择 |
| `scripts/deploy.mjs` | 配置/资源检查、入口解析、artifact 摘要、临时 Secrets 和已编译产物上传 |
| `scripts/prepare-ui.sh` | 下载/离线/归档准备前端，暂存校验后整体替换生成目录 |
| `scripts/patch-ui.mjs` | 检查固定前端版本、幂等修改 HTML 入口 |
| `static/overrides/` | 源管理的 CSS/JS 覆盖；`static/web-vault/` 是生成结果 |
| `sql/migrations/` | 唯一建库/升级来源；`schema.sql` 是派生结构快照 |
| `.tools/` | 项目安装工具与缓存，非运行服务 |
| `build/index.js` | worker-build 生成的 WASM 加载入口，非手写 Node 后端 |

## 部署环境与工作流

只有本地与生产两套配置；不使用隐式 `WRANGLER_CONFIG` 选择迁移目标。三个 workflow 保持为 Integration、Coverage 和 Cloudflare：前者检查并构建，Coverage 单独报告，Cloudflare 只部署已验证产物。普通可选配置、Secret 来源和展示开关见[运行配置表](runtime-config.md)，账户/存储/请求链路见[架构说明](architecture.md)。

`keep_vars: true` 暂时保留，避免删除 Dashboard 中尚未核对的普通变量；它不负责 Secret 转换。若已有同名普通 `DOMAIN` 或 `ALLOWED_EMAILS`，升级前核对并移除 Plaintext 冲突，确保仅维护 Secret 来源。本文的从零路径没有此冲突。

本轮只修改和验证仓库代码，没有替你创建资源、执行生产迁移、上传 Secret 或发布线上实例。
