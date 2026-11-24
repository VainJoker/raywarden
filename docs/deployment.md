# Raywarden：从零部署到首次使用

本文对应当前源码，更新于 2026-11-19。推荐通过 GitHub Actions 部署，默认使用 workers.dev，先跑通一个 V1 账户，再联调邮件、推送或 V2。操作对象是**新建的生产 D1 和 R2**；已有旧迁移历史的数据库不能直接照抄建库步骤。

## 先理解部署结果

浏览器的 Web Vault 和 Rust/WASM API 一起由 Cloudflare Worker 提供。D1 保存账户、密文和包装后的服务端签名密钥；独立 Worker Secret `KEY_ENCRYPTION_KEY` 用来解开签名密钥。R2 保存附件和文件 Send；notifydo 处理通知连接，heavydo 承担部分计算。你不需要准备 VPS、Node 服务、独立 SQLite 服务器或公开的 R2 下载站。

部署完成不等于已经创建账户。部署先建立表和服务，随后只有持有初始化令牌、使用配置邮箱的人才能创建白名单账户；主密码及客户端加密材料仍由 Bitwarden 客户端生成。

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
  "binding": "DB", // Worker 访问 D1 的绑定键
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

再生成一份独立的包装根密钥，例如：

```bash
node --input-type=module -e 'import { randomBytes } from "node:crypto"; console.log(randomBytes(32).toString("base64url"))'
```

它是 43 个字符，不带 `=` padding。先在独立安全位置备份，再保存为 `KEY_ENCRYPTION_KEY`。生产部署持续使用这份密钥，`wrangler.jsonc` 中 `env.local` 的公开开发值仅用于本地。丢失或更换生产密钥会让已包装的 JWT 密钥和 API Key 无法读取。

在 GitHub 仓库 **Settings → Environments** 新建 `production`，然后在该环境配置五个 Secrets（也可使用同名 repository Secrets；同名环境值优先）。当前 workflow 使用命名环境；私有仓库的环境功能需要支持它的 GitHub 计划，公开仓库也可使用；环境权限和保护规则以[GitHub 官方说明](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)为准：

| GitHub Secret | 填什么 | 用途 |
| --- | --- | --- |
| `CLOUDFLARE_API_TOKEN` | 上面的 API Token | workflow 访问 Cloudflare |
| `CLOUDFLARE_ACCOUNT_ID` | Account ID，32 位十六进制 | 明确选中账户，避免自动选择歧义 |
| `ALLOWED_EMAILS` | 完整邮箱列表，如 `owner@example.com,family@example.com`，支持逗号或换行 | 私密开户及改邮箱目标的白名单；不接受通配符或空条目 |
| `OWNER_SETUP_TOKEN` | 刚生成的随机值 | 授权首次开户 |
| `KEY_ENCRYPTION_KEY` | 独立生成的 32 字节 base64url 随机值 | 包装 D1 中的 JWT 根密钥，长期保留并独立备份 |

不要把这些值写到仓库或普通 GitHub Variables。前两个仅供部署工具使用；后三个通过临时 secrets-file 与 Worker 代码一起上传，Cloudflare 将它们保存为 Worker Secrets。文件不进入 artifact，成功或失败都会清理，这些应用 Secret 不进入 Wrangler 子进程环境；未提供的已有 Secret 会由 Wrangler 保留。[随代码上传 Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)

作用：解决“Worker 尚未创建，但部署又要求提前有 Secret”的首部署问题。无需先运行 `wrangler secret put`，也不用手工提供 `JWT_SECRET` / `JWT_REFRESH_SECRET`；服务端 JWT 密钥由空库首次请求生成，使用外部包装 key 加密后持久化到 D1。

## 第五步：执行首次 workflow

在五个 Secrets 和生产配置准备好后，把完整代码和新版工作流推入 `main`，再按下文[版本发布步骤](#使用版本-tag-发布)推送一个稳定版本 tag（例如 `v0.1.2`）。只推送 main 或手动运行 main 的 Integration 会检查和构建，不部署。

流水线依次执行：

| 阶段 | 做什么 | 为什么需要 |
| --- | --- | --- |
| Integration check | 格式、Rust/JS/SQL 测试及宿主机与 WASM 目标严格 clippy | 先发现源码和迁移回归 |
| release 构建 | 下载固定 Web Vault、Worker dry-run、workerd 回归及 Wrangler 原生 D1/R2 测试 | 验证产物可处理请求、全新建库、重复应用迁移时保留数据和附件替换清理 |
| artifact | 保存编译模块、Web Vault、锁文件及文件摘要 | 后续部署复用这一份已验证产物 |
| production 预检 | 验证本次提供的应用 Secrets 格式 | 在访问生产资源和迁移 D1 前发现配置错误 |
| production 资源检查 | 核对账户、D1 的 ID/名称及 R2 bucket | 发现误配时停止，不创建替代资源 |
| D1 migration | 原生 migrations apply，新库执行完整迁移链 `0001`–`0008` | 建立完整表、索引与约束，账户 verifier 默认成本为 600,000 |
| Worker 发布 | `--no-bundle` 上传产物，同时上传 Secrets | 不在部署阶段重复编译；DO 类迁移由 Wrangler 管理 |
| release health | 校验公开 `/api/alive` 的 RFC3339 时间戳及 `X-Raywarden-Release-Id` | 确认 Worker 和 D1 可用，且实际响应来自本次验证的产物 |

预期 Integration 的 check 和 deploy 都通过。Integration 中的 coverage 并行作业统计覆盖率，check 与 coverage 都成功后才允许部署；PR 只执行检查和构建，不部署。无需再配置一套 Cloudflare Git 仓库自动构建，否则一次推送可能被两条链路部署。

注意：稳定版本 tag 的 Integration 成功后会自动写生产 D1 并发布 Worker。如果给 GitHub `production` 环境设置了审核人，部署会按你设置的规则等待审核。

当前 `0001`–`0008` 迁移链用于建立新库结构。使用同一迁移历史的 D1 可追加待应用迁移。使用旧迁移历史的实例需准备新 D1 并安排数据转移。 [迁移说明](../sql/migrations/README.md)

## 第六步：创建私人账户

1. 打开刚部署的 `https://<你的入口>/setup`。必须从你实际使用的同一入口开始，别在 workers.dev 和自定义域名之间切换。
2. 在页面中输入第四步的 `OWNER_SETUP_TOKEN`。页面通过同源 POST 发送，不把令牌放进 URL。
3. 白名单中仍有未注册邮箱且授权通过后，浏览器得到约 10 分钟有效的 HttpOnly、SameSite=Strict 初始化 cookie，跳转到 Web Vault 的 `/#/signup`。
4. 使用 `ALLOWED_EMAILS` 中配置的邮箱，在客户端设置强主密码并完成注册。账户加密密钥由客户端生成，不能通过手工 SQL 插入用户替代。
5. 注册成功后正常登录。为其他账号开户时，把其完整邮箱加入白名单，再重新通过 `/setup` 授权。账号之间独立隔离，数据库拒绝重复邮箱。普通访客的 `/api/config` 一直声明关闭注册。

作用：把“部署者授权开户”和“使用主密码加密保险库”分开。隐藏按钮或只校验邮箱都无法证明开户者是你。初始化 cookie 仅授权开户，不能当作 API access token。超时未完成时重新访问 `/setup`；完成开户后令牌不具备登录、改密或解密能力。

首次部署保持 `REQUIRE_EMAIL_VERIFICATION=false`，不需要邮件通道。若主动开启邮件验证，必须先配置并验收投递服务，再按客户端要求完成验证码。固定 Web Vault 已更新为 `2026.10.1`，隔离环境的 V1/V2 开户与解密均已验收；V2 注册仍需显式选择对应 feature flag，不会迁移后自动启用。V2 账户要求普通客户端 `2026.10.1+`、桌面端 `2026.10.2+`，强制升级等未支持 flag 继续关闭。

可以在完成开户后移除 GitHub 中的 `OWNER_SETUP_TOKEN`，并在 Cloudflare 删除同名 Worker Secret，停止签发新的初始化授权。此前签发的授权最多再有效 10 分钟；白名单变更会立即使旧 Cookie 失效，已有账户的登录不受影响。删除 Worker Secret 会立即产生部署；这是可选运维操作，不是登录所需步骤。保留 `ALLOWED_EMAILS`、`KEY_ENCRYPTION_KEY` 和 D1 的 `jwt_keys`，不要用删表或删密钥的方式“重置”实例。

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
4. 在无痕窗口确认未通过 `/setup` 授权时无法注册，名单中已有账户的地址无法重复注册。

这些操作才构成你这套云端环境的基础验收。仓库内自动测试使用隔离 workerd/SQLite 和模拟 R2、外部通道，不会替你证明真实浏览器、远程 D1、DNS、扩展或外发邮件已通过。

隔离浏览器与 workerd 的验收范围见[客户端兼容说明](architecture.md#客户端兼容范围)。

## 更新、重试与备份

日常更新先推送代码，再推送新的稳定版本 tag，走同一 Integration → artifact → production 链路。从 `0009_*.sql` 开始追加后续迁移，保留已应用文件。`sql/schema.sql` 用于查看结构。后续未提供邮箱或初始化令牌环境值时，现有 Worker Secret 保留，`DOMAIN` 每次根据选定入口更新。

当前新基线直接定义逐账户验证成本，不执行历史成本回填。新注册和凭据修改使用至少 600,000 次；旧账户在正确密码与所需二次验证通过后条件升级，不撤销现有会话。**一旦写入新成本，不能回退到仍固定按 100,000 次读写的旧 Raywarden 二进制**，否则可能无法登录或写入不匹配的 verifier。需要回退时使用识别 `password_iterations` 的版本；若只能恢复更旧实现，须连同匹配的完整 D1/R2 备份恢复并评估此后数据变化。当前 workflow 没有版本倒退拦截；需要恢复时应制定独立恢复方案，先确认旧版本与数据库兼容。

需要改邮箱时，先更新部署用的 `ALLOWED_EMAILS` 为新目标并部署，再在已登录客户端完成改邮箱及验证；现有改邮箱接口同样检查白名单。只改 Secret 不会改名或覆盖账户，也不会绕过主密码和密钥重包裹。

若 check 与 coverage 成功、部署阶段失败，修正权限或 Secrets 后，在 **Actions → Integration → 原 tag 的运行**中选择 **Re-run failed jobs**，复用同次运行已验证的产物，不重编译。Cloudflare 仅通过 `workflow_call` 被 Integration 调用，没有独立 Run workflow 按钮，也不接受 tag/run ID 输入。重试使用原运行的 commit 与产物，不再查询 tag 当前指向、main 祖先关系或生产版本历史。产物保留 14 天，过期后在原运行中选择 **Re-run all jobs** 重建。源码或配置需要修复时，合入 main 后发布新版本，不能移动旧 tag 或混用新配置与旧产物。

### 使用版本 tag 发布

main 的 push 与 PR 只执行 CI，其他分支不配置独立的 push 工作流，提交消息不参与部署判断。推送稳定的 `vX.Y.Z` tag 后，Integration 对 tag 对应 commit 重新执行完整检查和构建，通过后调用同一 commit 的 Cloudflare 工作流，复用本次产物。workflow 使用 `v[0-9]*.[0-9]*.[0-9]*` glob 筛选 tag；它不是严格的稳定版本正则，`v1.2.3-rc.1` 等名称也可能匹配，因此仅推送 release-plz 生成的稳定版本 tag。[GitHub tag 触发规则](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#push)

发布前确认当前 commit 已合入 main，且 tag 版本与 `Cargo.toml` 的 `[package].version` 完全相同。例如仅当 Cargo 版本为 `0.1.2` 时执行：

```bash
git switch main
git pull --ff-only
git tag -a v0.1.2 -m "Release v0.1.2"
git push origin v0.1.2
```

版本号仅为示例，每次发布使用新的 tag；不要移动或覆盖已发布 tag。也可以通过 GitHub 创建 Release 时创建新 tag；本项目部署由 tag push 触发，不再同时监听 `release.published`，避免一份版本触发两次部署。为已存在的 tag 补写 Release 说明不会重新部署。

在 **Actions → Integration → 本次 tag 运行**中查看 check、coverage 和 Deploy to Cloudflare。main/PR 仍执行完整构建与 workerd 测试，仅 tag 运行记录并上传生产部署产物，普通分支不配置部署入口。已按项目选择删除专用 release-policy 脚本：不再额外校验严格版本格式、tag/Cargo 版本一致、tag 是否移动或 main 祖先关系；发布时通过上述操作约定与 release-plz 维护版本。

若 `production` 的 Deployment branches/tags 目前只允许 main，在 **Settings → Environments → production** 增加 Tag 类型的 `v*` 允许规则；不再需要为 main 或其他分支开放此部署流程的生产权限；失败重跑仍使用原 tag。已有审核规则继续生效。另建议为 `v*` 配置 tag ruleset，限制创建者并禁止更新/删除，避免版本名复用；这些 GitHub 设置需在仓库中配置，不会随 YAML 自动启用。[环境部署规则](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)

自动发布和失败重跑使用 `wrangler.jsonc` 中同一生产 Worker、D1 和 R2，并共用部署并发锁。Release-plz 与 Cloudflare 均设置 `cancel-in-progress: false` 和 `queue: max`，最多保留 100 个等待项；check/coverage 则只保留同一 ref 最新的检查。队列按进入等待的顺序处理，构建完成顺序不保证与版本顺序一致。[GitHub 并发说明](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)

部署锁只保证串行，不保证版本递增。已删除基于 GitHub production 部署历史的降级和同版本换 SHA 拦截，也移除了对应 `deployments: read` 权限；旧版本重跑可能覆盖新版本。仍保留 check/coverage gate、同次 artifact 与提交/摘要校验、迁移先于上传、健康检查和生产环境规则。

### 使用 release-plz 自动管理发布

已配置 `.github/workflows/release.yml` 与根目录 `release-plz.toml`。main push 或手动运行 main 的 Release-plz 时，先检查是否合并了发布 PR并创建对应版本，再创建或更新下一份发布 PR。它只安装一次固定版本 release-plz 0.4.3，再依次运行 `release` 与 `release-pr`；无需安装 Node、just 或 cargo-semver-checks 来运行此工作流，也不自动合并发布 PR。

日常流程：

1. 功能、修复等 PR 合入 main。推荐使用 `feat: ...`、`fix: ...` 等 Conventional Commits；采用 squash merge 时，以最终合并提交标题为准。
2. Release-plz 自动维护发布 PR 中的 `Cargo.toml`、`Cargo.lock` 和 `CHANGELOG.md`。审查版本号、更新日志及 CI 结果后合并。
3. main 上的 Release-plz 为合并的发布 PR 创建 `vX.Y.Z` tag 和 GitHub Release。
4. tag 自动触发 Integration，完整检查和构建成功后部署 Cloudflare；失败可按上文方式重试。GitHub Release 已创建不代表 Cloudflare 部署已成功，需查看 Integration 的部署结果。

配置使用 `git_only = true`，版本基线取自 Git tag，不查询同名 crates.io 包作为发布基线，也不执行 `cargo publish`；`Cargo.toml` 另外设为 `publish = false`。`release_always = false` 将自动打 tag 限制为合并发布 PR 后，普通 main 提交只更新发布 PR。`semver_check = false` 关闭 Rust 库 API 检查，实际兼容性继续由项目 CI 验证；依赖升级交给单独 PR，不随发布自动更新。[release-plz 配置说明](https://release-plz.dev/docs/config)

首次没有匹配 tag 时按初次发布处理，检查生成的首份发布 PR，不假定它一定从当前 `0.1.1` 增加版本。后续版本由 Cargo 版本和已发布 tag 管理；`package.json` 是私有 Node 部署工具清单，其版本不由 release-plz 同步，也不作为 Worker 发布版本。

启用前在 GitHub 配置：

- 创建仅授权当前仓库的 fine-grained PAT，赋予 **Contents: Read and write**、**Pull requests: Read and write**，保存为仓库级 Actions Secret `RELEASE_PLZ_TOKEN`。也可把具备同等权限的 GitHub App token 用于此 Secret，但短期 token 必须有自动刷新机制。不要放在仅 production 环境可用的 Secret 中，Release-plz 不使用该环境。
- 仓库组织策略须允许该 token 创建/更新 PR 和 tag；若版本 tag 有 ruleset，允许发布身份创建 tag，继续禁止覆盖和删除。发布 PR 保留正常审核与 CI。
- production 环境允许 `v*` tag 部署；重跑使用原 tag，不要求开放 main 部署权限。

默认 `GITHUB_TOKEN` 创建的 PR 与 tag 不会自动触发后续 PR CI 和 tag push CI，因此工作流明确要求 `RELEASE_PLZ_TOKEN`，缺失时直接提示配置，不静默回退。无需 `CARGO_REGISTRY_TOKEN`，也不授予 crates.io 发布权限。[release-plz Token 说明](https://release-plz.dev/docs/github/token)

手动 tag 发布入口仍可使用。自动发布只监听 main，不配置其他分支的 push 发布入口。后续若增加 staging，应使用独立 Worker/D1/R2；health 失败不能直接触发可能与 D1 不兼容的旧二进制回滚。

已有迁移会跳过，但手动重试仍可能执行新的待执行迁移、上传 Worker 并检查健康，**不会回滚数据库**。发布旧 Worker 版本同样不等于恢复旧 D1 结构。

开始存放正式密码前，先安排备份：完整 D1（包括 `jwt_keys`、迁移历史）与 R2 对象需要一致保留，备份按敏感材料加密存放，并演练恢复。当前项目没有完整的 D1+R2 自动备份/恢复链路；详见[备份现状与恢复边界](db-backup-recovery.md)。

| 失败位置 | 优先检查 |
| --- | --- |
| resources 提示 ID/名称不符 | 数据库是否属于目标账户、ID 与名称是否同一资源，勿新建同名资源掩盖误配 |
| workers.dev 子域名缺失 | 在账户 Workers & Pages 设置子域名；API Token 是否可读对应账户 Workers 设置 |
| first deploy 缺 ALLOWED_EMAILS | GitHub Secret 名称、production 环境、是否为空；不要改为公开注册绕过 |
| migration 报表已存在 | 是否误用了旧迁移历史库或手动导入过 schema；停止并制定数据迁移方案 |
| 旧迁移历史或表冲突 | 当前为不兼容旧历史的新基线；使用新数据库，不伪造迁移记录 |
| `/setup` 拒绝授权 | 令牌是否完整、白名单中是否有未注册地址、是否使用同一 origin、浏览器是否允许 Cookie |
| 页面可开但登录异常 | `/api/config` 地址、客户端版本、D1 日志；V2 客户端须满足最低版本，升级 verifier 后勿回退到固定成本的旧 Worker |
| workers.dev 健康检查403/1010 | 确认请求到达 Worker；平台的域名安全检查可能拦截自动客户端，必要时改用自定义域名 |

## 本地运行

本地开发直接运行：

```bash
just dev
```

仅启动开发服务时直接 `just dev`，无需先手动 setup 或 ui-download。它通过 `--env local --local` 选择 `wrangler.jsonc` 的 `env.local`，使用 `.wrangler/local` 保存本地状态。命令先按需准备 Node 依赖、Rust/WASM 工具链和固定 worker-build；前端版本与入口 HTML 可用时离线更新覆盖资源，缺失或不匹配时下载固定版本，随后迁移本地库并启动 `https://localhost:8787`。首次缺失项需要联网，任一步失败立即停止，不会访问生产 D1/R2。已有本地旧历史也不会自动清空或转换，发生迁移冲突时保留数据，改用全新工作副本/独立状态做新基线测试。

本地命令从 `wrangler.jsonc` 生成 Git 忽略的配置副本，并省略生产的密钥要求。编辑本地设置后重启 `just dev` 即可重新生成。本地 DOMAIN 和虚构邮箱 `owner@example.test` 已由 `env.local.vars` 提供，浏览页面、检查 API 不必创建环境文件。已有 `.dev.vars` 可继续使用。**首次创建本地账户**时，在 Git 忽略的 `.dev.vars` 中增加一个自己的随机值（已有文件只追加该项，不覆盖其他配置）：

```dotenv
OWNER_SETUP_TOKEN="替换为 openssl rand -hex 32 的输出"
```

重启 `just dev`，访问 `https://localhost:8787/setup`，输入相同值，使用 `owner@example.test` 注册。固定 Web Vault 拒绝 HTTP API（包括 localhost），本地配置用 `dev.local_protocol=https` 与同源 DOMAIN 配套。Wrangler 的本地开发证书需要浏览器仅针对 localhost 信任；也可用受本机信任的证书配置 Wrangler。生产使用平台正式证书，不使用该开发证书。本地密钥和数据库独立，不使用 GitHub/线上 Secrets。

## 工具与构建

本机先安装 `.node-version` 声明的 Node 24、rustup、`package.json` 中 `config.justVersion` 声明版本的 just，以及 Python 3.14，再运行 `just dev` 或 `just setup`。`rust-toolchain.toml` 由 rustup 原生读取，选择固定 nightly、rustfmt/clippy 与 WASM target；构建与依赖准备由 Justfile 负责。前端下载另需系统 Bash、curl、tar、find、awk。

同一份版本声明继续供 CI 使用。worker-build、cargo-llvm-cov 和 Wrangler 分别由现有 Justfile/Cargo/npm 安装流程管理。

`just setup` 复用 Justfile 的 `setup-node`、`setup-rust`、`setup-worker-build` 并执行 `cargo fetch --locked`。已就绪的依赖直接复用，缺失或过期时原生安装；setup-deploy 只准备 Node 依赖。Node 安装成功后才记录 package/lock 内容及 Node ABI 标记，重复检查时还验证 Wrangler 可运行；Rust 检查固定 channel、WASM target 与 rustfmt/clippy；worker-build 检查实际二进制版本。Justfile 优先使用原生 rustup 代理并清除继承的 `RUSTUP_TOOLCHAIN`，不修改用户默认工具链。worker SDK 0.9 对应 worker-build 0.9.0；Wrangler 固定 4.163.0，旧 workerd 不具备 SDK 所需 tracing API。首次 release 还会下载匹配的 wasm-bindgen、wasm-opt 和 esbuild，缓存位于 `.tools/cache`。

| 命令 | 行为 |
| --- | --- |
| `just ci` | 格式、JS/SQL/Rust 测试、WASM 检查、clippy；不部署 |
| `just ui` / `ui-offline` / `ui-download` / `ui-archive <文件>` | 按需下载准备 / 仅离线准备 / 强制下载固定 Web Vault / 从归档导入 |
| `just build` | release WASM 编译，不执行迁移或上传 |
| `just test-worker` | 对已编译 WASM 运行隔离 workerd 回归，不监听端口、无外网和应用数据 |
| `just test-d1` | 用临时 Wrangler 实例验证全新 D1 建库、重复迁移及 R2 文件生命周期 |
| `just schema` / `test-sql` | 从迁移生成结构快照 / 检查一致性及 SQL 行为 |
| `just db-migrate` | 默认 local，仅执行本地待迁移文件 |
| `just dry-run` / `artifact` / `artifact-check` | 生成生产 bundle / 记录摘要 / 校验摘要，不上传 |
| `just resources` / `health` | 使用部署凭据进行云端资源核对 / 公共健康检查 |
| `just deploy-preflight` / `deploy-health` | 校验本次提供的 Secrets / 校验公开健康响应和本次发布标识 |
| `just db-migrate production` / `deploy-worker` | 分别写入真实生产 D1 / 发布真实 Worker |
| `just deploy` | 构建、校验、资源检查、生产迁移、上传、健康检查的完整真实部署 |
| `just clean` | 清理生成产物和缓存，保留本地持久数据、环境文件、node_modules 及安装工具 |

本地手动部署通过受保护的进程环境提供与 GitHub 流程相同的部署变量和首次开户 Secret，再运行 `just deploy`。避免将值写入 shell 历史。更新依赖时用 `just lock` 或原生 Cargo/npm 命令，审查锁文件并重新运行检查。

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

只有本地与生产两套配置；不使用隐式 `WRANGLER_CONFIG` 选择迁移目标。三个 workflow 分别为 Integration、Release-plz 和 Cloudflare：Integration 并行检查与覆盖率，并构建；Release-plz 管理版本 PR/tag/Release；Cloudflare 仅部署同次运行的已验证产物。Dependabot 的 Mergify 自动合并规则显式要求 Integration 的 check 与 coverage 两个 GitHub Actions 检查成功；仓库 main 的 required checks 也应与这两个名称保持一致。普通可选配置、Secret 来源和展示开关见[运行配置表](runtime-config.md)，账户/存储/请求链路见[架构说明](architecture.md)。

`keep_vars: true` 暂时保留，避免删除 Dashboard 中尚未核对的普通变量；它不负责 Secret 转换。若已有同名普通 `DOMAIN` 或 `ALLOWED_EMAILS`，升级前核对并移除 Plaintext 冲突，确保仅维护 Secret 来源。本文的从零路径没有此冲突。
