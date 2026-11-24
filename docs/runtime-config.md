# Raywarden 运行配置表

本文列出运行时读取的配置、默认值和限制。工具安装、发布与健康检查见[部署指南](deployment.md)。

## 1. 已确定的产品与账户策略

| 项目 | 对齐后的约定 | 当前状态 |
| --- | --- | --- |
| 使用范围 | 个人及小范围自用，多账户、每账户多设备 | 同邮箱唯一；账号数据独立，不增加组织或管理员体系 |
| 公开注册 | 关闭 | 注册及注册邮件入口均需私密开户授权 |
| 账户身份 | `ALLOWED_EMAILS` 完整邮箱列表 | 逗号或换行分隔，排序、去重、精确匹配；拒绝通配符和空条目 |
| 私密开户 | `/setup` 校验 `OWNER_SETUP_TOKEN` 后进入 Web Vault | 可以为不同白名单邮箱重复授权开户，客户端生成凭据与密钥 |
| 主密码与保险库密钥 | 由客户端生成或派生；配置文件只指定允许的账户身份 | 配置邮箱不会自动创建用户、密码、key 或 privateKey |
| 账户隔离 | 所有个人数据继续以 user_id 约束 | 数据库补充文件夹归属约束，删除一个账户不影响其他账户 |

所有开户均需私密授权，包括已有账户后的后续开户；仅在白名单中不代表可以公开自助注册。白名单变更不重命名、删除用户或阻止既有账户登录，只约束开户及改邮箱的目标地址。
## 2. 资源、入口与固定名称

生产和本地配置共用 [wrangler.jsonc](../wrangler.jsonc)。顶层用于生产，`env.local` 声明本地变量和资源绑定。

| 配置项 | 当前值 / 对齐值 | 来源与说明 |
| --- | --- | --- |
| 生产 Worker 名 | `raywarden` | `name`；部署读取目标 JSONC，不另设默认 Worker 名 |
| 主配置文件 | `wrangler.jsonc` | 生产命令选择顶层，本地启动和迁移统一使用 `--env local --local` |
| Worker 入口 | `build/index.js` | worker-build 生成的 JS/WASM 包装；不维护手写 Worker JS 入口 |
| Rust 入口 | `src/lib.rs` → `src/api/edge/mod.rs` → `api::bootstrap::handle_request` | 先分流通知/heavydo，其余由 Axum 处理，包含附件与 Send 完整文件路径；heavydo 复用同一套服务 |
| Rust 工具链 | `nightly-2026-11-13` | `rust-toolchain.toml` 为统一来源 |
| 环境准备入口 | 安装 Node、rustup、just 和 Python，随后 `just setup` 或 `just dev` | Justfile 定义 Node/Rust/worker-build 就绪检查，缺失或过期时原生安装；setup 另预取 Cargo 依赖 |
| Node 版本 | `.node-version` | 当前为 24，Integration/Cloudflare 通过共享 setup 原生读取；Release-plz 不需要 Node；package engines 另声明最低支持版本 |
| WASM 检查 / 打包 | `just check` / `just build` | 检查 WASM 目标并使用锁定依赖和固定 worker-build 打包 |
| 构建工具版本 | `package.json`、`Cargo.toml` | worker SDK 0.9，worker-build 固定 0.9.0，Wrangler 和 just 版本在 package 中维护 |
| 静态资源目录 | `static/web-vault` | 不使用旧脚本的 `public/web-vault` |
| 前端准备入口 | Justfile 的 ui + `scripts/prepare-ui.sh`、`scripts/patch-ui.mjs` | 固定 Web Vault `2026.10.1`；ui 判断版本及入口 HTML，按需下载；ui-offline 禁止下载，ui-download 强制下载，ui-archive 导入归档；HTML 修改幂等 |
| D1 binding | `DB` | 生产和本地共用绑定键。Rust 通过 `infra::db::binding` 获取绑定，通过 `models` 执行查询和提交事务 |
| 生产 D1 名 | `warden-db` | 保留当前 `database_name` 及已配置的 database_id，不因本次对齐更换资源 |
| D1 运行结构来源 | 迁移文件 `0001`–`0008` | 定义新库结构、对象暂存表和清理索引，由 Wrangler 管理执行历史 |
| D1 当前结构快照 | `sql/schema.sql` | 完整迁移链派生的纯应用 DDL；用于阅读、迁移评审和临时 SQLite 分析，不参与应用建库/升级 |
| D1 后续变更 | `sql/migrations/0009_*.sql` 起 | 保留已应用文件并追加变更，通过 `just schema` 再生快照 |
| R2 binding | `ATTACHMENTS_BUCKET` | Rust 附件与 Send 共用 `infra/storage.rs` |
| 生产 R2 bucket | `warden-attachments` | 保留现有 bucket；目标名称从 JSONC 读取 |
| KV fallback binding | `ATTACHMENTS_KV` | 当前未配置；仅作为可选后端，R2 存在时优先用 R2 |
| 通知 DO binding / class | `notifydo` / `notifydo` | 绑定与导出类名统一为小写；功能联调与 MVP 范围收敛另行执行 |
| CPU 卸载 DO binding / class | `heavydo` / `heavydo` | 执行同一套业务实现，启用时包含实际文件上传；分流不预读取上传正文，下载继续原生透传 |
| DO migration tag | `v1` | 当前声明两类 SQLite DO；保留实际配置中的迁移历史 |
| 敏感操作限流 | `LOGIN_RATE_LIMITER` | 生产 namespace `3101`、本地 `4101`，阈值 `5 / 60 秒`；按代码中的 key 在边缘机房局部近似计数 |
| Send 密码尝试限流 | `SEND_ACCESS_RATE_LIMITER` | 生产 namespace `3103`、本地 `4103`，阈值 `15 / 60 秒`；新旧匿名密码授权入口共用，边缘机房局部近似计数，已持 bearer 的访问不增加密码尝试检查 |
| 健康检查 | `/api/alive` | 当前返回时间并查询 D1；不是 `/alive` |
| 定时任务 | `0 3 * * *` | UTC 每天 03:00，调度清理任务并检查全局等价域名更新 |
| Workers compatibility date | `2026-01-06` | 保留当前值；工具链固定不自动修改此日期 |
| 生产域名 | 默认 `<Worker名>.<账户子域名>.workers.dev` | 自定义域名可选；配置 routes 时使用唯一明确的 custom-domain 主机名 |
| 生产 workers.dev | `true` | 无 routes 时，资源检查及健康探测通过 Cloudflare API 只读查询账户子域名；构建不联网，不读取 DOMAIN Secret |

资源名与 binding 不同：例如 R2 bucket 名是 `warden-attachments`，代码绑定名是 `ATTACHMENTS_BUCKET`。部署工具需要分别使用正确的字段。

## 3. 核心运行变量与 Secret

Worker 的普通文本变量和 Worker Secret 都以字符串绑定提供给 Rust；worker 0.9 的 `Env::var` 也能读取 Secret。部署工具读取的是仓库配置文件，不能取回已经保存的 Secret 值，因此运行时值与部署路由分别处理。

| 名称 | 存放位置 / 实际读取规则 | 当前行为 | 目标约定 |
| --- | --- | --- | --- |
| `DOMAIN` | 生产为 Worker Secret；Rust 通过字符串绑定读取 | 每次部署从公开入口计算并通过 `--secrets-file` 与代码一同写入；生产配置不保存值 | 默认 workers.dev；唯一 custom-domain 路由存在时使用它。无须 GitHub `DOMAIN` Secret；本地仍为 `https://localhost:8787` |
| `ALLOWED_EMAILS` | Worker Secret；本地普通变量 | 非空完整邮箱列表，逗号或换行分隔；精确匹配，拒绝通配符或空条目 | 后续省略时继承已有 Secret；变更不影响旧账户登录 |
| `OWNER_SETUP_TOKEN` | Worker Secret；本地忽略的 `.dev.vars` | 32–512 字符，无控制字符和首尾空白；授权白名单中的每次开户 | 用同源 `/setup` 表单提交；不是主密码 |
| `KEY_ENCRYPTION_KEY` | 生产必需的独立 Worker Secret；通过同名 GitHub Secret 首次上传，本地配置仅含公开开发值 | 32 字节安全随机值的 canonical base64url 无 padding 表示（43 字符），用于 AES-256-GCM 包装 D1 内 access/refresh 根密钥；缺失、非法或不能解密时拒绝请求 | 在本机生成并独立备份，不能使用仓库中的开发值、每次部署重生成或当作主密码；后续不提供时继承已有 Worker Secret |
| `DISABLE_USER_REGISTRATION` | 普通变量，默认 true | 仅展示兼容；有效开户凭据且有未注册邮箱时临时可见 | 不能绕过开户授权 |
| JWT access 密钥 | D1 `jwt_keys.access_secret`，保存 `v1.` AEAD 密文 | 空账户库首次使用时生成并包装持久化，供普通 API、文件接口和 DO 共用；也用于短期 token、API Key 包装密钥派生及用途分离的未知邮箱 KDF 响应 | 不需手工生成 JWT 密钥；数据库行和独立 KEY_ENCRYPTION_KEY 必须一同保留，不可当缓存删除 |
| JWT refresh 密钥 | D1 `jwt_keys.refresh_secret`，保存 `v1.` AEAD 密文 | 与 access 分别随机生成，用不同字段 AAD 包装，后续稳定复用，不自动轮换 | 每个环境使用自己的 D1 和独立包装 Secret，避免共享根密钥 |
| `CORS_ALLOWED_ORIGINS` | 逗号分隔的 origin | 缺失、空值或 `*` 允许任意来源；限制列表没有有效项时拒绝所有跨源访问 | 生产为注释示例，本地显式为空；主入口、DO、错误和预检共用策略 |
| `REQUIRE_EMAIL_VERIFICATION` | 当前支持 Secret 或普通变量 | 默认 `false` | MVP 保持 `false`；这不替代受控账户初始化与关闭公开注册 |

生产 `vars` 不保存所有者邮箱或包装根密钥。`secrets.required = ["DOMAIN", "ALLOWED_EMAILS", "KEY_ENCRYPTION_KEY"]` 声明必需名称，部署工具负责首次随代码写入；不需要预先创建空 Worker。`OWNER_SETUP_TOKEN` 只用于初始化，不是常态请求的必需项。部署校验拒绝把 KEY_ENCRYPTION_KEY 写进生产 vars。

邮箱白名单也用于既有改邮箱流程的目标地址检查。要更换账户邮箱，先将 GitHub/Worker 的 `ALLOWED_EMAILS` 更新为新目标，再由已登录客户端完成改邮箱验证；配置更新本身不重命名账户、不影响原邮箱登录，也不绕过客户端密钥重包裹。

部署工具把公开 URL 写为 `DOMAIN`；只在环境变量显式提供非空值时更新 `ALLOWED_EMAILS`、`OWNER_SETUP_TOKEN`、`KEY_ENCRYPTION_KEY`，否则继承已有 Worker Secrets。包装密钥在上传前严格验证格式；临时 JSON 文件限权保存，成功或失败后删除，这些值也从 Wrangler 子进程环境中移除。GitHub 不保存派生 DOMAIN；应用凭据不进入交付产物。`keep_vars: true` 不会把旧普通变量转换为 Secret，已有实例需核对同名旧变量。

本地配置直接提供虚构邮箱、localhost 和公开的开发包装 key，日常启动不需要 `.dev.vars`；该开发值不能用于生产。首次开户把本地 `OWNER_SETUP_TOKEN` 放入忽略的 `.dev.vars`；邮件、推送等按需配置。新环境不用提供 `JWT_SECRET`、`JWT_REFRESH_SECRET`。

客户端会从 `/api/config` 得到公共 URL。将 `DOMAIN` 设为 Secret 是存放选择，不会隐藏服务地址。部署工具优先使用唯一 custom-domain 路由，未配置时通过 Cloudflare API 查询账户子域名并生成 workers.dev 地址；同一个结果用于运行时 DOMAIN 与健康检查，不读取远程 Secret。

每次开户访问同源 `/setup`，授权成功后取得绑定 DOMAIN 和当前完整白名单摘要、有效期十分钟的 HttpOnly / SameSite=Strict Cookie，HTTPS 另带 Secure。客户端通过 Web Vault 生成密码与加密材料。成功后清除浏览器 Cookie；下一账号重新授权。同邮箱并发由唯一约束返回冲突，不同白名单邮箱可同时开户。所有注册别名及注册邮件入口校验相同规则。修改名单会让旧 Cookie 失效；移除开户令牌只停止新授权，旧 Cookie 最多十分钟后过期。CLI 的 `X-Raywarden-Setup-Token` 受相同规则约束。

已有环境首次建立 `jwt_keys` 时，如完整提供两个非空旧 JWT Secret，保留原始字节、包装后写入一次；只提供一个或空值报错。已有原文行会在配置 KEY_ENCRYPTION_KEY 后按两个旧字段做同条条件 UPDATE，转为包装格式，不改变 JWT/API Key 的实际密钥字节。并发初始化或包装后重读持久赢家；读写失败不重新生成。已有包装行只用外部 Secret 解密，忽略旧 JWT 环境值，错误根 key 不会回退成原文模式。

随机初始化只允许没有用户及 API Key 的库。已有用户或 API Key 却缺失 `jwt_keys` 时会拒绝持久化替代密钥；恢复原密钥行，或提供成对的原始旧 Secret 后再启动，不要通过删行尝试重置。新 API Key 密文使用 `v2.` 前缀及按用途分离派生的包装密钥；旧格式仍可读取，不要求重新生成 API Key。

仅泄露新格式的 D1 导出将不再直接获得 JWT/API Key 包装根密钥；运行中 Worker 仍可解密，不能抵御完整运行环境失陷。历史原文备份不会自动加密，数据库仍含账户验证和 2FA 等敏感材料，备份应加密保管。丢失 KEY_ENCRYPTION_KEY 或 jwt_keys 原行会影响登录和 API Key 读取，不能通过换随机 Secret 或删行恢复。旧二进制不识别 v1 包装格式，回退与恢复要求见[备份边界](db-backup-recovery.md#jwt-包装根密钥与版本回退)。

## 4. 核心参数

| 名称 | 当前默认 / 读取来源 | 对齐后的处理 |
| --- | --- | --- |
| `JWT_DURATION_SECONDS` | `3600`，普通变量 | access token 有效秒数，必须是正整数且计算到期时间不溢出；非法值拒绝加载配置；refresh 固定为 30 天 |
| `TWO_FACTOR_REMEMBER_DAYS` | `30`，普通变量 | 去除首尾空白后读取整数；解析失败回退 30，范围限制为 1–90 天。同时控制 Remember 记录校验、清理与 Cookie 有效期，不改变 refresh 的 30 天期限 |
| `IMPORT_BATCH_SIZE` | `30`，普通变量 | 导入分块准备后同事务提交；SQL/WASM 已覆盖快照、集合和回滚，真实大库性能另行验收 |
| `TRASH_AUTO_DELETE_DAYS` | `30`，普通变量 | 保留；非正值关闭回收站自动清理，不等于关闭其他清理任务 |
| `AUTHENTICATOR_DISABLE_TIME_DRIFT` | `false`，普通变量 | 设为 true 时关闭 TOTP 相邻时间步容差，同一时间步只允许消费一次 |
| `HEAVY_DO_ENABLED` | 有 binding 且未显式关闭时启用，Rust dispatch 读取 | 复用同一 Rust API 执行；原生 Wrangler 已验证 heavydo 注册、登录、流式请求与本地 D1/R2 路径 |
| `HEAVY_DO_SHARDS` | 代码回退 `16`，范围 1–64 | 生产和本地均显式设为 `"1"` |
| `LOG_LEVEL` | 普通变量，默认 `info` | 全局应用日志等级，生产和本地均设为 `info` |

`HEAVY_DO_SHARDS=1` 只收敛 CPU 卸载实例数量，不限制账户数；多个账户也可以使用同一分片。

时间格式没有运行开关。Rust 直接使用 Jiff 1，服务端新写入的时间固定为 UTC 三位毫秒 `...SS.mmmZ`，需要微秒的 API 日期字段固定为六位；不依赖本地时区数据库。已有时间字符串保留原值，到期和清理 SQL 按 `julianday` 比较时间点，兼容旧偏移表示，不能改回字符串字典序比较。

### 4.1 客户端 KDF 与服务端密码验证成本

客户端 KDF 用于派生主密钥与认证材料，参数保存在账户的 `kdf_type`、`kdf_iterations`、`kdf_memory`、`kdf_parallelism` 中。真实账户的 prelogin 始终返回自己的原参数和规范化邮箱盐。旧 `KDF_ITERATIONS`、`KDF_MEMORY`、`KDF_PARALLELISM` 配置字段没有业务消费者，现已移除；保留同名环境变量也不会改变账户参数或服务端验证成本。

服务端对客户端认证 hash 另做 PBKDF2 验证。账户基线直接定义独立 `password_iterations`，默认 600000；新写入至少此成本、64 字节随机盐，已有更高成本保留。显式低成本或无盐材料仍由现有条件升级路径处理，只有密码正确并完成所需 2FA 才更新；不修改修订游标、安全戳或其他设备会话。客户端 KDF 和 Send 密码成本独立。

Send 密码独立使用 `100000` 次创建成本；验证读取各条 Send 记录中的正整数成本，旧记录缺失成本时沿用历史值。它不跟随账户成本升级，也不读取客户端 KDF 参数。上述成本均为代码策略，没有新增全局配置开关。

未知邮箱使用规范化地址和持久化 access secret 做用途分离的 HMAC，稳定选择常见 PBKDF2/Argon2id 响应。响应包含仅用于未知账户的旧成本组合，不放宽真实账户的注册或改 KDF 校验，也不创建账户。数据库查询失败仍返回错误，不伪装成未知邮箱；该策略减少固定响应特征，不能保证消除账户枚举。

成本升级会改变旧二进制的兼容边界，回退前必须阅读[备份与恢复边界](db-backup-recovery.md#账户验证成本升级的回滚边界)。不能把已升级数据库交给固定按 `100000` 次读写的旧 Raywarden。

## 5. 扩展能力配置

浏览器展示设置与服务端授权各自生效。

| 能力 | 配置 | 行为与限制 |
| --- | --- | --- |
| 附件 | `ATTACHMENT_MAX_BYTES`、`ATTACHMENT_TOTAL_LIMIT_KB`、`ATTACHMENT_TTL_SECS`；普通变量 | 先预留，再上传正文。R2 支持流式分块上传，能力 TTL 默认 60 秒 |
| File Send 大小与配额 | `SEND_MAX_BYTES`、`USER_SEND_LIMIT_KB`；普通变量 | 单文件默认 95 MiB，可配置；仍受存储后端和平台限制，KV 原始字节上限 25 MiB。未配置用户配额时不限制总量，零表示零字节额度；空值、负数、非整数或换算溢出返回 500 |
| Send 文件能力期限 | `SEND_TTL_SECS`；普通变量，默认 `300` | 控制外部文件上传/下载能力；解析失败回退 300，非正数或不能表示到期时间则在预留、暂存、清理、访问计数前拒绝。`send_access` OAuth token 独立固定 300 秒 |
| Text Send 内容大小 | `SEND_TEXT_MAX_BYTES`；普通变量，默认 `1887436` | 按无符号整数读取，解析失败用默认，最高限制 `1900000`；`0` 禁止文本 Send，不禁用文件 Send。创建/更新统一按移除响应派生字段后的文本内容 JSON 的 UTF-8 字节计数 |
| 管理事件通知 | `NOTIFY_LEVEL`、`NOTIFY_EVENTS`；通道为 `WEWORK_WEBHOOK_URL` 或 `TELEGRAM_BOT_TOKEN`＋`TELEGRAM_CHAT_ID`，支持 Worker Secret | 支持下方全部标准事件、等级与旧名兼容；默认不选事件，不发送；本地为 warning/none；与收件人验证码投递分离，真实外发尚未验收 |
| 收件人邮件 | `MAIL_WEBHOOK_URL`、`MAIL_WEBHOOK_TOKEN`；支持 Secret/普通变量 | MVP 不要求；N 阶段接入真实按 `to` 投递的网关 |
| 移动推送 | `PUSH_ENABLED` 普通变量；`PUSH_INSTALLATION_ID`、`PUSH_INSTALLATION_KEY` 为 Secret | 默认关闭；后续单独启用 |
| 推送地址 | `PUSH_RELAY_URI`、`PUSH_IDENTITY_URI`；普通变量 | 默认使用现有代码的 Bitwarden relay/identity 地址；与账户数量无关 |
| WebAuthn 额外 origin | `WEBAUTHN_ALLOWED_ORIGINS`；普通变量 | 默认以 DOMAIN 为安全来源；扩展/原生客户端需要时显式配置 |
| Send 人机验证 | `TURNSTILE_SITE_KEY`、`TURNSTILE_SECRET_KEY`；支持 Secret/普通变量 | 成对配置；只配一个会进入需要验证却不完整的状态；后续验收 |
| 图标代理 | `DISABLE_ICON_DOWNLOAD`；支持 Secret/普通变量，默认 `false` | 保留；可按需求关闭 |
| HIBP 代理 | `HIBP_API_KEY`；支持 Secret/普通变量 | 不配置则不具备可用的代理凭据 |
| 客户端可选功能 | `CLIENT_FEATURE_FLAGS`；普通变量 | 逗号分隔的受支持名称或 name=false；macOS 凭据同步与 V2 密码注册仅显式启用，强制升级/JIT/no-logout 相关未支持 flag 被忽略 |
| 客户端引导展示 | `CLIENT_SUPPRESS_ONBOARDING`；默认 `false` | 独立输出 `/api/config.settings.suppressOnboardingInterstitials`；不合并注册开关，不关闭注册 API |
| 自动填充规则来源 | `FILL_ASSIST_RULES_URL`；普通变量 | 默认 fillassist.bitwarden.com；只接受无凭据、query、fragment 的 HTTPS URL，非法值回退默认 |
| Passkey 登录展示 | `VW_CSS_PASSKEY_LOGIN_ENABLED`；旧 `PASSKEY_LOGIN_ENABLED` 为回退别名，默认 `true` | 仅动态 CSS；不禁用服务端 Passkey API，详见下方完整样式表 |
| 自定义样式 | `VW_CSS_LOAD_USER_CSS`、`VW_CSS_USER`；支持 Secret/普通变量 | 前者默认 `true`，开启时才追加后者的非空 CSS；不作为服务端权限规则 |

### 5.1 展示与客户端开关

生产配置用注释提供可选项示例，`keep_vars: true` 保留 Dashboard 中已有的值。取消注释后由仓库设置该项。本地配置显式给出展示、CORS 和通知的默认值，邮件可用性按配置判断。

布尔开关接受 `true/1/yes/on` 与 `false/0/no/off`，忽略大小写及首尾空白；未配置或非法值使用表中默认值。`VW_CSS_USER` 是 CSS 字符串，其余 `VW_CSS_*` 为布尔值。

| 配置 | 默认值 / 兼容规则 | 展示行为 |
| --- | --- | --- |
| `VW_CSS_SIGNUP_DISABLED` | 继承 `DISABLE_USER_REGISTRATION`，默认 `true` | 隐藏注册链接，不影响注册 API 授权 |
| `VW_CSS_SENDS_ALLOWED` | `true` | 是否显示 Send 导航 |
| `VW_CSS_PASSWORD_HINTS_ALLOWED` | `true` | 是否显示密码提示入口 |
| `VW_CSS_SSO_ENABLED` | `false` | 控制 SSO 与普通邮箱登录布局 |
| `VW_CSS_SSO_ONLY` | `false` | 配合 SSO 展示隐藏其他登录选项 |
| `VW_CSS_PASSKEY_2FA_SUPPORTED` | `true` | 是否显示 WebAuthn 2FA 选项 |
| `VW_CSS_PASSKEY_LOGIN_ENABLED` | 回退到旧 `PASSKEY_LOGIN_ENABLED`，再默认 `true` | 是否显示 Passkey 登录和设置入口 |
| `VW_CSS_REMEMBER_2FA_DISABLED` | `false` | 是否隐藏记住 2FA 选项 |
| `VW_CSS_MAIL_ENABLED` | 未配置时随非空 `MAIL_WEBHOOK_URL` 自动判断 | 邮件能力的展示前提；无需为默认行为单独设值 |
| `VW_CSS_MAIL_2FA_ENABLED` | `true` | 与邮件展示能力同时为真时显示 Email 2FA |
| `VW_CSS_YUBICO_ENABLED` | `false` | 是否显示 YubiKey 选项 |
| `VW_CSS_DUO_ENABLED` | `false` | 是否显示 Duo 选项 |
| `VW_CSS_EMERGENCY_ACCESS_ALLOWED` | `false` | 是否显示紧急访问导航 |
| `VW_CSS_LOAD_USER_CSS` | `true` | 是否加载自定义 CSS |
| `VW_CSS_USER` | 空字符串 | 开启加载时，追加到基础样式及生成规则之后 |
| `CLIENT_SUPPRESS_ONBOARDING` | `false`，独立于注册设置 | 输出 `settings.suppressOnboardingInterstitials` 抑制欢迎/升级弹窗，并通过动态 CSS 隐藏新版 vault 引导任务清单 |

样式由 Rust 动态生成，ETag 取决于实际 CSS 内容；响应使用 `public, no-cache` 并按当前配置重新校验，CSS 输出变化后不会继续命中旧 ETag。`CLIENT_SUPPRESS_ONBOARDING` 不再写入 `disableUserRegistration`，两者可分别配置。2026.10.1 的引导清单组件不读取原生弹窗设置，因此同一开关额外控制 `app-vault-onboarding` 的隐藏规则，不修改第三方 JS。

这些选项只控制展示，不替代后端能力、认证或权限检查。显示 SSO、YubiKey、Duo、紧急访问等入口不会实现对应后端；关闭 Send、Passkey 或密码提示样式也不会禁用其 API。私密开户由独立服务端授权和邮箱唯一约束实现，不依靠这些样式开关。

### 5.2 日志过滤

`LOG_LEVEL` 接受 `off`、`error`、`warn`、`info`、`debug` 或 `trace`，忽略大小写及首尾空白。缺失或无效时使用 `info`。旧配置中的 `warn,auth=debug` 按全局 `warn` 处理。Worker、定时任务和 Durable Object 每个实例初始化一次应用日志。

### 5.3 管理通知

`NOTIFY_EVENTS` 未配置、为空或为 `none/off/0/false` 时不发送；`all` 或 `*` 选择全部，其他值为逗号分隔事件名，忽略大小写和首尾空白。未知名字不匹配事件。`NOTIFY_LEVEL` 默认 `info`，支持 `info/warning/warn/error`；`warn` 等同 `warning`，非法值回退 `info`。事件须同时通过名字与最低等级筛选。本地显式配置 `NOTIFY_LEVEL=warning`、`NOTIFY_EVENTS=none`，不会默认外发。

| 等级 | 全部标准事件名 |
| --- | --- |
| `info` | `login`、`cipher_create`、`cipher_update`、`import`、`send_create`、`2fa_enable`、`token_refresh`、`sync`、`auth_request`、`auth_response`、`webauthn_credential_create`、`webauthn_credential_update`、`webauthn_login` |
| `warning` | `login_failed`、`password_hint`、`password`、`email`、`kdf`、`cipher_delete`、`send_delete`、`2fa_disable`、`2fa_recovery_code_view`、`webauthn_credential_delete` |
| `error` | `2fa_recover` |

以上 24 项分别接入真实登录、刷新、同步、账户安全操作、密码库 CRUD/导入、Send、各类 2FA、设备审批和 Passkey 用例。软删除与永久删除均为 `cipher_delete`；按参考端语义，`send_create` 也覆盖所有者更新，公开 Send 访问及计数不会冒充所有者修改。登录失败仅报告明确的凭据/密码/2FA 拒绝；正常二次验证 challenge、限流、D1/基础设施故障、版本门槛和参数解析错误不作为 `login_failed`。

旧 Ray 的七个过滤名称继续有效：

| 旧过滤名 | 当前匹配 / 保留行为 |
| --- | --- |
| `vault-changed` | 匹配 Cipher CRUD、导入、Send 创建/更新/删除；文件夹和附件操作仍保留同名独有事件（info） |
| `account-security-changed` | 匹配 password/email/kdf；安全戳重置/会话撤销，以及不改密码的账户密钥轮换仍保留同名独有事件（warning） |
| `account-settings-changed` | 保留同名独有事件（info），用于资料、头像、域名设置 |
| `account.deleted` | 保留同名独有事件（warning），用于账户删除 |
| `account.email-changed` | `email` 的别名 |
| `two-factor.enabled` | `2fa_enable` 的别名，覆盖已接入的 TOTP/Email/WebAuthn 操作 |
| `two-factor.disabled` | `2fa_disable` 的别名 |

标准名和旧名同时匹配同一次操作时只发一条事件；旧的通用管理通知钩子不再重复发送。成功事件在实际成功结果/提交之后发送；通用停用与专用 Email 停用在目标不存在或已停用时保留原响应及清理，但不报告新的 `2fa_disable`。管理通知网络失败不会回滚或改变业务结果。

消息只包含事件名、等级与账户 ID，不携带 IP、User-Agent、邮箱、密码提示内容、验证码、密文、hash、token 或通道凭据。通道仍为 `WEWORK_WEBHOOK_URL` 或 `TELEGRAM_BOT_TOKEN`＋`TELEGRAM_CHAT_ID`；生产凭据放 Worker Secrets，本地可放 `.dev.vars`。管理通知与按收件人投递的邮件验证码相互独立，事件筛选不会禁用验证码投递。尚未使用真实通道向外发送，测试捕获不代表真实渠道已联调。

### 5.4 CORS 与可选测试页

`CORS_ALLOWED_ORIGINS` 缺失、为空或列表含 `*` 时允许任意来源。其他值按逗号分隔解析 origin，支持显式 `null`，遇到带凭据、路径、query 或 fragment 的项则忽略。显式限制列表没有有效项时拒绝全部跨源访问。

从使用 `ALLOWED_ORIGINS` 的版本升级时，发布前将原值迁到 `CORS_ALLOWED_ORIGINS`，以继续按来源限制访问。

主入口、Axum、通知 DO、错误响应和预检共用 `CorsPolicy`。Any 返回 `Access-Control-Allow-Origin: *`，限制列表仅回显匹配的来源；两种模式都不启用 credentials，客户端仍使用显式 bearer 认证。WebAuthn origin 校验独立存在，不能以 CORS 允许替代。

`DEMO_PAGE_ENABLED` 默认 `false`。开启后，Worker 在 `/demo.html` 提供可选测试页并返回 CSP 和 `no-store`，关闭时返回 404。测试页的账户操作使用正常 API 鉴权。

附件与 Send 的文件协议、签名校验和元数据提交均由 Rust 处理。共享存储层使用 R2 8 MiB 分块和 KV 25 MiB 有界回退；下载统一处理单范围、If-Range、HEAD 与 416，R2 原始流在最终 Worker 响应边界交给运行时。分块大小是实现常量，没有新增运行配置项。

同步与 Cipher、Send、文件夹列表在 D1 内部分批读取，客户端仍收到完整的原有 JSON。每批最多读取 200 行，按底层字段估算的 UTF-8 字节预算为 4,000,000 字节。Cipher 页面也计入关联附件元数据的预估体积，附件仍逐行读取。单个 Cipher 投影中的附件文件名、包装密钥、ID 和下载地址合计最多 16 MiB。上述列表和同步的完整编码响应最多 64 MiB。超出任一响应预算时返回 413，不发送部分结果。这两个响应预算是 Worker 内存约束，与附件文件本身的大小和配额设置独立。

### 5.5 统一响应头与缓存

`static/security-headers.json` 是编译内置策略，Rust 响应层与前端准备生成的 `_headers` 共用，不新增必需环境变量。修改策略后应重新构建 Worker 并执行 `just ui-offline`，使动态响应与静态资源一起更新。

普通动态响应缺省为 `Cache-Control: private, no-store`，并添加 nosniff、Referrer-Policy、X-Robots-Tag、Permissions-Policy、按内容类型选择的 CSP 和 frame 限制。已有 setup/Turnstile 的局部 CSP、文件下载限制、CSS ETag 与缓存策略继续优先；WebSocket 101 原样返回，不重建升级对象或读取响应体。

静态首页及 HTML 禁止存储，其他静态资源默认允许重验证；图像使用限制主动内容的 CSP，connector 页面保留嵌入需要的例外。`_headers` 只影响静态资源，不能替代 Worker 和 DO 响应的 Rust 处理。前端 CSP 的 connect/img 兼容 HTTPS 外部服务，不代表这些目的域已经逐个授权或验证可用。

### 5.6 限流配置与依赖故障

部署工具在远程查询、迁移或上传前校验 `LOGIN_RATE_LIMITER` 和 `SEND_ACCESS_RATE_LIMITER`：名称必须各出现一次，namespace 必须为独立的数字字符串，limit 为正安全整数，period 为 10 或 60 秒。当前项目命令不接受遗漏任一 binding 的部署配置。

运行中明确超过限额返回 429；binding 缺失、类型错误、调用异常或非法响应返回通用 503，停止受保护的认证/密码尝试，不绕过限流。普通登录、敏感操作和 notifydo 连接复用同一入口，Send 保持独立 binding；健康检查和无须该门控的读取不因限流服务故障关闭。固定类别 warning 在每实例、每 binding/故障种类内每 60 秒最多一次，不输出 key、邮箱、IP 或提供方异常；不同实例不共享门控。

### 5.7 文件响应与凭据 URL 日志

附件和文件 Send 的共享存储下载强制 `application/octet-stream`、`Content-Disposition: attachment`、`nosniff` 和独立 `default-src 'none'; sandbox` CSP。R2/KV 的历史 MIME 不作为可信响应类型；GET、HEAD、Range 共用限制，原始加密字节及流式传输保持不变。

生产开启 `observability.redact_query_string=true`，同时关闭 invocation_logs，保留应用日志；前者也用于 traces。部署工具拒绝未启用 query 脱敏的生产配置。通知 access_token 和文件 token 仍按客户端协议放在 URL，不能因为应用日志未显式打印就忽略平台日志；这些设置不负责清理历史日志或其他外部代理的日志。

## 6. 本地与生产边界

| 环境 | 配置 | 入口与约束 |
| --- | --- | --- |
| 本地 | `wrangler.jsonc` 的 `env.local` | `just dev` 准备 UI、自动应用本地迁移后启动。数据库和文件使用 `.wrangler/local` 中的本地模拟资源，`just db-migrate` 默认选择本地环境 |
| 生产 | `wrangler.jsonc` 顶层 | 自定义域名及既有 D1/R2/DO。远程数据库仅由显式 `just db-migrate production` 或完整部署流程操作 |

所有远程命令显式使用 `--env ""` 选择生产配置。`just dev` 显式使用 `--env local --local` 启动本地运行时。

`$schema` 已启用，供编辑器补全和校验。`assets.run_worker_first` 声明动态路径优先进入 Worker，包含 `/two-factor/*` 和动态 CSS；它不是请求白名单，未匹配的请求仍按正常静态资源路由处理。DO 的 `migrations` 管理类迁移，D1 结构由 `sql/migrations` 管理。

生产保留 `keep_vars: true`，沿用 Dashboard 中已有的普通变量。Secrets 继续独立管理。

## 7. 构建与部署配置

本地启动、构建、迁移、交付与健康检查见[部署指南](deployment.md)。Wrangler 日志默认写入 `.wrangler/logs`，可用 `WRANGLER_LOG_PATH` 指定位置。构建工具缓存默认使用 `.tools/cache`，可用 `XDG_CACHE_HOME` 覆盖。

数据库结构、迁移与回退见[迁移目录说明](../sql/migrations/README.md)和[恢复边界](db-backup-recovery.md)。

## 8. 账户与客户端行为

当前支持精确邮箱白名单内的多个独立账户，所有开户仍需私密令牌授权。不设全局单账户索引或空库门槛，也不新增组织、角色和管理员后台。移出白名单不撤销现有会话或阻止登录；账号撤销仍应使用已有会话/账户操作。

2FA 公共恢复入口按 IP 与规范化邮箱分别限流，未知账户也计数。公共入口和密码登录的 provider 8 使用同一事务消费恢复码并清理验证码、2FA Passkey 和 Remember 记录，保留 Passkey 登录凭据及其他账户的数据。

TOTP 设置使用 `POST /api/two-factor/get-authenticator` 和 `POST /api/two-factor/authenticator`。已有活动因子可继续使用。旧的 `request`、`enable` 和 `disable` 三个 TOTP 子路径及 `TWO_FACTOR_ISSUER` 已移除。

`POST /api/accounts/set-password` 只给已有、主密码与私钥均空的V1账户设置首次密码，必须持有效access会话；普通注册不会产生这类空账户，不能靠此接口建用户或重置已有密码。支持legacy及注册式modern凭据，保留公钥身份与已有会话，清除旧Remember/审批和PRF包装；更高服务端成本不降低。legacy完全省略KDF时保留该账户prelogin参数；显式更改须type/iterations完整，Argon内存/并行缺省64MiB/4。V2 JIT不支持，已存在key ID不得替换；V1新提交的合法ID不创建新身份。空或全空白的存储认证材料及密码输入均不能通过共享验证器。

V2 账户要求普通客户端版本至少为 `2026.10.1`，桌面端至少为 `2026.10.2`。V2 注册需要显式启用对应的客户端 feature flag。验收范围见[架构说明](architecture.md#客户端兼容范围)。

### 8.1 OAuth、Remember 与 PRF 兼容规则

`/identity/connect/token` 表单字段兼容大小写及下划线差异，归一化后重复字段拒绝；密码、token 等不去除内容空白。refresh 返回标准的精简字段集，普通密码登录仍输出当前账户真实的主密码解锁状态。

只有 form 未提供对应凭据时，refresh 或 Remember 才回退到参考 Cookie；显式但无效的 form 不会借 Cookie 绕过。浏览器请求的 Origin 必须等于 `DOMAIN`，`Sec-Fetch-Site` 只接受 `same-origin` 或 `none`；没有这两个浏览器头的 CLI 可按协议使用 Cookie。Cookie 为 HttpOnly、SameSite=Strict，仅 `/identity/connect/token` 路径可用，HTTPS 另加 Secure。普通 API 不接受 Cookie 作为 access 授权，CORS 也不启用跨源 credentials。

新 Remember 记录只存 token 摘要，读取兼容旧原文；签发/更新同时检查账户、会话、真实因子及旧记录，避免撤销后重新写回。缩短天数会影响历史记录的有效期；不能通过回退旧程序恢复已清除的 Remember，必要时重新完成 2FA 登录。

PRF probe/save/update 的 `canUsePasskeyUnlock`、`requiresPasswordLogin`、`success` 和状态来自实际凭据。只有完整的公钥、用户密钥和私钥包装材料才可报告可解锁；最终保存仍比较账户代际、会话及已接受的挑战与计数器，兼容入口不减少 WebAuthn 签名验证。

### 8.2 用量与通知的含义

usage 的 `d1Bytes` 按 UTF-8 逻辑字段估算，`r2Bytes` 来自文件元数据；`totalBytes` 合并两类，`items.storage` 保留文件分项。它们不包含 SQLite 索引/页开销，也不查询 R2 实际物理占用。`maxBytes=500 MiB` 是参考显示预算，响应带 `quotaIsEstimate=true` 与 `quotaSource=reference-budget`；实际文件约束仍由大小和用户配额配置执行，不是免费套餐的实时剩余额度。

域名设置在条件事务提交后推进 revision，仅发布一次 SyncSettings（10）；凭据撤销成功后才发 LogOut（11）。通知可能包含发起设备的 ContextId，客户端据此过滤自己的事件；投递尽力而为，手动同步仍是恢复路径。
