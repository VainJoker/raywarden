# Raywarden 运行配置表

对齐日期：2026-11-18。用途：作为后续实现、配置和部署的统一依据。

本表分别标明当前源码行为与目标策略。`Justfile` 直接调用原生工具；Rust 选择来自 `rust-toolchain.toml`，Node 来自 `.node-version`。2026-11-17 原生 CI、打包、production dry-run、产物校验及实际 no-bundle 路径已通过，历史构建记录保留在计划中。本轮未读取远程 Secret 或读写线上资源。

## 1. 已确定的产品与账户策略

| 项目 | 对齐后的约定 | 当前状态 |
| --- | --- | --- |
| 使用范围 | 单用户个人密码库，同一账户可以有多个设备 | `users_single_owner` 唯一索引拒绝第二行，包括并发开户的输家 |
| 公开注册 | 关闭，不提供公开自助注册 | 所有注册别名共用所有者授权与空库检查；展示变量不能开放公众注册 |
| 账户身份 | 由 `ALLOWED_EMAILS` 指定唯一、完整的邮箱地址 | 初始化要求非空、一个完整地址，归一化后精确匹配；不接受多值与 glob |
| 首次账户初始化 | 本人通过受控流程，使用客户端生成密码验证材料和加密密钥；完成后关闭初始化入口 | `/setup` 校验独立 `OWNER_SETUP_TOKEN`，签发短期授权后进入 Web Vault 注册；已有账户时拒绝再次初始化 |
| 主密码与保险库密钥 | 由客户端生成或派生；配置文件只指定允许的账户身份 | 配置邮箱不会自动创建用户、密码、key 或 privateKey |
| 现有实现 | 保留现有代码、分层、接口实现和数据归属校验，逐项收敛 | 不按单用户定位删除通用模型或直接清空已有数据 |

常态运行时，即使请求使用白名单邮箱，公开注册接口也应被拒绝。首次初始化是独立的、受控的一次性流程，不靠临时向公众开放注册完成。

白名单是唯一所有者邮箱的配置来源，不作为密码使用。已有账户应与该邮箱一致；修改白名单不会自动改名、迁移、删除或替换已有账户。若旧库存在多个用户或账户不匹配，应报告冲突并停止初始化，由单独的数据处理任务解决。

白名单约束初始化和邮箱变更，不是已有账户登录时的额外密码。修改它不会自动重命名已有账户；已有账户身份仍需由操作者核对。旧库存在多个用户时，`0010` 迁移失败停止，不删除或自动合并账户。

## 2. 资源、入口与固定名称

以 [wrangler.jsonc](../wrangler.jsonc) 和当前 Raywarden 代码中的名称为准。后续对齐部署脚本时沿用这些名称，不把 ww1/ww2 的默认名称覆盖回来。

| 配置项 | 当前值 / 对齐值 | 来源与说明 |
| --- | --- | --- |
| 生产 Worker 名 | `raywarden` | `name`；部署读取目标 JSONC，不另设默认 Worker 名 |
| 主配置文件 | `wrangler.jsonc` | 远程项目命令固定使用此文件；本地命令固定使用 `wrangler.local.jsonc`，初始化与迁移使用同一配置 |
| Worker 入口 | `build/index.js` | worker-build 生成的 JS/WASM 包装；不维护手写 Worker JS 入口 |
| Rust 入口 | `src/lib.rs` → `src/dispatch.rs` → `api::handle_request` | 先分流通知/HeavyDo，其余由 Axum 处理，包含附件与 Send 完整文件路径；HeavyDo 复用同一套服务 |
| Rust 工具链 | `nightly-2026-11-13` | `rust-toolchain.toml` 为统一来源 |
| 环境准备入口 | `just setup`；本地直接 `just dev` | Justfile 定义 Node/Rust/worker-build 就绪检查，缺失或过期时原生安装；setup 另预取 Cargo 依赖 |
| Node 版本 | `.node-version` | 当前为 24，三个 workflow 原生读取；package engines 另声明最低支持版本 |
| WASM 检查 / 打包 | `just check` / `just build` | 检查实际 WASM target，打包直接调用固定 worker-build 与锁文件；当前版本的验收结果见执行记录 |
| 构建工具版本 | `package.json`、`Cargo.toml` | worker SDK 0.9（宏由 SDK 重导出），worker-build 固定 0.9.0；Wrangler/just 版本在 package 中维护；工具和 crate 分别安装；依赖升级后的构建验证见执行记录 |
| 静态资源目录 | `static/web-vault` | 不使用旧脚本的 `public/web-vault` |
| 前端准备入口 | Justfile 的 ui + `scripts/prepare-ui.sh`、`scripts/patch-ui.mjs` | ui 判断版本及入口 HTML，按需下载；ui-offline 禁止下载，ui-download 强制下载，ui-archive 导入归档；HTML 修改幂等 |
| D1 binding | `warden-db` | Rust 数据访问统一使用 `env.d1("warden-db")` |
| 生产 D1 名 | `warden-db` | 保留当前 `database_name` 及已配置的 database_id，不因本次对齐更换资源 |
| D1 运行结构来源 | `sql/migrations/0001`–`0010` | 五个功能基线，加 JWT 密钥、域名刷新状态、V2 账户、文件清理及唯一用户约束；Wrangler 管理执行历史 |
| D1 当前结构快照 | `sql/schema.sql` | 完整迁移链派生的纯应用 DDL；用于阅读、迁移评审和临时 SQLite 分析，不参与应用建库/升级 |
| D1 后续变更 | `sql/migrations/0011+` | 追加新文件；改迁移后 just schema 再生快照，无旧历史映射或自动补记录步骤 |
| R2 binding | `ATTACHMENTS_BUCKET` | Rust 附件与 Send 共用 `infra/storage/mod.rs` |
| 生产 R2 bucket | `warden-attachments` | 保留现有 bucket；目标名称从 JSONC 读取 |
| KV fallback binding | `ATTACHMENTS_KV` | 当前未配置；仅作为可选后端，R2 存在时优先用 R2 |
| 通知 DO binding / class | `NOTIFY_DO` / `NotifyDo` | 保留现有绑定；功能联调与 MVP 范围收敛另行执行 |
| CPU 卸载 DO binding / class | `HEAVY_DO` / `HeavyDo` | 执行同一套业务实现，启用时包含实际文件上传；分流不预读取上传正文，下载继续原生透传 |
| DO migration tag | `v1` | 当前声明两类 SQLite DO；保留实际配置中的迁移历史 |
| 敏感操作限流 | `LOGIN_RATE_LIMITER` | 生产 namespace `3101`、本地 `4101`，阈值 `5 / 60 秒`；按代码中的 key 计数 |
| Send 密码尝试限流 | `SEND_ACCESS_RATE_LIMITER` | 生产 namespace `3103`、本地 `4103`，阈值 `15 / 60 秒`；新旧匿名密码授权入口共用，已持 bearer 的访问不增加密码尝试检查 |
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
| `ALLOWED_EMAILS` | 生产 Worker Secret；首次工作流从同名 GitHub Secret 传入 | 初始化必须为一个非空完整邮箱，归一化后精确匹配；缺失、多值和 glob 均拒绝初始化 | 不写入生产 vars 或文档；后续未显式提供时继承已有 Secret。本地使用配置中的虚构邮箱 |
| `OWNER_SETUP_TOKEN` | 生产 Worker Secret；首次工作流从同名 GitHub Secret 传入；本地放忽略的 `.dev.vars` | 32–512 字符，无控制字符或首尾空白；只在空库授权初始化，不作为主密码 | 推荐用 `openssl rand -hex 32` 生成并私下保存；通过同源 `/setup` 表单提交，不放 URL、源码或命令参数 |
| `DISABLE_USER_REGISTRATION` | Worker 普通变量；默认 `true` | 保留展示兼容配置；普通 `/api/config` 始终关闭注册，只有空库且有效初始化凭据的浏览器临时看到可注册状态 | 不能用 `false` 开放公开注册；所有注册 API 仍要求独立初始化授权 |
| JWT access 密钥 | D1 `jwt_keys.access_secret` | 空账户库首次使用时生成并持久化，供普通 API、文件接口和 DO 共用；也用于短期 token 和 API Key 包装密钥派生 | 新环境无需手动配置；必须随数据库保留，不可作为缓存删除 |
| JWT refresh 密钥 | D1 `jwt_keys.refresh_secret` | 与 access 分别随机生成，后续稳定复用，不自动轮换 | 每个环境使用自己的 D1，避免环境间共享密钥 |
| `CORS_ALLOWED_ORIGINS` / `ALLOWED_ORIGINS` | 逗号分隔的 origin；前者优先，只有未配置时才读取旧名 | 缺失、空值或 `*` 为 Any；显式限制列表没有有效项时拒绝所有跨源访问；不启用 credentials | 生产为注释示例，本地显式为空；主入口、DO、错误及预检共用同一策略；WebAuthn origin 另行校验 |
| `REQUIRE_EMAIL_VERIFICATION` | 当前支持 Secret 或普通变量 | 默认 `false` | MVP 保持 `false`；这不替代受控账户初始化与关闭公开注册 |

生产 `vars` 不再保存所有者邮箱。`secrets.required = ["DOMAIN", "ALLOWED_EMAILS"]` 声明必需的运行时名称，部署工具负责首次随代码写入；不需要为配置 Secrets 先创建一个空 Worker。`OWNER_SETUP_TOKEN` 只用于初始化，不是常态请求的必需项。

邮箱白名单也用于既有改邮箱流程的目标地址检查。要更换账户邮箱，先将 GitHub/Worker 的 `ALLOWED_EMAILS` 更新为新目标，再由已登录客户端完成改邮箱验证；配置更新本身不重命名账户、不影响原邮箱登录，也不绕过客户端密钥重包裹。

部署工具把公开 URL 写为 `DOMAIN`；只在环境变量显式提供非空值时更新 `ALLOWED_EMAILS`、`OWNER_SETUP_TOKEN`，否则继承已有 Worker Secrets。临时 JSON 文件限制为当前用户可读写，成功或失败后均删除。GitHub 不保存派生的 DOMAIN；应用凭据也不进入交付产物。`keep_vars: true` 不负责把旧普通变量转换为 Secret；已部署实例需要核对同名旧变量，避免两个来源。

本地配置继续直接提供虚构邮箱和 localhost，日常启动不需要 `.dev.vars`。只有首次开户需要把本地 `OWNER_SETUP_TOKEN` 放入被 Git 忽略的 `.dev.vars`；邮件、推送等可选服务也在需要联调时配置凭据。新环境不用提供 `JWT_SECRET`、`JWT_REFRESH_SECRET`。

客户端会从 `/api/config` 得到公共 URL。将 `DOMAIN` 设为 Secret 是存放选择，不会隐藏服务地址。部署工具优先使用唯一 custom-domain 路由，未配置时通过 Cloudflare API 查询账户子域名并生成 workers.dev 地址；同一个结果用于运行时 DOMAIN 与健康检查，不读取远程 Secret。

首次开户时访问同源 `/setup`，验证初始化令牌后，服务器签发绑定 DOMAIN 与所有者邮箱、有效期 10 分钟的 HttpOnly、SameSite=Strict Cookie；HTTPS 下另带 Secure。页面随后进入固定 Web Vault 的 `/#/signup`。客户端生成主密码验证材料和加密密钥，注册请求必须同时满足授权、精确邮箱与空库条件。成功后清除 Cookie；数据库索引拒绝并发第二账户。该凭据不能用于读取密码库或刷新登录会话，`/api/config` 的个性化注册状态也禁止缓存。令牌过期但未开户时重新访问 `/setup` 即可。CLI 可在同一接口通过 `X-Raywarden-Setup-Token` 显式提交令牌，仍执行相同的授权和空库检查；不建议把令牌直接写入会留下历史的命令行。

已有环境首次建立 `jwt_keys` 时，如完整提供两个非空旧 JWT Secret，保留原始字节写入一次；只提供一个或空值会报错。D1 已有密钥后直接复用并忽略旧环境值，即使环境中只剩一个旧值也不会阻断。并发初始化重读同一条成功写入的记录，数据库查询错误不会触发重新生成。保留已有 `.dev.vars`，无需为了启动重新整理它。

随机初始化只允许没有用户及 API Key 的库。已有用户或 API Key 却缺失 `jwt_keys` 时会拒绝持久化替代密钥；恢复原密钥行，或提供成对的原始旧 Secret 后再启动，不要通过删行尝试重置。新 API Key 密文使用 `v2.` 前缀及按用途分离派生的包装密钥；旧格式仍可读取，不要求重新生成 API Key。

这个选择省去手动签名密钥配置，同时意味着完整 D1 导出包含签名密钥，隔离程度低于外部 Secrets。保管数据库备份时应按同等级敏感材料处理。丢失或更换 access 密钥还会影响已有 API Key 密文，恢复时必须保留 `jwt_keys` 原行；它不是可重建的域名缓存。

## 4. 核心参数与单用户取值

| 名称 | 当前默认 / 读取来源 | 对齐后的处理 |
| --- | --- | --- |
| `JWT_DURATION_SECONDS` | `3600`，普通变量 | access token 有效秒数，必须是正整数且计算到期时间不溢出；非法值拒绝加载配置；refresh 固定为 30 天 |
| `IMPORT_BATCH_SIZE` | `30`，普通变量 | 保留，导入性能按 J04 后续样例验证 |
| `TRASH_AUTO_DELETE_DAYS` | `30`，普通变量 | 保留；非正值关闭回收站自动清理，不等于关闭其他清理任务 |
| `AUTHENTICATOR_DISABLE_TIME_DRIFT` | `false`，普通变量 | 先保留当前行为；I04 验证窗口与重放规则 |
| `HEAVY_DO_ENABLED` | 有 binding 且未显式关闭时启用，Rust dispatch 读取 | 保留现有机制；MVP 启用与否通过实际构建/运行确认，不删除 DO 实现 |
| `HEAVY_DO_SHARDS` | 代码回退 `16`，范围 1–64 | 生产和本地均显式设为 `"1"` |
| `LOG_LEVEL` | 普通变量；默认 `info` | 支持全局等级及 auth/api/db/external/notify 覆盖，如 `info,auth=debug`；两套配置均显式为 `info`；解析与分类规则见第 5.2 节；Worker、cron、DO 每个实例初始化一次 |
| `KDF_ITERATIONS` / `KDF_MEMORY` / `KDF_PARALLELISM` | Config 当前默认 `600000` / `64` / `4` | 具体客户端 KDF 以账户记录为准，不把这三项直接当作 Argon2id 的一组初始化参数；真实客户端派生与解密仍需验收 |

单用户是账户与数据约束，不以 DO 分片数实现。`HEAVY_DO_SHARDS=1` 只收敛 CPU 卸载实例数量，不会阻止第二个用户创建。

时间格式没有运行开关。Rust 直接使用 Jiff 1，服务端新写入的时间固定为 UTC 三位毫秒 `...SS.mmmZ`，需要微秒的 API 日期字段固定为六位；不依赖本地时区数据库。已有时间字符串保留原值，到期和清理 SQL 按 `julianday` 比较时间点，兼容旧偏移表示，不能改回字符串字典序比较。

## 5. 扩展能力配置

保留现有实现与绑定。下表中的“后续验收”表示尚未纳入 MVP 的真实环境或客户端验收，不表示当前路由已被服务端关闭。展示开关和服务端授权分别处理。

| 能力 | 当前支持的配置 | 本轮对齐范围 |
| --- | --- | --- |
| 附件 | `ATTACHMENT_MAX_BYTES`、`ATTACHMENT_TOTAL_LIMIT_KB`、`ATTACHMENT_TTL_SECS`；普通变量 | R2 流式分块上传；TTL 默认 60 秒；大小与配额仍按 K 阶段验收 |
| File Send | `SEND_MAX_BYTES`、`USER_SEND_LIMIT_KB`；普通变量 | R2 单文件默认/上限 95 MiB；KV 上限 25 MiB；后续验收 |
| 管理事件通知 | `NOTIFY_LEVEL`、`NOTIFY_EVENTS`；通道为 `WEWORK_WEBHOOK_URL` 或 `TELEGRAM_BOT_TOKEN`＋`TELEGRAM_CHAT_ID`，支持 Worker Secret | 支持下方全部标准事件、等级与旧名兼容；默认不选事件，不发送；本地为 warning/none；与收件人验证码投递分离，真实外发尚未验收 |
| 收件人邮件 | `MAIL_WEBHOOK_URL`、`MAIL_WEBHOOK_TOKEN`；支持 Secret/普通变量 | MVP 不要求；N 阶段接入真实按 `to` 投递的网关 |
| 移动推送 | `PUSH_ENABLED` 普通变量；`PUSH_INSTALLATION_ID`、`PUSH_INSTALLATION_KEY` 为 Secret | 默认关闭；后续单独启用 |
| 推送地址 | `PUSH_RELAY_URI`、`PUSH_IDENTITY_URI`；普通变量 | 默认使用现有代码的 Bitwarden relay/identity 地址；不因单用户改动 |
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

本轮已接入下列配置。生产的新增可选项都保留为注释示例，配合 `keep_vars: true` 沿用 Dashboard 已有值；取消注释才改由仓库值管理。本地显式记录默认展示、CORS 和通知选项，邮件可用性仍自动判断。

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
| `CLIENT_SUPPRESS_ONBOARDING` | `false`，独立于注册设置 | 输出 `settings.suppressOnboardingInterstitials`，由客户端抑制 onboarding 提示 |

样式由 Rust 动态生成，ETag 取决于实际 CSS 内容；响应使用 `public, no-cache` 并按当前配置重新校验，CSS 输出变化后不会继续命中旧 ETag。`CLIENT_SUPPRESS_ONBOARDING` 不再写入 `disableUserRegistration`，两者可分别配置。

这些选项只控制展示，不替代后端能力、认证或权限检查。显示 SSO、YubiKey、Duo、紧急访问等入口不会实现对应后端；关闭 Send、Passkey 或密码提示样式也不会禁用其 API。单用户与受控初始化由独立服务端检查和数据库约束实现，不依靠这些样式开关。

### 5.2 日志过滤

`LOG_LEVEL` 格式为 `全局等级[,模块=等级...]`。等级为 `off/error/warn/info/debug/trace`，默认 `info`；模块名为 `auth/api/db/external/notify`。例如：

```text
LOG_LEVEL=info,auth=debug,external=debug
LOG_LEVEL=off,auth=debug
```

模块等级覆盖全局值，因此全局 `off` 时仍可单独开启模块。非法或缺失的全局等级回退 `info`；未知模块和非法模块等级忽略；重复模块使用最后一个有效配置。等级、模块名忽略大小写及首尾空白。

| 模块 | 实际日志分类来源 |
| --- | --- |
| `auth` | 账户、身份、设备/会话、邮箱、2FA、WebAuthn、限流等 API 模块，以及 crypto/jwt/jwt_keys/webauthn 基础模块 |
| `api` | 入口分流、HeavyDo、普通 API 及 Send 用例；更具体的分类优先 |
| `db` | models、infra::db，以及 Send 的 store/rotation |
| `external` | infra::storage 与 API meta 模块 |
| `notify` | 邮件/管理事件投递、实时通知、推送及 NotifyDo |

具名日志 target 优先；普通日志按真实 Rust `module_path` 归类，不要求每个调用重新标记。未归类日志使用全局等级。Worker、cron 和 DO 复用每实例一次的初始化；这不修改 Cloudflare invocation logs、observability 配置或浏览器 console 输出。

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

`CORS_ALLOWED_ORIGINS` 是主名称，只有它未配置时才回退 `ALLOWED_ORIGINS`；主名称显式为空仍优先于旧名，结果为 Any。缺失、空值或列表含 `*` 时允许任意来源；其他值按逗号分隔解析 origin，允许显式 `null`，不接受凭据、路径、query 或 fragment。无效项忽略；显式限制列表若没有有效项则拒绝全部跨源访问，不自动放开。

主入口、Axum、通知 DO、错误响应和预检共用 `CorsPolicy`。Any 返回 `Access-Control-Allow-Origin: *`，限制列表仅回显匹配的来源；两种模式都不启用 credentials，客户端仍使用显式 bearer 认证。WebAuthn origin 校验独立存在，不能以 CORS 允许替代。

`DEMO_PAGE_ENABLED` 默认 `false`，本地显式关闭、生产仅注释示例。开启后由 Rust 的 `/demo.html` 动态提供可选测试页，关闭时返回 404；响应设置 CSP 和 `no-store`，页面不进入不受此开关控制的静态 assets。测试页的业务请求仍受现有 API 鉴权和校验，不提供初始化授权旁路，也不为旧 TOTP URL 新增后台兼容别名。页面可见不代表真实客户端流程已验收。

附件与 Send 的文件协议、签名校验和元数据提交均由 Rust 处理。共享存储层使用 R2 8 MiB 分块和 KV 25 MiB 有界回退；下载统一处理单范围、If-Range、HEAD 与 416，R2 原始流在最终 Worker 响应边界交给运行时。分块大小是实现常量，没有新增运行配置项。

## 6. 本地与生产边界

| 环境 | 配置 | 入口与约束 |
| --- | --- | --- |
| 本地 | `wrangler.local.jsonc` | `just dev` 准备 UI、自动应用本地迁移后启动；数据库和文件使用本地模拟资源，`just db-migrate` 默认 local |
| 生产 | `wrangler.jsonc` | 自定义域名及既有 D1/R2/DO；远程数据库仅由显式 `just db-migrate production` 或完整部署流程操作 |

未完成的远程 `env.dev` 和相关命令、工作流选择项已移除。所有远程命令固定生产，Wrangler 参数显式使用 `--env ""`；本地开发仍使用 `just dev`，两者不同义。未来若需要远程测试环境，再为独立资源和路由增加完整配置。

`$schema` 已启用，供编辑器补全和校验。`assets.run_worker_first` 声明动态路径优先进入 Worker，包含 `/two-factor/*` 和动态 CSS；它不是请求白名单，未匹配的请求仍按正常静态资源路由处理。DO 的 `migrations` 管理类迁移，D1 结构由 `sql/migrations` 管理。

按本轮确认保留 `keep_vars: true`，继续沿用 Dashboard 中可能存在的普通变量。未来若要完全由配置文件管理，先核对并收回这些变量，再取消开关；Secrets 继续独立管理。本次没有读取或更改远程变量。

## 7. 构建和部署入口

| 项目 | 来源 / 命令 | 规则 |
| --- | --- | --- |
| Rust | `rust-toolchain.toml`，`just setup` | channel、components、targets 一处声明，原生 rustup 安装；不手写 channel 解析 |
| Rustup 代理 | `Justfile` PATH 与 unexport | 优先项目 .tools/bin 和 Cargo bin 目录，避免 mise shim 重新注入其他 channel；清除继承的 RUSTUP_TOOLCHAIN，让项目文件生效，不改用户默认工具链 |
| Node | `.node-version` | setup-node 先安装 Node，再读取 package 中的 just 版本 |
| 依赖锁 | `Cargo.lock` / `package-lock.json` | npm ci 和 Cargo --locked 原生约束；主动更新用 just lock 并审阅提交 |
| 检查 / 打包 | `just ci` / `just build` | 直接执行原生命令；Wrangler custom build 同样调用 just build |
| 真实 WASM 回归 | 构建后 `just test-worker` | workerd test 无监听、无外网，使用临时 SQLite 执行真实 SQL，R2/KV 使用内存测试绑定；Integration 在 dry-run 后运行，不连接真实 D1/R2 |
| 环境诊断 | `just doctor` | 直接列出版本及已装 target；不以版本存在代替编译或运行通过 |
| UI | `just ui` / `ui-download` / `ui-archive` | Bash 管下载/暂存/替换，patch-ui.mjs 管版本与 HTML；源 CSS/JS 为 static/overrides |
| 本地 D1 | `just db-migrate` 或 `just db-migrate local` | 直接原生 migrations apply；dev 自动调用；新库执行 0001–0010，不创建账户 |
| 远程 D1 | `just db-migrate production` | 显式选择生产，原生 apply；新基线不提供旧库原地升级或历史映射 |
| 后续迁移 | `sql/migrations/0011+` | 在当前链上追加；Wrangler 按实际执行管理 d1_migrations，不忽略迁移失败 |
| 结构快照 | `just schema` / `just test-sql` | Python 3 在内存 SQLite 应用完整迁移，导出应用 DDL；SQL 测试检查漂移；不含业务数据、种子或迁移历史，不是完整备份 |
| 全局等价域名 | 运行时自动获取并缓存到 D1 | 首次需要时补齐，成功后 24 小时内复用；失败保留旧数据、稍后重试；不再生成或导入 SQL |
| 资源与部署 | `just config` / `just resources` / `just deploy` | 固定生产；config 仅读文件，resources 查询已有资源，deploy 迁移生产库并上传和健康检查 |
| 部署依赖 | `just setup-deploy` | 仅 npm ci，不装 Rust、不重编译 |
| 工作流 | Integration / Coverage / Cloudflare | 分别构建、覆盖率、复用产物部署；不在 CI 生成缺失锁 |
| 交付范围 | 最终 bundle、Web Vault、两份锁和清单 | 保留 commit/env/config 摘要及最终文件哈希；不上传原始 build，不遍历全源码哈希 |
| 预构建上传 | `scripts/deploy.mjs` | 在部署代码内流式调用项目 Wrangler，失败传播；不保留独立 runner 或无调用方的输出捕获分支 |
| 本地私密配置 | 被 Git 忽略的 `.dev.vars` | 日常启动不需要；首次开户配置 OWNER_SETUP_TOKEN，邮件、推送等按需配置 |
| 日志 / 缓存 | `WRANGLER_LOG_PATH` / `XDG_CACHE_HOME` | 默认项目 .wrangler/logs 和 .tools/cache；保留显式覆盖 |
| 部署凭据 | `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` | 部署使用，不写入应用 D1；按目标环境配置 |

`Justfile` 优先 Cargo 原生代理目录并清理继承的 Rust 工具链覆盖值。本机此前 `just doctor` 已确认项目 nightly-2026-11-13 和 WASM/host target 选择正确。最新测试、编译和打包证据见 [执行记录](implementation-plan.md#8-执行记录)。

`sql/schema.sql` 是 10 份迁移派生的结构快照，不参与应用初始化或升级。当前链包含 19 表、38 个显式 DDL 对象；真实 D1 和客户端闭环仍需另行验收。更早旧历史库没有自动转换路径，未清库或改写实际用户数据库。迁移规则见 [目录说明](../sql/migrations/README.md)。

## 8. 已实现的账户规则与后续验收

严格单邮箱、关闭公开注册、独立所有者初始化授权和数据库唯一用户约束已纳入实现。初始化授权统一保护所有注册别名，已有账户不能再次注册；历史多用户库在唯一索引迁移处停止。开户检查不会改写既有登录和邮箱变更的事务，也不会因改配置自动拒绝旧账户登录。

仍需分别处理或取证：

1. D05：服务端 verifier 仍固定使用 PBKDF2 100,000 次，尚无逐账户迭代记录和成本升级；不能直接调大常量，否则会破坏现有账户验证。
2. D09：未知邮箱仍返回 PBKDF2/600,000，真实账户使用不同 KDF 时存在可区分性；应只改未知账户的回退策略，保留真实参数与数据库错误传播。
3. G08：固定 Web Vault 和一个扩展完成真实初始化、登录、密文解密、同步、刷新与撤销，并验收唯一账户和数据归属保护。
4. 邮件、推送、DO/R2 和隔离恢复仍需真实环境验收，不能以编译或内存测试代替。

本轮验证结果见 [Rust 重构设计与记录](rust-refactoring.md)，功能边界见[功能审计](feature-parity.md)。
