# Raywarden 与 ww1 / ww2 功能移植审计

更新日期：2026-11-18。最新 ww1 的主要账户加密、密码库及文件变化已补入 Rust；配置、管理通知和受控单用户初始化已补齐；本轮完整 CI、真实 Worker 和部署预演的结果见下文。当前状态见第 0 节，后文保留早期审计证据，不将隔离回归等同完整客户端或生产验收。

原审计对照 HTTP 方法与路径、handler/controller、模型 SQL、当时的 JS 文件流、DO、数据库结构、配置、静态资源及工作流。审计阶段只修改文档，没有修改业务代码、用户数据库或线上资源；后续实现变化在下文另行说明。

## 0. 本轮 ww1 更新对齐

上一轮对照本地 ww1 `ab378e5c263e1cf943de3722944cf2906ff763bf` → `31359e3a10bd75f8c1a2b9d32a660da07730f427`，该轮修改前的源码保存在 `.raywarden-backups/20261117T082733Z-ww1-sync/source.tar.gz`。本轮继续核对 ww1 `31359e3`、ww2 `7a9f6b9`，不修改参考仓库或访问远程。原 Rust 入口、D1 迁移链、R2/KV 流式路径及三工作流分工继续保留。本文 P/D 编号沿用历史功能审计，不等同于重构设计中的任务编号。

下表维护位置均相对 `src/`，反映当前拆分后的目录。

| 能力 | 本轮实现 | 主要维护位置 |
| --- | --- | --- |
| V1/V2 账户材料 | 兼容注册、首次 keys、签名公钥/签名密钥对、安全状态、profile/sync/token 输出；拒绝部分 V2 材料、降级及轮换时替换公钥身份 | models/account_keys.rs、models/user/、api/controller/accounts/extras/identity/sync |
| 两种密钥轮换 | 密码连同用户 key 轮换、纯 key/升级；完整 Cipher/Folder/附件/Send/PRF 集合校验、账户和逐行快照、随机写入 token、同事务提交；升级桥接材料与重放检查 | api/service/account_keys.rs |
| 凭据与设备代际 | 密码/KDF/邮箱修改比较已验证的 verifier、账户材料和设备 nonce；清理旧 remember/升级材料；有效 PRF 仅重标记相同旧代际的 user-key wrapper，不重写其密文 | api/service/account_keys.rs、models/email.rs、models/webauthn.rs、models/auth_request.rs |
| 客户端门槛 | 凭据验证成功后检查版本；V2 普通客户端最低 2026.10.1，桌面最低 2026.10.2；提供 OAuth 错误码；固定 Web Vault 的条件不兼容见下表 | api/controller/identity.rs |
| Cipher 新模型 | 类型 1–8、blob 密文与 500,000 字节上限、历史活动类型空/数组字段的兼容对象、加密用户/key ID 校验、旧 UUID key ID 精确匹配兼容 | models/cipher/ |
| Cipher 写入一致性 | 创建/完整编辑/partial/bulk/归档/Folder/import 在同一事务检查会话、账户及资源快照，写入后推进严格递增游标；attachments2 与 Cipher 原子更新 | api/service/cipher_mutation.rs、api/controller/ciphers/folders/archive/import |
| 导入与归档 | 组织导出转个人、合法 folderId 回退、归档输入和取消归档、分块准备后一次事务提交 | api/controller/import.rs、api/controller/ciphers.rs |
| 大密码库读取与轮换 | 逐行读取与绑定，避免整库 JSON 成为单个 SQL 值；坏行整体报错，不静默漏项；不保留只供测试使用的旧聚合投影 | models/cipher/、api/service/account_keys.rs、send/rotation.rs |
| 附件 URL 与上传 | 列表/sync 提供不带 token 的稳定 URL，鉴权 metadata 签默认 60 秒能力；随机暂存 key、账户/资源快照提交指针；Bearer multipart 支持已完成附件替换，Azure 仅完成 pending；旧 capability 无新增 issuer 限制 | api/controller/attachments.rs、models/attachment.rs |
| Send 访问与轮换 | 领访问 token 不计数；实际文本/有效文件授权原子计数；错误 file ID、元数据及存储缺失不扣；轮换只改包装 key、revision 及内部撤销 stamp | send/{http,access,token,upload,store,rotation}.rs |
| 文件替换及清理 | 独立暂存对象与指针 CAS；失败/并发输家保旧文件，数据库提交结果不确定时先查引用；D1 删除/替换触发器持久登记任务，按 generation 确认，存储故障可重试 | infra/storage/cleanup.rs、sql/migrations/0009_file_lifecycle.sql（仓库根目录） |
| 通知 | 资源级 Cipher/Folder/Send 事件，批量同步事件；匹配身份的旧连接先收 LogOut 后关闭，升级/轮换 Reason=1；管理事件分类与筛选见本轮配置表 | api/service/notifications.rs、api/service/mutation.rs、infra/admin_notify.rs、durable/notify_do.rs |
| 2FA 与兼容入口 | TOTP step 原子消费、配置/停用 snapshot 与事务断言、受会话/用途/key/状态约束的短期 proof；SessionSnapshot 不依赖 API Claims；Email proof 在 service 共享；修复 Email/WebAuthn-only 状态误报 | models/twofactor.rs、models/device.rs、api/controller/twofactor.rs、api/service/twofactor.rs |
| 配置 | CLIENT_FEATURE_FLAGS 白名单、macOS/V2 注册可选 flag、自动填充规则 URL 校验、config no-store 与错误响应兼容 | api/controller/config.rs、api/response.rs、infra/config.rs |

新增 `0008_account_encryption.sql` 和 `0009_file_lifecycle.sql`，不重写已存在的 `0001`–`0007`。前者只补结构和现有 PRF 代际，不清空旧 key ID，也不自动把 V1 账户升级到 V2。随后追加 `0010_single_user.sql`，以唯一索引限制用户总数；当前结构快照为 10 份迁移、19 表、38 个显式 DDL 对象，尚未应用到用户实际数据库。

两种轮换入口限制为 16 MiB，完整集合在一个事务提交。逐行方案避免 [D1 单值/行 2 MB、函数参数 32、绑定参数 100 的限制](https://developers.cloudflare.com/d1/platform/limits/)，不代表取消平台的查询数、总响应大小或 CPU 限制。

### 保留的设计差异

- 继续保留 Ray 更严格的设备 nonce/security stamp：普通轮换撤销旧会话，不移植 ww1 的旧 access 宽限期。强制 V2 升级、SDK key rotation、no-logout/JIT 升级 flag 不对外宣告；macOS 凭据同步和 V2 注册仅显式选择启用。
- 继续保留 Send 短期下载能力的禁用/过期/轮换撤销检查，不因参考放宽而削弱现有行为；内部 access_stamp 的轮换不覆盖用户内容或访问策略。
- 兼容未提供 encryptedByKeyId 的旧客户端。快照保护请求执行期间的账户代际，无法证明一个省略 key ID 的客户端在新请求开始前是否已同步。
- 文件 capability 仍按各自协议授权，不将缺少设备字段的历史附件 token 伪装成 bearer session。每个上传 key 只用一次，D1/R2 之间没有分布式事务；删除任务不是备份。
- 2FA proof 是有时限、用途和状态约束的能力，不宣称每次只能消费一次。通知仍尽力投递，不能替代手动同步或可靠消息队列。
- 不照搬 ww1 的部署 baseline 脚本、仓库内预编译 Web Vault、静态域名种子或 JS 入口。项目继续固定前端版本、自动域名缓存、原生追加迁移和生成入口。

### 本轮配置能力补全（2026-11-18）

以下实现已通过本轮 Rust 114、JS 52、SQL 104 和真实 Worker 92 项检查，release 与两种部署预演也已通过，详见[第四轮实施记录](rust-refactoring.md#12-第四轮实施记录2026-11-18)。不据此宣称浏览器交互、真实通知外发或生产部署已经验收。

| 能力 | 当前实现与边界 | 维护位置 |
| --- | --- | --- |
| 模块日志 | `LOG_LEVEL` 支持全局级别及 auth/api/db/external/notify 覆盖，按现有 target/module_path 分类；最大级别包含模块覆盖，支持 `off,auth=debug`；无效全局回退 info，未知模块和无效覆盖忽略 | [logging.rs](../src/infra/logging.rs) |
| CSS 展示矩阵 | 读取 `VW_CSS_*` 展示开关、自定义 CSS 加载与旧 Passkey 变量别名；ETag 随实际输出变化。显示 SSO、Duo、YubiKey 或紧急访问入口不等于新增这些后端能力，注册样式也不授权注册 | [service/ui.rs](../src/api/service/ui.rs)、[controller/presentation.rs](../src/api/controller/presentation.rs) |
| 客户端引导 | `CLIENT_SUPPRESS_ONBOARDING` 独立输出 `settings.suppressOnboardingInterstitials`，不再合并成注册禁用；固定前端包含该设置的消费者，实际页面效果仍需浏览器验收 | [controller/config.rs](../src/api/controller/config.rs)、[service/ui.rs](../src/api/service/ui.rs) |
| 管理事件（原 D13） | 补入 ww1 的 24 类事件及 `NOTIFY_LEVEL` 分级，与 `NOTIFY_EVENTS` 联合筛选，保留旧 Ray 事件过滤兼容；登录、刷新、同步、设备审批、Passkey、密码库、Send 和账户/2FA 操作接入实际结果。消息仅含事件名、级别和账户 ID，刻意不复制邮箱/IP/UA 等上下文；通道外发尚未验收 | [admin_notify.rs](../src/infra/admin_notify.rs)、各业务提交后的 emit 调用 |
| CORS | `CORS_ALLOWED_ORIGINS` 优先，保留 `ALLOWED_ORIGINS`；Axum、入口错误、预检和 DO 共用策略。显式无效列表不回退为允许所有，不启用 Cookie credentials | [cors.rs](../src/infra/cors.rs)、[dispatch.rs](../src/dispatch.rs) |
| 演示页 | `DEMO_PAGE_ENABLED` 默认关闭，由 Rust 控制 `/demo.html`，前端准备时移除静态副本；演示调用现有受保护接口，不豁免 API 鉴权，TOTP 使用当前 proof 流程 | [controller/demo.rs](../src/api/controller/demo.rs)、[prepare-ui.sh](../scripts/prepare-ui.sh)、[demo.html](../static/demo.html) |
| 生产域名与交付 | 生产 `DOMAIN` 由 Worker Secret 提供；部署从唯一 custom-domain 路由推导健康地址，不读 Secret。本地仍用 localhost；三工作流和精确提交/产物摘要绑定继续保留 | [运行配置](runtime-config.md)、[部署说明](deployment.md) |

### 尚未移植或验收

P01/P02/P03、D01/D02/D04/D06/D07/D08/D10/D11 的上述实现已补入，具体回归结果见[最新执行记录](implementation-plan.md#8-执行记录)。D03 已补 TOTP proof；新版 ww1 的 get-* 不接受 proof 自我续期，Ray 也维持此规则，因此早期表中的 Email get-proof 差异不再成立。D12 的资源事件、凭据 Logout 和恢复删除通知已补，真人双端仍未验收。

| 条目 | 当前结论与影响 | 证据与后续边界 |
| --- | --- | --- |
| **P04：单用户与受控初始化** | **已实现并通过隔离回归。** 单一完整邮箱必需、精确匹配；独立 OWNER_SETUP_TOKEN 经 `/setup` 签发 10 分钟 HttpOnly/SameSite 初始化凭据；所有注册与注册邮件准备入口共用授权和空库保护。普通访客始终关闭注册，配置开关不能旁路；数据库最多一个用户 | [初始化授权](../src/api/service/setup.rs)、[register](../src/api/controller/accounts.rs)、[唯一索引](../sql/migrations/0010_single_user.sql)。真实 Worker 覆盖全部别名、失效/用途混用、代码消费、初始化后关闭与并发 200/409；原多用户隔离 fixture 显式模拟异常历史库，专门约束用例始终保留真实索引 |
| D05：服务端 verifier 成本与升级 | **真实缺口。** Ray 固定使用服务端 PBKDF2 100,000 次，无 `password_iterations`；已实现 salt=NULL 的旧原始 verifier 条件升级，不能说完全没有迁移。两参考保存迭代次数并支持成本升级；这与客户端 PBKDF2/Argon2 参数不同，不阻止由 Ray 正常创建的现有账户登录 | [crypto](../src/infra/crypto.rs)、[credentials](../src/models/user/credentials.rs)、[当前 CAS 迁移](../src/models/user/store.rs)、[ww1 password](../../ww1/src/password.rs)。补字段时必须把旧 Ray 行识别为 100,000 次，并统一所有凭据写入、验证和条件升级；直接改固定常量会破坏旧账户登录，参考数据库也不能直接导入 |
| D09：未知邮箱 KDF 策略 | **真实隐私差异。** 未知邮箱仍固定返回 PBKDF2/600,000，真实账户使用 Argon2 或非默认参数时更容易被区分；ww1 按持久密钥与邮箱稳定选取常见参数，不保证完全消除枚举 | [prelogin](../src/api/controller/accounts.rs)、[KDF 查询](../src/models/user/store.rs)、[ww1 策略](../../ww1/src/handlers/accounts.rs)。后续仅替换无账户时的回退，保留真实账户参数、邮箱归一化及数据库错误传播 |
| V2 与固定 Web Vault | **条件不兼容。** 当前前端固定 2026.7.0，实际发送同版本的 `Bitwarden-Client-Version`；V2 账户门槛为普通客户端 2026.10.1、桌面 2026.10.2，因此 V2 账户不能用当前固定前端登录。V1 账户不受这项最低版本限制 | [固定版本](../package.json)、[版本门槛](../src/api/controller/identity.rs)。保留升级/注册 flag 的显式选择，在固定并验收匹配前端前不能称 V2 Web Vault 已可用；不伪造版本头、不自动追踪新版 UI |
| 旧 TOTP request/enable/disable | **仍有协议差异，但不阻断当前固定 Web Vault。** 前端实际使用 get-authenticator＋PUT/DELETE authenticator；三条旧路径另有 pending secret、code、otpauth/QR 状态流，不能直接绑定到现有不同请求体的 handler | [当前路由](../src/api/routers/twofactor.rs)、[当前 proof 流程](../src/api/controller/twofactor.rs)、[ww1 旧流程](../../ww1/src/handlers/two_factor.rs)。若补兼容，须保留会话/proof、并发快照及启用状态保护，不复制较弱的仅会话设置边界；demo 不依赖这三条旧路径 |
| set-password | **真实但独立的协议缺口。** ww1 仅允许主密码和私钥均为空的既有账户初始化；Ray 的普通注册要求非空 verifier 和 wrapped key，当前完整注册/改密不依赖该路径。它不是 change-password 或空库所有者初始化的别名 | [注册数据](../src/models/user/requests.rs)、[账户路由](../src/api/routers/accounts.rs)、[ww1 post_set_password](../../ww1/src/handlers/accounts.rs)。若未来确实引入这种未初始化账户，需新增只允许目标空状态的条件提交及重放/并发测试，不能直接复用普通改密 |

组织/SSO/企业与紧急访问后端仍不在范围内，CSS 开关不改变此边界。严格设备 nonce/stamp 与轮换撤销仍是有意差异；参考的每条辅助入口、Cookie/大小写和前端补丁没有全部复制。当前尚未发现除上述条件外、可单凭这些缺路由就断言现有 V1 个人密码库基础链路必然失败的证据；仍需目标客户端实际验收。

本轮 Rust 119、JS 65、SQL 108 和真实 Worker 100 项回归通过，发布构建、普通 dry-run 和 artifact 校验通过；部署临时 Secrets 亦有针对性回归。结果见[第五轮实施记录](rust-refactoring.md#14-第五轮实施记录2026-11-18)。真实云端 D1/R2/DO、邮件/推送、目标版本真人客户端、旧迁移历史转换和生产部署仍需分别验收，不采用参考仓库测试计数当作本仓已验证。

另外使用真实Chromium与固定Web Vault2026.7.0，通过临时HTTPS环境完成UI开户、登录、保存密码项、刷新解锁、退出重登及两次原始字段解密比对；由此发现并修复本地HTTP入口不兼容。退出时短暂的空账户控制台错误仍作为非阻断前端兼容项记录；此结果不代替远程资源、扩展双端和V2客户端验收。

**以下第 1–8 节保留最初审计基线和反例，P/D 的当前状态以上述同步记录为准。旧路径计数不作为本轮完成率。**

## 1. 对照基线与统计口径

| 仓库 | 本地 HEAD | 实际审阅内容 |
| --- | --- | --- |
| ww1 | `ab378e5c263e1cf943de3722944cf2906ff763bf` | 干净工作树，包括近期兼容性测试与合入记录 |
| ww2 | `7a9f6b9e3cb46449f50df33d7577481ccb9f1b71` | 干净工作树，包括 JS streaming、DO 与运维工作流 |
| raywarden | `e89200f62624f8e5c389d5f4a9af3c3caca8983e` | 审计时未提交工作树，包括此前移植与当时的单迁移链整理 |

这是本地检出版本的对照，没有联网更新参考仓库。参考代码自身也存在未实现功能及设计限制，不能视为完整 Bitwarden 服务端规范。

审计后，Ray 的迁移 DDL 已按原有结构重编排为 `0001_accounts.sql`–`0005_sends.sql` 新基线。旧迁移路径与列号不再适用，下文账户表链接已更新为当前文件；本次只重新分块现有 DDL，不修复下列业务缺口，原审计验证记录保留。

随后按项目决定，原 `src/worker/` 八个手写 JS 文件已迁入 Rust 并删除：Wrangler 使用生成的 `build/index.js`；`lib.rs`/`dispatch.rs` 负责入口和 DO 分流，附件/Send 完整路径进入 Axum，复用 JWT、通知、存储和 Range 模块。R2 分块上传和原生流下载、KV 25 MiB 回退均保留。这是运行结构收敛，**不代表 P01–P04、D01–D13 已修复**；原审计计数及反例保留，迁移后的验证另见执行记录。

下表保留原审计时的路由统计：解析多行 `.route` 和链式 HTTP 方法，并人工加入当时的 JS/DO 分流入口。参数名统一，末尾斜杠归一化并去重；不计自动 HEAD、CORS OPTIONS 或内部 fanout 端点。这个口径用于比较入口，**不表示运行时自动兼容末尾斜杠，更不表示行为相同**。

| 仓库 | Axum 方法＋路径 | 加入 streaming / 通知后 | 规范化路径数 |
| --- | ---: | ---: | ---: |
| ww1 | 162 | 164 | 128 |
| ww2 | 102 | 108 | 80 |
| raywarden | 157 | 168 | 130 |

按原审计口径，Raywarden 覆盖 ww2 的 108/108 个同名方法路径，覆盖 ww1 的 146/164 个；ww1 另有 18 项入口差集，见第 5 节。不能据此计算“功能移植完成率”：已经对上的路径中仍有字段丢失、状态转换和计数时机差异。

## 2. 功能域覆盖

“有实现”表示已追踪到实质处理和存储代码，不表示已经通过真实客户端或云端验收。“部分”对应后续确定缺口。

| 功能域 | 当前 Raywarden 覆盖 | 结论与缺口 |
| --- | --- | --- |
| 单用户、白名单与首次初始化 | 注册、邮箱配置、KDF 校验存在 | **部分**：缺 ww1 的精确白名单与数据库单用户约束；独立所有者授权初始化也未完成，见 P04 |
| prelogin、密码登录与 refresh | 实际 verifier、设备会话、JWT purpose/nonce/stamp、刷新与撤销 | 有实现；未知邮箱 KDF、部分表单/响应/Cookie 兼容不同，见 D09、第 6 节 |
| API Key / client_credentials | 加密保存、哈希验证、读取/轮换、设备会话绑定 | 有实现；不能因表结构不同判为缺失 |
| 密码、KDF 与账户密钥轮换 | 账户、Cipher、Folder、附件、Send 的更新及事务路径 | **部分**：Send 轮换语义、remember 清理和 verifier 升级不齐，见 D01/D04/D05 |
| 初始密钥对、userKeyId、公钥 | GET/POST keys、条件初始化、用户公钥与 key ID | 有实现；profile/sync 的 accountKeys 仍缺，见 D07 |
| Cipher 1–5 类、字段与单项 key | CRUD、partial、移动、批量删除/恢复、purge；key 在 data JSON 中保留 | **部分**：新类型 6–8、attachments2、加密上下文和完整归档输入缺口，见 P01/P02/D10/D11 |
| Folder | CRUD、用户归属、删除后 Cipher folder_id SET NULL | 有实现；缺 ww1 的 POST 更新别名，部分不存在资源的响应不同 |
| Archive | 单项和批量 archive/unarchive | 有实现；完整 Cipher 创建/更新/导入的 archivedDate 未同步，见 D11 |
| Import | 文件夹映射、用户归属、随机 ID、分批写入 | **部分**：组织导出转个人、直接 folderId 与归档输入未同步，见 D10/D11 |
| Sync 与等价域名 | profile、folders、Cipher JSON、Send、userDecryption、excludeDomains、排除全局组 | **部分**：accountKeys、新类型和大 JSON 容错缺口，见 P01/D07/D08；全局数据现已自动获取并缓存 |
| 附件 | V2 预留、Azure PUT、direct/legacy multipart、下载、删除、Range、R2/KV | 有实现；普通 Cipher 更新附件 key 缺失，旧 URL 与 TTL 有差异，见 P02、第 5/6 节 |
| Text / File Send | CRUD、密码、有效期、访问凭据、三种上传、范围下载、配额与清理 | **部分**：新版 token 访问次数和轮换行为不齐，见 P03/D01 |
| TOTP、remember、恢复码 | 设置、验证、停用、恢复与记住设备 | **部分**：原子消费、proof token、另一套管理流程与 remember 失效策略不齐，见 D02–D04 |
| 邮件 2FA / OTP / 账户邮件 | 按收件人投递、用途绑定、尝试/过期/消费、改邮箱、提示与恢复删除 | **部分**：注册 verified 入库、get-email proof 重用和恢复删除通知缺口，见 D03/D06/D12 |
| WebAuthn 2FA | 真正的挑战、attestation/assertion、签名与 counter、UV、用途/会话绑定 | 有实现，非占位；辅助响应差异及客户端联调仍待验证 |
| Passkey / PRF | 无密码 grant、PRF 包裹材料存储/更新、缺材料时主密码回退 | 有实现；未验证真实客户端，部分参考辅助响应字段未同步 |
| Devices / AuthRequest | known-device、列表、push token、请求/审批/轮询、5 分钟期限和一次性消费 | 有实现；Ray 保留更严格的设备/IP/stamp 校验；部分 ww1 别名未保留 |
| NotifyDo | SignalR MessagePack、匿名授权通知、WebSocket、保活与内部签名 | **部分**：资源级事件、LogOut 投递次序和管理通知覆盖不齐，见 D12/D13 |
| 移动推送 | installation OAuth、设备 UUID、注册/注销、事件发送 | 有实现，默认关闭；外部 relay 未联调 |
| HeavyDo | 固定数量分片、可关闭、复用同一 api::handle_request | 有实现；未照搬 ww2 无界用户名分片，属于有意收敛 |
| Turnstile | Siteverify、hostname/action、重放检测、短期证明、Send 验证页 | 有实现；完整部署与外部验证未联调 |
| 辅助接口与前端覆盖 | alive/version/now、tasks/events、图标、HIBP、CSS、用量、Apple association | 有实现；少量兼容入口与开关不齐，见第 5/6 节 |
| Cron / 生命周期 | 回收站、pending 附件、Send、AuthRequest、OTP、WebAuthn challenge 清理 | 有实现；生产定时执行与失败恢复需独立验收 |
| 构建与部署 | 原生工具、锁版本、单迁移链、构建/覆盖率/产物部署三工作流 | 已按项目要求重做；不是逐文件照搬参考仓库，见第 7 节 |
| 备份与恢复 | 已有边界说明 | **未移植自动化**：ww2 每日 S3/WebDAV 备份工作流未保留，不能宣称已有自动备份 |

## 3. 优先补齐的移植缺口

| ID | 缺口、触发与影响 | 代码证据 |
| --- | --- | --- |
| P01 | **Cipher 类型 6–8 缺失**：银行账户、驾照、护照在 ww1/ww2 已有。Ray 请求只接受 1–5；实际 sync/list 投影也不输出三类字段，但 config 仍宣告新类型开启。创建/导入失败，已有该类行的输出不完整。 | [ww2 类型与输出](../../ww2/src/models/cipher.rs#L149)、[ww1 类型字段](../../ww1/src/models/cipher.rs#L23)；[Ray 类型校验](../src/models/cipher.rs#L149)、[投影](../src/models/cipher.rs#L1096)、[功能开关](../src/api/controller/config.rs#L65) |
| P02 | **普通 Cipher 更新忽略 attachments2**：请求接收附件新加密名称和重包 key，却只保存 Cipher。返回成功后附件仍是旧 key/名称，存在附件解密失败风险。账户整体轮换的附件处理不能替代这条路径。 | [ww2 更新附件](../../ww2/src/handlers/ciphers.rs#L232)、[ww1 更新调用](../../ww1/src/handlers/ciphers.rs#L474)；[Ray 接收字段](../src/models/cipher.rs#L418)、[普通更新](../src/api/controller/ciphers.rs#L162) |
| P03 | **新版 Send 访问计数时机不同**：Ray 领 send_access token 就扣次数，同一 token 后续读取不再计数，并跳过次数检查；可在 token 有效期内重复读取/取得文件 URL。ww1 要求真正文本访问或有效文件访问时原子扣数，领 token、查看文件元数据、错误 file ID 均不应扣数。 | [ww1 HTTP 契约](../../ww1/tests/upstream_compat_http.mjs#L103)；[Ray 领 token 扣数](../src/api/service/send.rs#L171)、[token 后续访问](../src/api/service/send.rs#L128)、[处理器](../src/api/controller/sends.rs#L221) |
| P04 | **单用户约束未移植**：ww1 有 handler 检查和数据库 INSERT 触发器；Ray 只有 email UNIQUE 和可选 glob 白名单，缺配置会跳过白名单。多值/glob/缺配置时数据库可接纳第二用户。正常唯一精确邮箱配置下，同邮箱重复仍会被 UNIQUE 拒绝。 | [ww1 注册检查](../../ww1/src/handlers/accounts.rs#L812)、[单用户触发器](../../ww1/sql/schema.sql#L60)；[Ray 注册](../src/api/controller/accounts.rs#L117)、[配置读取](../src/infra/config.rs#L89)、[当前账户 DDL](../sql/migrations/0001_accounts.sql) |

`DISABLE_USER_REGISTRATION` 在 Ray 仍仅控制客户端展示。ww1 的注册 token 直接返回调用方，也不能替代独立所有者授权。当前项目要求的“服务端关闭公开注册＋受控首次初始化”仍未完成，不能只复制 ww1 的 token 步骤就标完成。

## 4. 其余确定的行为差异

| ID | 缺口与影响 | 参考 / Ray 证据 |
| --- | --- | --- |
| D01 | **Send 密钥轮换更新范围过大**：ww1 只重包 key 并改 revision；Ray 还要求 name/content 并覆盖 name、notes、data。ww1 兼容样例的 `must-be-ignored` 会被 Ray 存入。事务原子性不等于更新字段正确。 | [ww1 key-only 更新](../../ww1/src/handlers/sends.rs#L162)、[兼容断言](../../ww1/tests/upstream_compat_http.mjs#L148)；[Ray 轮换](../src/api/service/send.rs#L386) |
| D02 | **TOTP 并发防重放弱化**：ww1 条件 UPDATE 并检查只修改一行；Ray 先读 last_used 再无条件更新。同一步并发验证存在重复通过窗口，串行重放仍会被前置校验拒绝。 | [ww1 原子消费](../../ww1/src/two_factor.rs#L295)；[Ray 验证](../src/api/controller/identity.rs#L285)、[无条件更新](../src/models/twofactor.rs#L227) |
| D03 | **2FA 新 proof-token 流程不完整**：TOTP get/activate 未签发或接受 ww1 的 provider-specific proof；Email get-email 也不能用已有 proof 重取状态。其他 Email send/verify/disable 与 WebAuthn proof 已有实现。 | [ww1 TOTP proof](../../ww1/src/handlers/two_factor.rs#L245)；[Ray TOTP](../src/api/controller/twofactor.rs#L79)、[通用校验拒绝 token](../src/api/service/email.rs#L289) |
| D04 | **改密码/KDF 后 remember 凭据未清理**：旧 access/refresh 因 stamp 失效，但新密码＋原设备＋旧 remember token 仍可免 2FA。不能把它误报成所有会话撤销都失效。 | [ww1 清理](../../ww1/src/handlers/accounts.rs#L921)、[KDF 清理](../../ww1/src/handlers/accounts.rs#L1161)；[Ray 密码更新](../src/models/user.rs#L703)、[KDF 更新](../src/models/user.rs#L981)、[remember 校验](../src/models/twofactor.rs#L402) |
| D05 | **服务端 verifier 迭代记录/升级未移植**：两参考保存 password_iterations 并按已存迭代验证、升级；Ray WebCrypto 固定 100000，无独立迭代字段。这与客户端 PBKDF2/Argon2 KDF 参数不同，参考数据库不能直接套入 Ray。 | [ww2 配置](../../ww2/src/handlers/mod.rs#L74)、[升级](../../ww2/src/handlers/identity.rs#L372)、[ww1 验证升级](../../ww1/src/password.rs#L70)；[Ray 固定值](../src/infra/crypto.rs#L26)、[用户模型](../src/models/user.rs#L33) |
| D06 | **注册协议与 verified 入库不齐**：ww1 的 PascalCase 认证/解锁字段别名缺失；finish 返回 `{object:"registerFinish"}`，Ray 返回 `{}`。Ray 在需验证分支设置 email_verified=true，INSERT 却漏该列，落库仍为 false。 | [ww1 请求别名](../../ww1/src/models/user.rs#L120)、[注册 INSERT](../../ww1/src/handlers/accounts.rs#L769)；[Ray 请求](../src/models/user.rs#L174)、[注册返回](../src/api/controller/accounts.rs#L182)、[INSERT](../src/api/service/user.rs#L83) |
| D07 | **profile / sync.profile 缺 accountKeys**：get-keys/token 另有该字段，不能补足 profile/sync 的缺失。具体客户端影响尚未实测。 | [ww1 profile](../../ww1/src/handlers/accounts.rs#L378)、[sync](../../ww1/src/handlers/sync.rs#L161)；[Ray Profile](../src/models/sync.rs#L13)、[sync 序列化](../src/api/controller/sync.rs#L110) |
| D08 | **大 JSON 逐行 fallback 未移入**：ww2 聚合遭遇 SQLITE_TOOBIG 时切换逐行投影；Ray 聚合 `.first()` 失败即整个 sync/list 失败。 | [ww2 fallback](../../ww2/src/handlers/ciphers.rs#L1134)；[Ray 查询](../src/models/cipher.rs#L983)、[sync 调用](../src/api/controller/sync.rs#L100) |
| D09 | **未知邮箱 KDF 响应策略未同步**：Ray 未知邮箱总返回 PBKDF2/600000，真实账户采用非默认参数时可被区分；ww1 有按 secret＋邮箱稳定选桶。该参考策略也不是消除所有枚举的保证。 | [ww1 策略](../../ww1/src/handlers/accounts.rs#L560)、[调用](../../ww1/src/handlers/accounts.rs#L662)；[Ray 回退](../src/api/controller/accounts.rs#L80) |
| D10 | **导入兼容与加密上下文校验缺失**：ww1 导入先去组织 ID，支持没有关系表时保留合法 folderId，并校验 encryptedFor；Cipher 创建另核对 encryptedByKeyId 与当前用户 key ID。Ray 分别拒绝、丢弃或忽略相应输入。这不要求实现组织协作，也不是已证明可读取他人数据。 | [ww1 导入](../../ww1/src/handlers/import.rs#L35)、[folderId](../../ww1/src/handlers/import.rs#L104)、[加密上下文](../../ww1/src/models/cipher.rs#L976)；[Ray 导入校验](../src/api/controller/import.rs#L44)、[文件夹推导](../src/api/controller/import.rs#L123)、[请求字段](../src/models/cipher.rs#L392) |
| D11 | **完整 Cipher / 导入忽略 archivedDate**：独立 archive/unarchive 存在，但创建和导入固定未归档，完整更新固定保留旧值，无法按 archivedDate:null 取消归档。 | [ww1 更新归档](../../ww1/src/handlers/ciphers.rs#L422)、[导入](../../ww1/src/handlers/import.rs#L133)；[Ray 创建](../src/api/controller/ciphers.rs#L79)、[更新](../src/api/controller/ciphers.rs#L184)、[导入](../src/api/controller/import.rs#L147) |
| D12 | **通知语义未完整保留**：普通资源变更统一发 SyncVault，未调用已有资源级 helper；密码/KDF/轮换后再发 LogOut 时，DO 会先因旧 session 无效而关闭连接，无法发出 LogOut 帧。邮件恢复删除也少删除前广播。旧 API 凭据仍会被拒绝，不是持续越权。 | [ww2 资源事件](../../ww2/src/handlers/folders.rs#L105)；[Ray Mutation](../src/api/service/mutation.rs#L87)、[DO 投递](../src/durable/notify_do.rs#L482)、[恢复删除](../src/api/controller/email.rs#L730) |
| D13 | **管理安全通知覆盖收缩**：ww1 有登录/失败/刷新/Passkey/2FA 等事件、UA 上下文与 NOTIFY_LEVEL；Ray 主要是几个泛化事件。配置 NOTIFY_EVENTS 不能产生没有调用发布的事件。 | [ww1 事件](../../ww1/src/notify/types.rs#L37)、[登录调用](../../ww1/src/handlers/identity.rs#L1710)；[Ray 分类](../src/api/service/mutation.rs#L43)、[发送](../src/infra/delivery.rs#L83) |

## 5. ww1 的 18 项入口差集

以下是方法＋路径模式差集，不全部属于独立业务功能，也不全部进入本项目 MVP。

| 分类 | Ray 尚未提供的 ww1 入口 |
| --- | --- |
| 独立或另一套状态流 | `POST /api/accounts/set-password`；`POST /api/two-factor/authenticator/request`、`/enable`、`/disable` |
| 兼容声明 | `GET /api/two-factor/get-device-verification-settings`；ww1 固定声明两个 device verification 开关为 false，没有实现整套新设备验证 |
| 空列表兼容 | `GET /api/collections`、`/api/organizations`、`/api/policies`；ww1 返回空列表，Ray 目前未注册这些入口 |
| 方法/路径别名 | `GET /alive`；`POST /accounts/verify-password`、`/api/accounts/avatar`、`/api/auth-requests/admin-request`、`/api/folders/{id}` |
| 旧文件 URL | `GET /attachments/{cipher_id}/{attachment_id}`；`POST /ciphers/{cipher_id}/attachment/{attachment_id}`；`POST /sends/{send_id}/file/{file_id}` |
| 展示/匹配范围 | `GET /demo.html`、`GET /icons/{*path}`；Ray 已支持标准 `/icons/{domain}/icon.png`，并非整个图标功能缺失 |

入口证据集中在 [ww1 router](../../ww1/src/router.rs#L63)；Ray 当前的实际挂载见 [routers](../src/api/routers.rs)、[入口分流](../src/dispatch.rs)、[附件处理](../src/api/controller/attachments.rs)、[Send 处理](../src/api/controller/sends.rs)。

set-password 是只允许尚无主密码/私钥账户调用的独立能力，不是 change-password 别名；当前完整密码注册不依赖它。旧式 TOTP request/enable/disable 会存 pending secret、返回 otpauth/QR，并按 code 启用/停用，Ray 使用另一套 key＋token＋密码/OTP 流程。参考旧 request 的授权边界较弱，补兼容时应重新设计，不能只把旧 handler 照搬进来。

ww1/ww2 在入口统一处理尾斜杠，Ray 只对通知和选定 HeavyDo 请求规范化；普通 `/api/sync/` 等不能据上述归一化统计认定等价。

## 6. 配置与响应的其他差异

- ww1 默认启用 `undetermined-cipher-scenario-logic`、`windows-native-credential-sync` 等 flag；Ray 未完整保留。ww1 的 `CLIENT_FEATURE_FLAGS`、`FILL_ASSIST_RULES_URL`、`CLIENT_SUPPRESS_ONBOARDING` 也未移植。不能仅凭 flag 名断言某个客户端功能必坏。
- ww1 的 `TWO_FACTOR_REMEMBER_DAYS` 可配置，Ray 固定 30 天；ww2 的 `SEND_TTL_SECS`、`SEND_TEXT_MAX_BYTES` 调优项没有原样保留；Ray 选择 File Send 的 R2 最高 95 MiB，现由统一 Rust 文件路径执行。
- ww1 的完整 `VW_CSS_*` 显示开关矩阵没有照搬；Ray 保留 `VW_CSS_USER`，其余主要从实际能力配置派生。
- Ray **已有 Send 密码尝试限流**：审计时按 Send ID＋IP 调用共享登录 limiter；后续已接入独立 `SEND_ACCESS_RATE_LIMITER`，生产/本地均15次/60秒，登录等敏感操作保持5次/60秒。不能将之前共用阈值误报为没有限流；这不修复 P03 的访问计数缺口。
- ww1 token form 的大小写/下划线规范化和部分别名更广；Ray 的 serde 别名集合较窄。ww1 可从 Cookie 回退取 refresh token，Ray 只从 form 读取；Ray 仍输出参考已删除的 `ResetMasterPassword:false`，refresh 响应字段集合也不同。
- ww1 的 PRF probe/保存响应另有 `canUsePasskeyUnlock`、`requiresPasswordLogin`、`success` 等辅助字段；Ray 响应不同。密码学与 PRF 状态处理已存在，真实目标客户端的影响仍需验证。
- 附件下载 TTL：ww1 已收紧为 1 分钟；Ray 默认 300 秒且可配置，与 ww2 相同。这是短期 capability 策略差异，不等于下载未实现。
- 邮件投递改为按收件人的 HTTPS webhook；不能沿用 Telegram/企业微信群配置就期待邮件验证码送达。管理聊天不接收验证码是现有设计选择。

配置读取与限制的完整说明见 [运行配置表](runtime-config.md)，不在本表再维护第二份所有变量清单。

## 7. 有意变化、共同问题与不应误判的内容

- 单项 key 从 ww1 独立列映射为 Ray 的 `ciphers.data.key`；归档表映射为 `ciphers.archived_at`；ww2 的 pending Send 表映射为 `sends.pending`。不能按表名/列名不同认定功能缺失。
- 审计时三仓应用表数分别为 18 / 11 / 16（Ray 后续增加 JWT 密钥和缓存状态表，现为 18），数据模型、verifier、会话和密钥存储不同。**功能移植不代表参考 D1 数据库可直接导入 Ray。**
- ww1 的 JWT/TOTP manager 会从 D1 读取或首次生成 key；TOTP 用 AES-GCM 保存，但解密 key 也在同一 D1，不能据此声称能防完整数据库泄露。Ray 后续也改为 D1 自动持久化 JWT 密钥；TOTP 仍保存原始 secret，未复用 ww1 的密文保存格式。双方都没有上述 manager 的自动轮换/重加密机制，不能虚构“参考已自动轮换而 Ray 漏掉”的功能。见 [ww1 key manager](../../ww1/src/two_factor_key_manager.rs#L45)、[Ray TOTP 创建](../src/api/controller/twofactor.rs#L172)。
- Cipher 先读 revision 再 UPDATE、缺原子 CAS 是三个仓库共有的问题；整批导入分批写入也不是 Ray 独有回退。这些仍应修，但不计成“参考已经实现而移植遗漏”。
- Ray 的会话用途/设备 nonce/stamp、WebAuthn 挑战、API Key 加密、Send 配额预留和上传抢占含真实约束，部分比参考更严格。修复缺口时应保留这些增强。
- 组织、企业共享、SSO、紧急访问在既定项目范围外。Ray 有 emergency-access 空列表接口，但没有前述 organizations/collections/policies 三条空列表入口；不能把兼容声明写成完整组织能力。
- Send 邮件验证模式在参考中也未完整实现；Ray 明确拒绝，不宣称已支持。
- 自动创建资源/改写配置、追踪 latest UI、重复列容错、自动合成迁移历史，已按项目决策替换为现存资源验证、固定前端和原生迁移链；不是待恢复功能。
- 三份工作流按要求固定为 Integration、Coverage、Cloudflare；Cloudflare 仅部署已有构建产物。ww2 的独立 dev 部署和每日备份没有逐文件复制；其中自动备份仍是待建设能力，见 [备份与恢复](db-backup-recovery.md)。
- 两参考与 Ray 的 SERVER_VERSION 字符串不能单独证明兼容与否；本次没有据前端/服务端版本号差别虚构漏项。

## 8. 本轮验证与尚未验收的部分

实际执行：

- Ray `just test`：Rust **29/29**、JS **72/72**、SQL **51/51**，没有跳过；仍有 8 条既有编译 warning。这是现有用例集通过，不覆盖上述所有反例。
- ww1 三个选定兼容/迁移测试文件：**12/12** 通过，包含 Send 轮换字段、原子次数、密钥对初始化和近期兼容行为；部分用例是源码契约检查，不等同 HTTP 联调。
- 在内存 SQLite 中执行 Ray 模型提取的真实 SQL：普通 Cipher 更新后附件名称/key 不变，archived_at 仍保留旧值；类型 6 的实际同步投影缺 bankAccount；Send 轮换 SQL 会保存请求中的新名称。
- 将内存 SQLite 的单值长度限制暂设为 4096：真实聚合 SQL 报 too big，同投影逐行 52 条均成功，最大单行 862 字节。这只复现 fallback 的必要性，**4096 不是宣称的 D1 默认限额**。
- ww1 单用户触发器拒绝第二用户，而 Ray 当前迁移建立的库接受两个不同邮箱；TOTP 同步 claim 的实际 UPDATE 语义分别为 `[1,0]` 和 `[1,1]`。这是并发窗口的 SQL 证据，未执行并发 HTTP。

后续恢复派生的 `sql/schema.sql` 后新增一项结构一致性检查，SQL 测试为 **52/52**；上述业务缺口并未因此修复。

此后迁移曾重新编排为五个功能基线，当时 `just test` 为 Rust **29/29**、JS **72/72**、SQL **35/35**，0 skip。SQL 减少来自去掉 14 个业务场景的旧模式重复、两个旧升级测试及一个旧结构比对；业务场景与快照一致性检查保留。发布前内存比对确认 16 表、29 个显式 DDL 对象不变；这没有修复上述审计缺口，也未执行旧库原地升级。

随后按简化配置的决定，Ray 增加 `0006`/`0007`，自动持久化 JWT 密钥和全局等价域名缓存；本轮回归为 Rust **33/33**、JS **77/77**、SQL **44/44**，无跳过，当前为18表/31显式DDL对象。它减少初始化步骤，不改变上述业务审计缺口。

本次没有启动新的真实 D1/HTTP 或客户端测试，也没有发送真实邮件、推送或管理通知。此前 Worker 打包、production dry-run、262 文件校验和实际 no-bundle dry-run 的证据仍有效；此前用户终端 alive/config/prelogin=200、未鉴权 sync=401 只证明最小运行链路。

**移植完成的下一道门槛**：先修复 P01–P04 并补失败用例，再逐项处理 D01–D13 和确认需要保留的兼容入口；最后固定 Web Vault 与一个扩展，完成受控初始化、登录、密码项/附件/Send、同步解密、刷新撤销与恢复演练。每次修复和客户端验收应拆为不超过 30 分钟的任务卡，不因源码存在或 CI 通过提前标完成。

当前架构见 [架构说明](architecture.md)，执行与修复卡见 [建设计划](implementation-plan.md)。文中 ww1/ww2 相对链接用于当前并排检出的参考仓库；Ray 的构建运行不依赖它们存在。
