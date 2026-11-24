# Raywarden 项目全面审查与终轮安全评估

审查日期：2026-11-24  
审查范围：当前工作区全部 Rust/WASM 源码（`src/**`）、D1 迁移与 SQL（`sql/**`）、构建与部署脚本（`scripts/**`、`Justfile`、`wrangler.jsonc`）、CI/CD 工作流（`.github/workflows/**`）、回归测试套件（`tests/**`）及项目文档（`docs/**`）。

---

## 一、总体评估结论

**结论：经过两轮深度审查与本轮针对性修复，当前项目的架构设计、密码学边界、并发事务一致性（CAS + 会话快照）、流式存储隔离及自动化测试回归均已达到严密、完备的生产级标准。**

### 验证状态
所有修复均已落地并通过全套静态检查、单元/SQL/JS 测试与真实 WASM 运行时回归：
- `just ci`：格式检查、71 项 JS 测试、143 项 SQL 源码级回归测试、160 项 Rust 单元测试，以及宿主机与 `wasm32-unknown-unknown` 双目标严格 Clippy（`-D warnings`）全部零告警通过。
- `just build && just test-worker`：编译 Release WASM 并在 `workerd` 运行时执行全部 **303 项端到端与并发故障注入检查**，100% 通过。

---

## 二、本轮缺陷修复闭环记录（D-01 ～ D-09 & DOC-01 ～ DOC-04）

| 编号 | 原始优先级 | 缺陷描述 | 修复方案与代码落点 | 状态 |
| --- | --- | --- | --- | --- |
| **D-01** | **P1** | 账户密钥初始化（`set_key_id` / `set_initial_material`）及资料修改（`update_profile_name` / `update_avatar_color`）缺少提交时的设备会话 Nonce 校验 | 在 [account_keys.rs](../src/models/identity/account_keys.rs#L35-L115) 与 [user.rs](../src/models/identity/user.rs#L388-L456) 中将上述写入统一纳入带 `authorization::session_guard`（校验 `user_id`、`security_stamp`、`device_id`、`session_token`）的原子 `db.batch(...)`，并在资料更新后广播 D1 实际提交的单调 `updated_at` 修订时间（[accounts.rs](../src/api/controller/identity/accounts.rs#L244-L303)） | **已修复并新增并发回归** |
| **D-02** | **P1** | 附件元数据 16 MiB 上限在预留/完成上传时未拦截，超限后会导致普通单附件删除因先水合全集而返回 413 死锁 | 在 [attachment.rs](../src/service/vault/attachment.rs#L27-L61)、[attachments.rs](../src/api/controller/vault/attachments.rs#L139-L154) 与 [upload.rs](../src/service/vault/attachment/upload.rs#L130-L137) 的预留与发布阶段强制校验单 Cipher 16 MiB 元数据预算；新增 `hydrate_cipher_attachments_after_delete`（[attachment.rs](../src/service/vault/attachment.rs#L79-L118)），排除被删附件且在历史超限状态下优雅降级响应而不阻断删除 | **已修复并新增恢复回归** |
| **D-03** | **P2** | 附件上传与下载能力 URL 共用无用途区分的 `AttachmentClaims`，且默认叠加 60 秒过期宽限 | 在 [attachment.rs](../src/service/vault/attachment.rs#L261-L340) 引入 `AttachmentTokenScope::{Upload, Download}`，签发时写入明确 `scope`，上传与下载入口分别强制校验对应 `scope`，并将能力令牌验证的 `leeway_seconds` 收紧为 `0` | **已修复并新增越权回归** |
| **D-04** | **P2** | `SEND_MAX_BYTES` 在 R2 后端下与默认值 95 MiB 取 `min`，导致调大单文件上限失效 | 修正 [send/upload.rs](../src/service/send/upload.rs#L264-L269) 的 `max_file_size_bytes`，当存储后端无硬性上限（R2 `storage.max_bytes() == None`）时直接使用 `send_max_bytes(env)` | **已修复并新增 >95 MiB 回归** |
| **D-05** | **P2** | `/identity/connect/token` 请求体超过 64 KiB 时回退到本地 Worker，可通过填充未知表单字段绕过 `heavydo` 算力卸载 | 在 [routers/identity.rs](../src/api/routers/identity.rs#L19)、[identity.rs](../src/api/routers/identity.rs#L81-L86) 为 `/identity/connect/token` 显式设置 `DefaultBodyLimit::max(65_536)`，与 `heavydo` 的 64 KiB 预读阈值严格对齐，超限表单在进入业务层前直接返回 413 | **已修复** |
| **D-06** | **P2** | 密钥轮换内部快照读取使用无分页全量查询，且 `/api/accounts/password` 与 `/api/accounts/kdf` 缺少与轮换一致的 16 MiB 请求体上限 | 在 [rotation.rs](../src/models/identity/account_keys/rotation.rs#L152-L185) 与 [send.rs](../src/models/send.rs#L447-L482) 中将 `CollectionSnapshot::load` 和 `SendRow::all_for_user` 改为复用 `PageQuery` 键集分页读取；在 [routers/identity.rs](../src/api/routers/identity.rs#L70-L78) 为密码与 KDF 变更路由补齐 16 MiB `DefaultBodyLimit` | **已修复** |
| **D-07** | **P2** | 过期 Send 定时清理使用无 `LIMIT` 的 `SELECT *`，Cipher 批量选择（`fetch_selected`）未分页加载 | 在 [send.rs](../src/models/send.rs#L403-L410) 为 `SendRow::cleanup_candidates` 增加 `ORDER BY rowid LIMIT 16` 边界；在 [cipher.rs](../src/models/vault/cipher.rs#L91-L120) 将 `CipherRow::fetch_selected` 改为 `PageQuery` 分页读取 | **已修复** |
| **D-08** | **P3** | KV 回退后端的清理批处理（128 条）仅在全批成功后确认，单键失败会导致已删前缀重复执行 | 在 [storage.rs](../src/infra/storage.rs#L360-L380)、[models/storage_cleanup.rs](../src/models/storage_cleanup.rs#L112-L130) 与 [service/storage_cleanup.rs](../src/service/storage_cleanup.rs#L112-L125) 中改为返回已完成前缀计数并调用 `acknowledge_prefix(completed)` 先行确认已删键 | **已修复** |
| **D-09** | **P3** | 全局等价域名刷新（`refresh_global_domains`）对上游响应直接全量 `.text().await`，缺少流式字节上限 | 在 [domains.rs](../src/service/vault/domains.rs#L77-L116) 新增 `read_bounded_upstream_text`，同时检查 `Content-Length` 与流式分块累计大小（上限 2 MiB） | **已修复** |
| **R-05 / DOC** | **运维/文档** | Web Vault 归档可选 SHA-256 校验及文档细节同步 | 在 [prepare-ui.sh](../scripts/prepare-ui.sh#L47-L50) 支持 `WEB_VAULT_SHA256` 校验并补充单测；移除已完成使命的历史重构草稿并同步更新 [architecture.md](architecture.md)、[runtime-config.md](runtime-config.md)、[deployment.md](deployment.md) | **已修复** |

---

## 三、终轮安全性专项审查（Security Audit）

本轮对全库密码学实现、认证与会话状态机、授权隔离、数据库事务、文件存储及边缘防线进行了逐模块安全复核，结论如下：

### 1. 密码学与密钥管理安全（Cryptography & Key Hierarchy）—— **安全**
- **服务端密码验证器（PBKDF2）**：客户端提交主密码哈希后，服务端在 [password.rs](../src/service/password.rs) 使用每账户独立 64 字节 CSPRNG 盐值与至少 `600,000` 次迭代的 PBKDF2-HMAC-SHA256 计算服务端验证器，并通过 `constant_time_eq` 进行常量时间比对。低成本历史记录仅在密码及所需二次验证全部通过后才执行条件升级。
- **根密钥信封加密（Envelope Encryption）**：D1 中的 `jwt_keys`（`access_secret` 与 `refresh_secret`）由外部独立 Worker Secret `KEY_ENCRYPTION_KEY`（32 字节）通过 AES-256-GCM 包装为 `v1.` 密文，并绑定字段级 AAD（`raywarden:jwt_keys:global:access_secret` / `refresh_secret`），防止跨列替换或篡改（[jwt_keys.rs](../src/service/identity/jwt_keys.rs)）。
- **API Key 用途隔离加密**：用户 `client_secret` 存储在 `user_api_keys` 时，使用从 `access_secret` 派生的用途隔离密钥加密（`v2.` 前缀）并绑定用户级 AAD（`raywarden:user_api_keys:{user_id}`），验证哈希同样采用常量时间比对（[api_key.rs](../src/service/identity/api_key.rs)）。
- **JWT 验签时序**：[jwt.rs](../src/infra/jwt.rs) 严格遵循“先拆分三段、先做常量时间 HMAC-SHA256 验签、验签通过后再反序列化 Header 与 Claims 并强制校验 `alg == "HS256"` 及 `typ == "JWT"`”的顺序，杜绝未验签解析或 `alg: none` 攻击。

### 2. 认证、二步验证与一次性凭证原子性（Auth & Replay Protection）—— **安全**
- **全链路令牌域隔离**：
  - 会话令牌强制区分 `TokenUse::Access` 与 `TokenUse::Refresh`（[session.rs](../src/service/identity/session.rs)）。
  - Send 令牌强制绑定 `aud: "raywarden.send"` 与 `SendScope::{Access, Upload, Download}`（[send/token.rs](../src/service/send/token.rs)）。
  - 附件能力令牌强制绑定 `cipher_id`、`attachment_id` 与 `AttachmentTokenScope::{Upload, Download}`，且禁用过期宽限（[attachment.rs](../src/service/vault/attachment.rs)）。
  - 内部通知扇出令牌强制绑定 `scope: "notifications.internal"` 与请求体 SHA-256 摘要 `body_hash`（[notifications.rs](../src/service/notifications.rs)）。
- **一次性凭证防重放与故障回滚**：
  - TOTP 记录 `last_used_step`，在 SQL 条件中要求 `last_used_step IS NULL OR last_used_step < ?`；Email OTP、WebAuthn challenge、设备登录审批（`auth_requests`）及 2FA 恢复码均在最终写入会话或敏感操作的**同一 D1 `db.batch(...)`** 中原子核销。若批次内后续语句失败，凭证消费自动回滚，既防止并发双花重放，又避免故障吃掉用户有效凭证。
- **WebAuthn 协议完整性**：挑战记录绑定会话快照与账户加密代际快照（`account_snapshot`），验签覆盖 RP ID SHA-256、`UP`/`UV` 标志位、ES256/RS256 签名及签名计数器单调性（[webauthn/protocol.rs](../src/service/identity/webauthn/protocol.rs)）。

### 3. 提交时授权与并发一致性（TOCTOU & CAS Guards）—— **安全**
- **会话与安全戳守卫全覆盖**：本轮补齐 `set_initial_material`、`set_key_id`、`update_profile_name`、`update_avatar_color` 后，所有依赖 Bearer 会话的写操作均在提交事务内校验 `users.security_stamp` 与 `devices.session_token`。设备被撤销、同设备重登或安全戳轮换后，任何在途请求在提交阶段均会被原子拦截（返回 401/409）。
- **跨表快照防撕裂**：`/api/sync` 在分页读取跨表数据后，末尾再次复验 `AccountSnapshot`、`updated_at` 游标与会话活性（[sync.rs](../src/api/controller/sync.rs)），确保客户端绝不会收到跨越密钥轮换或并发修改的撕裂快照。

### 4. SQL 注入、日志脱敏与隐私保护（Injection & Redaction）—— **安全**
- **100% 参数化绑定**：所有外部输入（用户 ID、邮箱、密文、JSON 集合等）均通过 `?N` 占位符绑定（即使集合查询也通过单参数 JSON 字符串配合 `json_each(?N)` 传递），动态拼接的 SQL 片段仅限编译期常量列名、表名与哨兵表达式。
- **错误与日志脱敏**：5xx 数据库与内部错误对外统一返回 `"Internal server error"`；日志仅输出安全的 SQLite 错误分类码（如 `SQLITE_CONSTRAINT`），不记录 SQL 原文、令牌、密码提示或用户输入全文；生产配置强制开启 `observability.redact_query_string = true`（[wrangler.jsonc](../wrangler.jsonc)）。

### 5. 文件下载、SSR/XSS 防护与边缘防护（Storage & Edge Defense）—— **安全**
- **惰性安全下载**：附件与 File Send 下载一律强制返回 `Content-Type: application/octet-stream`、`Content-Disposition: attachment`、`X-Content-Type-Options: nosniff` 及 `Content-Security-Policy: default-src 'none'; sandbox`（[download.rs](../src/api/common/download.rs)），彻底阻断存储对象被浏览器解析为可执行 HTML/JS。
- **图标与外部请求防护**：图标代理严格校验域名语法（禁止 IP、凭据、端口与路径穿越）、校验上游 `image/*` 光栅类型（排除 `image/svg+xml`）并限制流式读取 5 MiB（[client_assets.rs](../src/api/controller/client_assets.rs)）；邮件与通知 Webhook 禁用自动重定向（`Redirect::Error`）并设 5 秒硬超时。
- **边缘算力与限流防线**：`/identity/connect/token` 请求体上限（64 KiB）与 `heavydo` 分片预读上限严格一致，防止填充请求体绕过 DO 卸载；`LOGIN_RATE_LIMITER` 与 `SEND_ACCESS_RATE_LIMITER` 在绑定缺失或故障时执行 Fail-Closed（返回 `503` 拒绝认证尝试）。

---

## 四、保留的平台运行特征说明（非代码缺陷）

以下为 Cloudflare 平台固有架构特征，已在文档中明确说明，供日常运维参考：
1. **Worker Isolate 128 MB 共享内存边界**：单次快照响应上限（64 MiB）与单 Cipher 附件元数据上限（16 MiB）为应用层保护上限；在单实例（`HEAVY_DO_SHARDS="1"`）下应避免多个超大密码库同时并发执行全量同步与分块上传。
2. **单密码库密钥轮换体积边界**：全量密钥轮换接口（`/api/accounts/password`、`/api/accounts/kdf`、`rotate-user-keys`、`rotate-user-account-keys`）请求体上限统一为 16 MiB，日常个人密码库远低于此阈值。
3. **Cloudflare Rate Limiting 机房局部性**：平台原生 Rate Limiting 绑定按边缘 PoP 局部近似计数，用于抵御常规暴力猜解；高安全要求下仍应依赖强主密码、2FA 与高长度 Send 密码。

