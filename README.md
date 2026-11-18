# Raywarden

运行在 Cloudflare Workers 上的 Bitwarden 兼容服务端，使用 Rust/WASM、Axum、D1 和预编译 Web Vault。密码库内容由客户端加密，服务端保存密文、账户验证材料及文件元数据。

项目定位是单用户个人密码库，同一账户可以有多个设备。注册需要空库、唯一完整邮箱和独立的所有者初始化授权；数据库唯一索引同时拒绝第二账户与并发开户的输家。配置邮箱不会自动生成账户、主密码或客户端加密密钥。

现有代码包含密码项、文件夹、会话、附件、Send、通知及多种认证方式。与 ww1/ww2 对照后，**移植尚未全部完成**，最新 ww1 的 V2 加密、blob、新类型、附件 key 与 Send 计数已补入；剩余差异和验证边界见 [功能移植审计](docs/feature-parity.md)。组织、企业共享、SSO 和紧急访问不在建设范围。代码实现与真实客户端验收分别记录。

手写服务端代码统一为 Rust：入口分流、附件与 Send 文件流、JWT 和通知共用现有模块。Wrangler 加载工具生成的 `build/index.js` 包装；前端覆盖资源仍在 `static/overrides/`。具体分工见[架构说明](docs/architecture.md#3-从哪里阅读和修改代码)。

配置支持模块日志过滤、完整动态 CSS 开关、独立 onboarding、管理通知级别及24类事件、严格 CORS 和默认关闭的 demo。生产配置提供可选项注释示例，本地给出默认值；变量取值、兼容别名及展示与服务端权限的区别见[运行配置表](docs/runtime-config.md)。

首次部署请从[从零部署指南](docs/deployment.md)开始：准备 Cloudflare 资源与 GitHub Secrets、运行工作流、通过 `/setup` 创建唯一账户，再验收登录和同步。指南解释每一步的作用与预期结果。

## 本地开发

需要 rustup、Node.js 22.13+、npm 10+、Bash 和 just；结构快照生成和 SQL 测试另需 Python 3。CI 使用 `.node-version` 中的 Node 24，其他构建工具版本见 `package.json`。

```bash
just dev
```

`dev` 自动检查并补齐 Node 依赖、Rust 工具链/WASM target 和固定版本 worker-build，再准备前端、迁移本地 D1 并启动。已准备好的工具会复用；Node 依赖安装成功后才记录锁文件及 Node ABI 标记，依赖文件变化或 Wrangler 缺失/不可运行时重新执行 `npm ci`。首次启动需要联网下载缺失项并编译 Rust/WASM，基础工具需预先安装。

`just setup` 复用 Justfile 中同一套准备规则，并额外执行 `cargo fetch --locked`，适合完整准备开发/CI 环境。其他检查命令为 `just ci`、`just build` 和 `just test-worker`。仓库的 `Cargo.lock`、`package-lock.json` 由原生工具消费；只有主动更新依赖时才执行 `just lock`，审阅并提交锁文件变化。

`rust-toolchain.toml` 声明 Rust channel、组件及 WASM target。`Justfile` 优先使用项目工具和 Cargo 的原生代理，并清除继承的 `RUSTUP_TOOLCHAIN`，让项目文件选择工具链，不修改用户默认配置。

`ui` 在 Justfile 中检查已有前端版本与入口 HTML：可用时离线更新覆盖资源；缺失或版本不符时下载固定版本。需要强制下载、禁止下载或导入归档时分别使用：

```bash
just ui-download
just ui-offline
just ui-archive /path/to/bw_web_v2026.7.0.tar.gz
```

下载和本地归档是两种替代方式。源 CSS/JS 在 `static/overrides/`，准备前端不修改第三方预编译 JS。

`just clean` 清理 Rust/WASM 构建产物、前端生成目录、覆盖率报告、Wrangler 临时产物与日志、项目工具缓存和 Python 测试缓存；保留本地数据库及存储、`.dev.vars`、`node_modules` 和已安装的工具。清理后直接 `just dev` 会补齐前端并重新构建，也可用 `just ui-archive` 离线恢复前端。

按 [本地运行说明](docs/deployment.md#本地运行)直接启动：

```bash
just dev
```

`dev` 在启动前自动迁移独立本地 D1。单独迁移用 `just db-migrate`（默认 `local`）。`0001`–`0005` 是按功能划分的新基线，`0006`–`0009` 增加服务端密钥、域名缓存、V2 账户材料和文件清理任务，`0010` 约束唯一用户；后续追加迁移，见 [迁移规则](sql/migrations/README.md)。旧历史库没有自动转换路径；已有多个用户时，唯一用户迁移失败并保留数据。

`sql/schema.sql` 是完整迁移链生成的当前应用结构快照，用于阅读结构、评审迁移和临时 SQLite 分析。修改迁移后用 `just schema` 再生，`just test-sql` 检查快照漂移。它不含业务数据、种子数据或 `d1_migrations` 历史，不用于应用初始化、升级或完整备份；运行始终只应用迁移。

首次请求自动在 D1 保存 JWT 签名密钥，后续复用；全局等价域名自动下载并缓存，下载失败仍可运行。日常启动不需要 `.dev.vars`，也不用生成或导入域名 SQL。本地首次开户时，在被 Git 忽略的 `.dev.vars` 配置 `OWNER_SETUP_TOKEN`，再访问 `https://localhost:8787/setup`；迁移本身不会创建账户或客户端密钥。首页为 `https://localhost:8787`，健康接口为 `/api/alive`。

## 构建与部署

`Justfile` 负责安装、编译、测试和 Wrangler 命令，数据库直接使用原生 `d1 migrations apply`；辅助脚本仅处理部署配置、产物校验和前端准备，见 [目录与脚本职责](docs/deployment.md#目录与脚本职责)。

只维护本地与生产。`just dry-run` 准备生产产物，`just deploy` 迁移并部署生产；远程命令不再带环境参数。独立迁移仍默认本地，只有 `just db-migrate production` 才访问远程。生产和本地均设置一个 HeavyDo 分片，Send 密码尝试使用独立限流器，Rust 应用日志级别由 `LOG_LEVEL` 控制。

生产必需的 Worker Secrets 是 `DOMAIN` 与 `ALLOWED_EMAILS`。部署工具从公开入口计算 `DOMAIN`，通过临时 `--secrets-file` 与 Worker 代码一同上传，无须提前创建 Worker 或手工写入其 Secret。首次工作流需要 GitHub Secrets 中的 `ALLOWED_EMAILS` 与 `OWNER_SETUP_TOKEN`；后续未提供这两个值时沿用已有 Worker Secrets。具体步骤见[部署指南](docs/deployment.md#部署环境与工作流)。本地配置仍直接提供 localhost 和虚构邮箱。

自定义域名可选，当前配置省略 routes 并启用 workers.dev。先在 Cloudflare Dashboard 配置账户的 workers.dev 子域名；部署工具只读查询它，再与 Worker 名组合成访问地址。若配置一个明确的 custom-domain 路由，则优先使用该地址。部署、运行时 URL 和健康检查使用同一入口，无须 GitHub `DOMAIN` Secret。

三份工作流分别承担 Integration 检查与构建、Coverage 覆盖率，以及 Cloudflare 产物部署。PR 只检查和构建；main 推送或手动运行 main 的 Integration 时，完整检查和构建成功后自动调用 `cloudflare.yaml` 部署本次产物。

复用已有产物时，先将工作流文件推入 main，再到 Actions → Deploy to Cloudflare → Run workflow，选择 main，并在必填的 `run_id` 中输入 Integration 运行 URL `/actions/runs/<run_id>` 里的数字。只接受同仓库 main 上由推送或手动触发、已经结束且最新 check 执行成功的 Integration；整体因部署失败而失败的运行也可重试。产物保留 14 天，过期需重新运行 Integration。手动部署精确检出产物对应的提交并校验摘要，不重新编译；仍会迁移生产 D1、上传并检查健康接口，不回滚数据库。详见[部署工作流](docs/deployment.md#部署环境与工作流)。

结构快照来自全部 10 份迁移，共 19 表、38 个显式 DDL 对象。纯 Rust 运行路径的测试、构建与环境验证结果见 [执行记录](docs/implementation-plan.md#8-执行记录)；脚本和前端仍有独立 Node 测试。

此前用户终端已完成本地启动及最小 HTTP 烟测，但早于迁移基线重编排；旧的 14 条迁移历史不能直接套用当前链。真实 D1、账户初始化、登录与客户端同步仍需单独验收。本轮未改写实际数据库或操作线上资源。

- [建设计划与执行记录](docs/implementation-plan.md)
- [架构与请求链路](docs/architecture.md)
- [运行配置、账户策略与 Secret 来源](docs/runtime-config.md)
- [开发、数据库与部署步骤](docs/deployment.md)
- [功能移植审计、缺口与验证边界](docs/feature-parity.md)
- [备份现状与恢复边界](docs/db-backup-recovery.md)

## License

MIT，见 [LICENSE](LICENSE)。
