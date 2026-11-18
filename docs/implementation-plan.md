# Raywarden 从外向内建设计划

创建日期：2026-11-13；当前入口对齐日期：2026-11-17。只维护本地与生产：`just setup`、`just ui-download`、`just dev` 供日常开发；生产构建和部署为 `just dry-run` / `just deploy`，远程命令不再带环境参数；独立迁移仍默认本地，仅显式 `just db-migrate production` 才远程。`keep_vars` 按确认保留。手写服务端统一为Rust，Wrangler使用工具生成的build/index.js包装；附件与Send复用共享流式存储、范围解析、JWT和通知。JWT密钥和全局等价域名在运行时初始化；schema是迁移生成的结构参考。0001–0005为功能基线，0006–0007增加密钥与缓存；旧历史库没有自动转换路径。最新验证见第8节，公开注册关闭、单用户约束、受控初始化及客户端闭环仍需独立完成。

目标是逐步建立属于自己的 Raywarden：每个入口、接口、业务规则和存储行为都能解释、运行和验证。ww1、ww2 提供行为参考；具体实现沿用并逐步整理 Raywarden 自己的结构。

## 1. 工作方式与范围

采用当前架构：Cloudflare Workers、Rust/WASM、Axum、D1，以及预编译 Bitwarden Web Vault。定位已确定为单用户个人密码库，关闭公开注册，`ALLOWED_EMAILS` 在配置中指定唯一完整邮箱。现有代码与数据模型保留，单用户约束和服务端关闭注册逐项实现。统一配置依据见 [运行配置表](runtime-config.md)。

第一目标是一个最小可用版本（MVP）：本人受控初始化唯一账户后，指定版本的 Web Vault 和一个浏览器扩展可以登录、新增和修改密码项、整理文件夹、手动同步、刷新会话、撤销会话和重新登录，并能正确解密保存的数据。公开注册一律被拒，数据库阻止第二个用户；归属过滤继续用隔离测试验证，不要求生产允许创建第二个账户。

邮箱配置只定义允许的账户身份，不自动生成账户、密码或加密密钥。空库的首次初始化需要所有者授权和客户端生成的加密材料；已有匹配账户直接沿用，不能为了满足本计划重建或清空密码库。`DISABLE_USER_REGISTRATION` 当前仅影响客户端展示，不能视为服务端关闭注册已经完成。

附件、Send、实时同步、移动推送、邮件验证、Passkey 等在 MVP 后逐组建设。组织协作、企业共享、SSO、紧急访问暂不进入计划。是否启用某项扩展，由该阶段开始时决定。

现有代码是可复用的实现资产。每张任务卡都先找到对应代码，再决定保留、修改或补写；通过验收才能标为完成。已有 [功能对照](feature-parity.md) 用于定位代码，不能替代本计划的验收。

卡片只包含一个边界内的小改动及其验收。若开工前发现某卡需要补写完整子系统，先拆成“接口契约、一个状态转换、一个存储操作、对应验收”等更小的实现卡，再开始编码；不把整个子系统的开发算进一张 25 分钟卡。真实客户端流程卡只负责执行指定场景和取证，修复另开卡。

### 单项工作不超过 30 分钟

- 下表时间单位为分钟，包含理解、修改、针对性验证及结果记录；预算为 10–25 分钟，保留收尾余量。
- 每次只开始一张卡。到 25 分钟检查剩余工作，到 30 分钟停止该卡，保存现场并拆分后续卡。
- 下载、编译、远程服务和人工操作的等待也计入本次时间盒；超时记录阻塞原因，下次单独继续，不静默延长。
- 发现新的编译或行为问题时，新增 `原任务 ID-R1`、`-R2` 等修复卡，每张预算 15–25 分钟，只解决一个根因或一个行为。
- 一次验收失败只产生失败证据和后续修复卡；不能把“已经尝试”记成“功能通过”。
- 默认按阶段及行顺序执行。阶段内有明确依赖时写在验收说明中；扩展阶段可以按需求调整顺序。
- 本文时间是单次执行预算，不是项目总工期承诺；未知问题会增加任务卡。

每次完成一张卡，说明四件事：为什么做、改了什么、如何验证、还有什么问题。只有影响了相应行为，才增加必要的回归检查。

## 2. “从外向内”的路线

```text
项目定位与可复现构建
          ↓
域名 / Assets / 生成的 Worker 包装与 Rust 请求入口
          ↓
HTTP 契约 / Axum 路由 / 配置与错误响应
          ↓
controller / service：受控初始化、认证、密码库规则
          ↓
models / infra：D1、密码校验、JWT、文件存储
          ↓
真实客户端最短闭环
          ↓
账户安全、文件、Send、通知、高级认证、发布运维
```

业务阶段也按这个顺序推进：先写一个客户端可观察的输入和输出，再沿现有分层完成它，最后回到客户端验证。数据库阶段只先建立后续业务需要的基础，具体查询随业务逐项收敛。

### 当前起点与已知阻塞

| 事实 | 对应处理 |
| --- | --- |
| 当前工作树有大量未提交及未跟踪文件 | A02 留存基线，后续修改只覆盖当前任务范围 |
| Rust 固定 `nightly-2026-11-13`，toolchain 文件声明组件和 WASM target；配置异步化后已去掉 `once_cell_try` | Justfile 优先 Cargo 原生代理并清理继承 override；本轮 doctor 确认项目 nightly/target，原生 CI 与构建已通过 |
| 保留两份原生锁文件，worker SDK 现为 `0.9`，宏由 SDK 重导出；worker-build 固定 `0.9.0` 并分别安装 | 原生 npm ci / Cargo --locked 消费锁；Rust 单独更新用 cargo update，npm 与工具另行升级，不在 CI 生成锁 |
| 已建立 `Justfile` 及共享脚本，CI 与手动部署复用同一套命令 | B07 核对离线入口；远程 Actions 尚未运行 |
| 资源准备改为从目标 JSONC 读取 Worker/D1/R2 名称与绑定 | H01 的离线契约检查与远程资源验证分别记录 |
| 单用户、不开放注册已确定，但当前 handler 仍允许白名单注册，数据库无单用户约束 | D04、E06、F03–F06 分别实现配置收紧、数据约束与初始化策略 |
| 工具入口与工作流健康探测统一为 `/api/alive`；用户终端已取得本地 200 及 prelogin 查询证据 | 只证明本地最小链路；H03 远程与 E05 隔离样例仍独立验收 |
| D1 的0001–0005为功能基线，0006–0007持久化JWT密钥和域名刷新状态，0008–0009增加账户材料及文件生命周期；schema是派生快照 | 后续从0010追加，不自动转换更早旧历史或重置用户数据库；JWT密钥必须随库保留 |
| Justfile 编排原生命令；UI 用 prepare-ui.sh 准备、patch-ui.mjs 验版本和修改 HTML | H02 复用 just；C03 离线、download、archive 分别验收 |
| worker-build 现固定 0.9.0，匹配 SDK 0.9；旧 0.7.4 工具拒绝该 SDK，新工具的上游锁文件已用支持 OpenSSL 4 的 openssl-sys 0.9.118 | 原 0.7.4 构建证据保留；本轮安装和重新打包单独记录，不以旧产物替代验证 |

## 3. MVP 任务

### A. 明确项目边界并留存起点

产物写入下方决策记录和执行记录，运行配置另见独立文档。A01 的账户策略和 Web Vault 版本已确定，浏览器扩展版本仍待固定；A04 文档已完成，其列出的代码和脚本差异仍按后续任务处理。构建环境不依赖客户端版本选择，B01 可先行，不代表 A01/A03 已验收。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| A01 | 15 | 记录已定账户策略并固定 MVP 客户端版本 | 单用户、不公开注册、配置唯一邮箱已确定；补齐 Web Vault 与扩展的准确版本 |
| A02 | 20 | 留存当前工作树基线，包括未跟踪源码和文档 | 有可恢复的本地快照及清单；不把密钥或构建缓存放入快照；不清空现有改动 |
| A03 | 20 | 写出 Raywarden 的模块职责与一条请求链 | 能沿入口、路由、controller、service、models、infra 定位登录和同步代码；记录与参考仓库的取舍 |
| A04 | 20 | 整理唯一的运行配置表 | 已形成 [运行配置表](runtime-config.md)，区分当前值、目标策略、变量/Secret、环境和待实现项；完成状态见执行记录 |

### B. 建立可复现的构建与本地运行基础

保留现有模块，先得到真实诊断，再按根因拆修复卡。B04 未通过时，不推进依赖完整构建的任务。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| B01 | 20 | 确定并固定 Rust 工具链 | 已固定 `nightly-2026-11-13`；本地与 CI 由 rustup 原生读取 toolchain 文件，声明组件和 WASM target，不手写解析 channel；保留不稳定 API；验证范围见执行记录 |
| B02 | 20 | 固定 worker、worker-build、Wrangler 及锁文件策略 | 版本来源与真实锁已保留；使用原生安装/锁约束，本轮原生构建相容性复验已通过 |
| B03 | 15 | 检查工具、依赖获取和 WASM target | 记录 Rust/Node/Wrangler 版本、target 和依赖获取结果；环境阻塞有原始错误 |
| B04 | 25 | 执行一次真实 WASM cargo check 并整理诊断 | 真实检查已通过；修复 WASM RNG 和 Send query 借用问题；证据见执行记录，B05 打包独立验收 |
| B05 | 25 | 完成 Worker release 打包 | 已真实生成入口和 WASM，67 exports 可解析；production dry-run、产物校验和 no-bundle dry-run 通过；详细证据见执行记录 |
| B06 | 25 | 建立独立本地配置与变量示例 | 已完成：独立配置与本地 Secret 生效；2026-11-17 用户终端实际 Worker 启动，连接本地 D1，四项 HTTP 烟测符合预期；账户与客户端流程另行验收 |
| B07 | 20 | 收敛 CI 的基础检查命令 | 移除或替换失效 just 调用；格式、构建、现有 Node/SQL 检查的命令与执行目录真实存在 |

阶段门槛：真实 WASM 检查、release 打包和本地启动均通过。离线 SQL 或 JS 替身测试不能替代这一门槛。

### C. 建立外部请求入口和 Web Vault

先解释浏览器如何到达 Worker，再处理业务。开发域名先使用 localhost；远程独立环境安排在 H。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| C01 | 20 | 整理 Assets、Rust/WASM、DO 的路由归属 | 一张路由表说明哪些请求走哪里；动态请求不会误回静态 HTML |
| C02 | 20 | 统一健康检查路径和语义 | 固定 `/api/alive`；明确成功条件与失败响应；Wrangler 能把该路径送到 Worker |
| C03 | 25 | 固定 Web Vault 获取版本和准备命令 | `scripts/prepare-ui.sh` + `patch-ui.mjs` 使用固定 `2026.7.0`；离线/下载/归档和幂等注入分别验收 |
| C04 | 20 | 打通首页与静态资源加载 | 浏览器打开登录页；主要 JS/CSS 正确返回；静态 404 行为明确 |
| C05 | 25 | 验收 Rust dispatch 的分发顺序与路径归一化 | 普通 API、文件和通知路径分发符合 C01；可选 DO 缺失时行为明确 |
| C06 | 20 | 统一预检、CORS 和未知 API 的返回 | 一个允许来源的 OPTIONS 通过；未知 API 返回预定错误；不破坏 WebSocket upgrade 响应 |
| C07 | 20 | 为 MVP 关闭未启用的扩展入口 | 未启用的文件/通知路径不进入相应处理器；返回约定的不可用结果；与 D06 的启用清单一致 |

### D. 固定客户端可观察的 HTTP 契约

契约样例使用虚构账户和密文，随实现一起维护。这里先限定 MVP，避免一次覆盖全部接口。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| D01 | 20 | 列出 MVP 的路径、方法、认证方式和关键响应字段 | 覆盖 config、prelogin、公开注册拒绝、受控初始化、token、profile、sync、Cipher、Folder 和会话撤销 |
| D02 | 25 | 实现或收敛 `/api/config` | 返回正确的 vault/api/identity/notifications 地址；功能声明与当前启用范围一致 |
| D03 | 25 | 收敛错误到 HTTP/Bitwarden 响应的映射 | 错误密码、参数错误、未认证、越权四类样例有明确状态与响应形状；敏感内部信息不外泄 |
| D04 | 20 | 收敛配置读取与归一化 | DOMAIN、布尔值行为明确；白名单仅一个归一化完整邮箱，缺失/空值/多值/glob 拒绝初始化；Secret 不进入响应或日志 |
| D05 | 20 | 建立一组可重复执行的 HTTP 样例 | 先重放 config 和无 token 的受保护请求，核对拒绝契约；prelogin 的数据库成功路径样例在 E05 后执行 |
| D06 | 25 | 按 MVP 启用清单收敛 Rust 路由挂载 | 未启用的扩展路由在服务端拒绝请求；config/UI 与路由一致；不会仅隐藏入口却允许调用 |

### E. 建立数据库基础与迁移规则

本阶段只操作一次性测试数据库。当前迁移按用户要求采用新的空库功能基线；旧 v7 fixture 与兼容升级用例已删除，旧数据库原地转换不在本次范围。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| E01 | 20 | 整理 MVP 表、关系及用户归属约束 | 明确 users/devices/ciphers/folders 的关键字段、外键、唯一约束和 user_id 过滤位置 |
| E02 | 20 | 收敛 D1 binding 与数据库错误处理 | `warden-db` 的读取只有明确来源；缺 binding 与查询失败有可定位错误 |
| E03 | 25 | 建立按功能划分的新数据库基线 | 空库原生顺序执行当前0001→0007链，Wrangler管理7条实际历史；后续追加0008+；不导入schema或预填记录，不自动转换旧历史；真实D1单独验收 |
| E04 | — | 旧 v7 升级路径：已移出当前范围 | 本轮按用户要求采用全新功能基线，不再维护旧 fixture 或原地升级用例；如以后需要转换旧数据，另立任务 |
| E05 | 25 | 打通本地 D1 与 readiness 检查 | `/api/alive` 按 C02 的约定检查 D1；准备一个虚构白名单账户、被拒邮箱和无权资源的隔离样例 |
| E06 | 25 | 增加数据库单用户约束与旧库冲突检测 | 第二用户插入失败；旧库多用户时停止并保留数据，不删除或自动合并；现有归属过滤继续保留 |

### F. 从登录接口走入账户与认证实现

每项只收敛一个行为。客户端 KDF 参数与服务端 verifier 分开处理；沿用已有密码学实现及标准库，单独验证输入、绑定和失败路径。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| F01 | 20 | 实现或收敛 prelogin | 已知/未知邮箱响应满足契约；邮箱归一化及 PBKDF2/Argon2id 参数含义明确 |
| F02 | 25 | 收敛服务端密码 verifier | 受控初始化与密码验证调用同一规则；正确/错误输入结果明确；与客户端 KDF 参数独立 |
| F03 | 20 | 关闭公开注册的所有路径 | `/api/accounts/register` 及两个 identity 注册别名一律拒绝，包括白名单邮箱；客户端注册入口隐藏 |
| F04 | 20 | 明确受控首次初始化的契约 | 定义所有者授权、空库前提和客户端加密材料输入；不依靠知道白名单邮箱就能占用账户；复用现有处理逻辑 |
| F05 | 25 | 实现一次受控的唯一账户写入 | 只有授权初始化可创建白名单账户；key/privateKey 保留；非法 KDF、非白名单和重复/并发初始化失败；所需改动过大先拆卡 |
| F06 | 20 | 核对已有账户与唯一邮箱配置的一致性 | 匹配账户可沿用；不匹配或多用户冲突清楚报错，不自动创建、改名或删除账户 |
| F07 | 25 | 打通 password grant | 指定客户端 form、设备字段和正确密码能获得预定 token 响应；错误密码失败 |
| F08 | 25 | 收敛 access token 鉴权 | 校验签名、时间、用途、用户安全戳和设备会话；无效 token 不能访问 profile/sync |
| F09 | 25 | 打通 refresh grant | 有效 refresh 产生可用 access token；过期、用途错误及已撤销会话失败 |
| F10 | 25 | 打通会话撤销与重新登录 | 明确客户端本地退出与服务端撤销的区别；撤销后旧 access/refresh 被拒；新登录可用 |
| F11 | 20 | 收敛 prelogin 与初始化入口的限流 | 超限返回约定状态；IP 来源明确；关闭的公开注册路径保持拒绝；记录缺少 limiter 时的行为 |
| F12 | 20 | 收敛 password grant 的邮箱/IP 限流 | 固定阈值样例命中限流；不依赖真实等待；错误密码不能绕过限制；与 F11 的缺 binding 策略一致 |

### G. 从密码库 API 走入核心数据实现

先完成 Login 类型的真实闭环，再逐步验证其他 Cipher 类型。测试断言关注密文与 key 是否保留、归属是否正确，不在服务端解密保险库。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| G01 | 25 | 实现或收敛 profile 与空库 sync | key/privateKey、KDF、revision 和空集合满足 D01；合法客户端能进入空密码库 |
| G02 | 25 | 打通 Login Cipher 创建与读取 | 客户端发送的密文、单项 key、类型字段往返保留；新项出现在 sync |
| G03 | 25 | 打通 Cipher 修改 | 修改后的密文和元数据正确保留；revision 更新；重新同步可见 |
| G04 | 20 | 打通 Folder 创建与改名 | 文件夹名称密文往返；列表及 revision 反映本次变更 |
| G05 | 20 | 收敛 Folder 删除与 Cipher 归属 | 删除后的条目归属明确；指定 Cipher 的文件夹映射正确；不能引用另一账户的 Folder |
| G06 | 20 | 打通 Cipher 软删除 | deletedDate 和 sync 行为满足契约；另一账户不能删除该条目 |
| G07 | 20 | 打通 Cipher 恢复 | 恢复后状态正确，客户端可解密原条目；revision 更新 |
| G08 | 25 | 验证唯一账户闭环及访问边界 | 唯一账户重新登录后可解密；第二账户创建被拒；未认证/撤销会话和无权资源请求被拒；归属过滤用隔离夹具验证 |

### H. MVP 的真实客户端和独立环境验收

H01–H03 可在前置产物具备时提前做准备。H04 只执行限定流程并记录结果，不同时承包所有修复。远程步骤使用独立测试资源和测试数据。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| H01 | 25 | 对齐 provisioning 的名称并增加前置校验 | 与 A04 一致；无远程调用的检查可通过；错误配置在资源创建前失败 |
| H02 | 25 | 收敛一个正式部署入口 | 主 workflow 复用 B/E 的命令；备用脚本完成适配或明确停用；新库/旧库顺序正确 |
| H03 | 25 | 完成一次 dry-run 和测试部署准备 | dry-run 通过；独立资源、Secret、域名及健康探测地址完整；尚缺外部条件时明确阻塞 |
| H04 | 25 | 首次部署独立环境并做外层烟测 | 部署成功；首页、config、健康检查可用；记录部署版本与绑定，超时则另卡继续 |
| H05 | 25 | 指定浏览器扩展与 Web Vault 完成最短闭环 | 扩展登录并同步 Web 创建的条目，扩展修改后 Web 手动同步可解密；刷新/撤销结果符合 F09/F10 |

MVP 完成门槛：B 的构建门槛通过，G08 与 H05 在指定版本客户端通过；保存真实执行记录。远程环境的结果与本地结果分别记录。

## 4. MVP 后按需建设

以下都是任务组，组内每一行才是一个不超过 30 分钟的工作单元。默认 I、J 先做；K–O 按实际需求选择。未启用的功能在 config、UI 和文档中保持一致的状态。

### I. 账户安全与 TOTP

依赖 F、G；以两个测试设备验证撤销行为。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| I01 | 25 | 打通主密码修改 | 新密码登录成功；新包装 key 可解密原库；旧密码和旧会话失效 |
| I02 | 25 | 打通客户端 KDF 参数修改 | 先覆盖一种 KDF 变更样例；prelogin 与解锁参数一致；原有条目可解密 |
| I03 | 25 | 打通 TOTP 设置与关闭 | 指定客户端可启用/关闭；设置接口返回形状与版本匹配 |
| I04 | 25 | 收敛登录 TOTP 的窗口和防重放 | 正确、错误、过期及重复使用的码有明确结果 |
| I05 | 20 | 收敛 remember-device | 有效期明确；关闭 2FA 后旧 remember 失效；错误设备不能复用 |
| I06 | 20 | 收敛恢复码消费 | 有效恢复码完成预定操作；重复使用失败；操作后 2FA 状态明确 |

### J. 补齐个人密码库行为

依赖 G；密钥轮换同时依赖已经启用的文件/Send 模块，未启用部分必须明确排除。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| J01 | 25 | 验证其他四种 Cipher 类型的序列化往返 | SecureNote/Card/Identity/SSH 的固定样例字段及单项 key 不丢失；失败类型另开修复卡 |
| J02 | 20 | 打通永久删除 | 指定条目删除后不能读取或同步；不影响另一账户的数据 |
| J03 | 20 | 打通归档及取消归档 | 固定条目的 archivedDate、列表及同步行为符合契约 |
| J04 | 25 | 打通一种导入格式及 Folder 映射 | 固定小样本导入后可解密；非法关系和跨账户 ID 被拒；大批量另开性能卡 |
| J05 | 20 | 明确账户密钥轮换的完整性约束 | 写出必须一起更新的账户、Cipher、Folder、附件和 Send 字段及失败断言 |
| J06 | 25 | 收敛密钥轮换的提交边界 | 已启用对象的更新处于同一个 D1 原子 batch；一次成功的小样本字段对应正确 |
| J07 | 20 | 验证密钥轮换失败回滚 | 在测试库注入一次写入失败，证明没有新旧 key 混合状态 |
| J08 | 25 | 执行客户端密钥轮换样例 | 指定客户端轮换后重新登录并解密原条目；后来新增附件/Send 能力时分别追加对应回归卡 |

### K. 附件与文件存储

依赖 E、F、G；第一轮只启用 R2，KV fallback 单独验收。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| K01 | 20 | 固定附件协议与存储 key 规则 | 列出元数据、pending、上传/下载 token、对象 key 和完成状态的对应关系 |
| K02 | 25 | 打通附件元数据与额度预留 | pending 对属主可追踪；无权限和超额请求被拒；未上传文件不会误标完成 |
| K03 | 25 | 打通一种 R2 上传路径及完成提交 | 一个小文件流式上传完成；实际大小匹配；失败保留可清理状态 |
| K04 | 20 | 打通完整下载 | GET 返回正确密文字节；下载 token 不能跨用户或跨文件使用 |
| K05 | 15 | 收敛 HEAD 响应 | 与 GET 的长度及类型一致；没有响应体；失效 token 被拒 |
| K06 | 20 | 打通单段 Range | 一个合法范围返回 206 与正确字节；不可满足范围返回约定错误 |
| K07 | 25 | 收敛删除和过期 pending 清理 | 元数据与对象按约定清理；失败可重试；不清理其他用户文件 |
| K08 | 25 | 单独验收 KV fallback 的边界 | 附件与 Send 对 raw bytes 读写一致；容量上限被执行；切换后端的迁移要求明确 |

### L. Text / File Send

文本 Send 依赖 E/F，文件 Send 另依赖 K；访问次数必须在存储层原子更新。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| L01 | 25 | 打通文本 Send 的创建、读取和编辑 | 密文及 key 往返；拥有者列表正确；匿名接口不返回拥有者会话数据 |
| L02 | 25 | 收敛匿名访问密码与次数限制 | 错误密码失败；达到次数上限后失败；并发样例不能突破计数上限 |
| L03 | 25 | 收敛失效、禁用和删除 | 过期或禁用后拒绝访问；删除后旧 access token 不可继续使用 |
| L04 | 25 | 打通一种 File Send 上传路径 | 预留配额、上传完成状态和密文元数据一致；小文件可被接收方解密 |
| L05 | 25 | 收敛 Send 文件下载及清理 | 短期 token 绑定正确文件和用途；过期、替换及删除后旧链接失效 |
| L06 | 25 | 接入 Turnstile 门禁并验证回跳 | 开启时匿名访问需验证；重复兑换失败；回跳保留客户端 fragment 中的解密 key |

### M. 设备批准登录与实时通知

依赖 F/G；移动推送需要单独配置的测试 relay 凭据。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| M01 | 20 | 收敛设备列表 | 设备字段满足契约；仅返回自身设备；不能查询另一账户设备 |
| M02 | 25 | 打通单设备会话撤销 | 目标设备的旧 access/refresh 被拒；另一设备的会话仍可用 |
| M03 | 25 | 打通 auth-request 创建与轮询 | 请求绑定申请设备及有效期；未批准时不返回可登录材料 |
| M04 | 25 | 打通 auth-request 审批与一次性消费 | 正确批准样例可登录；错误设备/IP/访问码、过期及重复消费被拒 |
| M05 | 25 | 打通 NotifyDo 连接与 SignalR 握手 | 用户连接成功；匿名连接只收到自身授权请求通知；非法会话被拒 |
| M06 | 25 | 打通一种 Cipher 变更的实时同步 | Web 修改后扩展收到通知并取得新数据；单独记录通知与读取一致性 |
| M07 | 25 | 收敛连接重连与会话撤销 | 撤销后旧连接不能持续接收；连接中断后可重新认证 |
| M08 | 20 | 收敛内部投递鉴权 | 正确签名可投递；篡改请求体、过期及无签名的请求被拒 |
| M09 | 25 | 单独接入移动 push relay | 一个指定移动客户端的测试事件可送达；未配置时基础同步仍可用 |

### N. 邮件与验证码

依赖 F，先准备能按收件人投递的测试邮件网关。管理事件通知与用户验证码投递分别处理。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| N01 | 25 | 打通收件人邮件网关 | 指定测试收件人收到邮件；失败不返回已发送；Secret 不进入日志 |
| N02 | 25 | 收敛验证码的保存与绑定 | 只保存 HMAC；用途/账户/收件人/会话不匹配的样例不可使用；投递失败不启用验证码 |
| N03 | 20 | 收敛验证码的消费限制 | 冷却、尝试次数、过期和一次性消费按固定样例验证，不依赖真实等待 |
| N04 | 25 | 打通 Email 2FA 设置 | 指定客户端完成发送验证码与启用；邮件地址和响应形状符合约定 |
| N05 | 25 | 打通 Email 2FA 登录 | 正确验证码建立会话；错误、过期或重复验证码不能登录 |
| N06 | 20 | 打通 Email 2FA 关闭 | 指定验证方式可关闭；随后登录状态及 remember 失效行为正确 |
| N07 | 25 | 打通受保护操作 OTP | 一个账户操作可用 OTP 完成；另一用途或另一会话的验证码不可复用 |
| N08 | 25 | 打通现有唯一账户的可选邮箱验证 | 验证链接/码与客户端流程吻合；未验证状态行为明确；不重新开放公开注册 |
| N09 | 25 | 打通所有者主动进行的邮箱修改 | 先明确与唯一邮箱配置的协调步骤；验证新收件人及包装 key；旧会话失效且原库可解密；不自动改配置或新建账户 |
| N10 | 25 | 打通删除账户恢复流程 | 测试邮件证明有效；一次性消费；明确这是确认删除，不提供主密码或保险库解密恢复 |

### O. WebAuthn、Passkey 与 API Key

依赖 F/N 的验证基础；WebAuthn 还需要固定、安全的测试 origin。每行先覆盖一个固定样例，失败的边界另开卡。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| O01 | 25 | 收敛 WebAuthn 注册及 challenge 绑定 | 正确 origin 可注册；错误 purpose/用户/会话或重复 challenge 被拒 |
| O02 | 25 | 收敛 WebAuthn 签名与 counter 校验 | 固定 ES256/RS256 样例及篡改样例结果正确；counter 规则有证据 |
| O03 | 25 | 打通一个客户端的 WebAuthn 2FA | 可注册并完成登录；凭证管理和 userVerificationToken 与该版本契约一致 |
| O04 | 25 | 打通无 PRF 的 Passkey 登录 | 身份认证成功后明确要求主密码解锁，不伪造可解密的包装材料 |
| O05 | 25 | 收敛 PRF 注册材料的保存与更新 | 客户端包装材料完整且按用户/凭证绑定；缺失材料时状态明确 |
| O06 | 25 | 执行 PRF 登录解锁样例 | 指定浏览器和凭证可以解锁；账户 key 轮换后旧 PRF 材料按规则失效 |
| O07 | 25 | 打通个人 API Key 读取与轮换 | 加密保存且按用户绑定；受保护证明有效；轮换后旧 key 失效 |
| O08 | 25 | 打通 client_credentials grant 与会话撤销 | 正确 key 建立限定 scope 会话；错误 key/scope 被拒；轮换撤销对应 API 会话 |

## 5. 发布与运行收尾

### P. 让交付过程与已实现能力一致

在拟发布的功能集合稳定后执行。真实用户数据迁移另开明确任务，不复用新库初始化步骤。

| ID | 预算 | 工作与产物 | 完成条件 |
| --- | ---: | --- | --- |
| P01 | 25 | 收敛定时清理与保留周期 | 对一组过期测试数据执行清理；Cipher/pending/Send/验证码/challenge 按已启用能力处理；失败可定位 |
| P02 | 20 | 收敛日志、request id 与错误定位 | 一次失败请求可串起入口和处理层；不记录密码材料、验证码、token 或保险库内容 |
| P03 | 25 | 验证一次 D1 备份与恢复 | 一次性库恢复后账户和密文完整；明确备份是否包含 R2/KV 文件 |
| P04 | 25 | 验证一次文件对象备份与恢复 | 选定后端的一份小样本可恢复并被客户端解密；记录对象与 D1 元数据对应关系 |
| P05 | 20 | 写明发布、回滚及数据库变更的兼容边界 | 区分 Worker 回滚与数据库恢复；已有数据不经过新库初始化脚本 |
| P06 | 25 | 更新 README、部署文档及功能开关 | 名称、命令、配置来源与代码一致；已通过/待验证/未启用能力清楚 |
| P07 | 25 | 完成一次候选发布的固定烟测 | 锁定版本、构建产物和验收记录；只发布所选范围；发现问题分别拆修复卡 |

## 6. 验证方法与阶段门槛

| 层次 | 使用方式 | 能证明什么 |
| --- | --- | --- |
| 静态检查 | 格式、语法、配置路径及纯函数检查 | 结构或规则满足约定 |
| SQL / JS 隔离测试 | 复用 `tests/`，按修改补充必要样例 | 数据约束、权限、计数、状态转换和文件边界 |
| 真实构建 | 选定工具链的 WASM cargo check、worker-build、Wrangler dry-run | 整套模块能编译打包，绑定和产物可供运行 |
| 本地 HTTP | Wrangler 本地 D1 与真实请求 | 入口、路由、认证、响应及查询可以衔接 |
| 客户端联调 | A01 固定版本的 Web Vault / 扩展 / 后续移动客户端 | 实际协议兼容及密文可解密 |
| 独立 Cloudflare 环境 | 测试域名、D1、R2/KV、DO | 平台绑定、文件流和真实通知等运行行为 |

基础命令统一通过 `Justfile`，其实现和版本来源见 [部署说明](deployment.md)：

```bash
just doctor
just fmt-check
just check
just test
just build
```

`doctor` 直接报告工具版本和 target，不证明编译成功；setup 只消费已有锁。缺锁或主动更新依赖时显式执行 `just lock`，审阅提交后再安装。Rust、JS、SQL 检查也可分别执行，避免将隔离结果当作完整构建结果。

这些命令各有覆盖范围；一次通过只用于对应任务，不自动把其他功能标为完成。

## 7. 决策记录

| 决策 | 当前状态 | 最迟确定任务 |
| --- | --- | --- |
| 用户模型 | 已确定单用户，多设备；保留现有模型，新增单用户约束另行验收 | A01 / E06 |
| 公开注册 | 已确定关闭；本人受控首次初始化单独实现 | F03–F05 |
| 账户身份配置 | 沿用 `ALLOWED_EMAILS`，仅一个完整邮箱；默认取配置 vars，核对同名 Secret 遮蔽 | D04 / H03 |
| 现有代码 | 保留当前实现与分层，按任务逐步修改，不整体重写 | 已确定 |
| 运行配置依据 | [统一运行配置表](runtime-config.md) 已完成；实际脚本与配置差异按表中任务落实 | A04 |
| 首个 Web Vault 与浏览器扩展版本 | Web Vault 固定 `2026.7.0`；扩展准确版本仍待固定；不自动追踪 latest | A01 |
| Rust 工具链 | 固定 `nightly-2026-11-13`；配置异步化后移除 `once_cell_try`，仍由原生 rustup 管理组件和 target | 工具链不随本次改动切换 |
| 正式部署入口 | 本地配置独立，远程只保留生产；生产 Just 命令无环境参数；数据库默认本地、显式production才远程；三工作流保留原职责 | H02；远程未验收 |
| Dashboard 普通变量 | 按本轮确认保留 keep_vars:true，未来取消前先核对并迁回需要保留的值 | 不读取或修改远端配置 |
| 运行可调项 | 两套配置均HeavyDo分片1、注册展示禁用true、LOG_LEVEL=info；登录5/60和Send密码尝试15/60分别限流 | 源码与离线契约已接入，真实限流/DO联调另验 |
| 服务端签名密钥 | D1首次缺行才生成或沿用完整旧Secrets，后续API/文件接口/DO共用同一Rust模块；不自动轮换；原行必须随库保留 | 已实现；真实Worker重启与客户端流程单独验收 |
| 全局等价域名 | 运行时自动获取并缓存D1，成功24h复用、失败1h重试；校验后原子替换；用户分组独立 | 已实现；不再手动生成/导入种子SQL |
| R2/KV、移动推送、邮件、Passkey 的启用范围 | MVP 后按需选择 | 对应扩展阶段开工前 |

## 8. 执行记录

状态使用：待办 / 进行中 / 已完成 / 阻塞 / 已拆分 / 跳过。未在下表更新的卡为待办；跳过的扩展卡记录原因及功能开关状态。同一任务按执行顺序追加记录，当前状态以最新一行为准，保留较早的失败证据。

| 日期 | 任务 ID | 状态 | 实际分钟 | 修改 / 产物 | 验证命令与结果 | 下一步或阻塞 |
| --- | --- | --- | ---: | --- | --- | --- |
| 2026-11-13 | 计划建立 | 已完成 | — | 本文 | 任务预算与结构检查 | 从 A01 开始 |
| 2026-11-13 | A01 | 进行中 | — | 用户已确定单用户、关闭公开注册、配置唯一邮箱、保留现有代码 | 决策与计划对齐；未执行账户创建 | 仍需固定首批客户端版本 |
| 2026-11-13 | A04 | 已完成 | — | [运行配置表](runtime-config.md) | 对照代码/JSONC/工作流，核对名称、读取来源、环境边界和差异 | 本轮仅文档；D04/E06/F03–F06/H 阶段处理实现差异 |
| 2026-11-13 | A02 | 已完成 | 约 2 | 本地快照 `/home/vj/Codes/.raywarden-backups/20261113T092827Z`：归档、SHA-256 清单、HEAD、Git 状态与缺失路径记录 | 417 个文件逐一核对归档哈希；保留 8 个已删除路径的记录；忽略环境 Secret 和构建缓存 | 快照留在仓库外；Git index 和用户现有改动未重置 |
| 2026-11-13 | B01 | 已完成 | 约 4 | `rust-toolchain.toml`、`scripts/setup-rust.sh`、三个 CI 的 Rust 安装步骤 | 固定日期 nightly 的 rustc/cargo/rustfmt/clippy 可用；清除 mise 环境覆盖后仍由工具链文件选中；`cargo fmt -- --check`、shell 语法、安装脚本离线烟测、`git diff --check` 通过 | 未实际执行远程 CI；本机缺 WASM target；B02 固定依赖与构建工具，B03/B04 安装 target 并真实编译 |
| 2026-11-13 | B02 / B03 | 阻塞 | — | 工具版本统一到 `package.json`，worker/worker-macros/worker-build 固定 `0.7.5`；锁文件改为保留 | 当前环境禁止联网，Cargo 缓存缺 `axum`，npm 无完整缓存，WASM target 缺失；未伪造锁文件 | 联网执行 `just bootstrap`，提交真实生成的 Cargo/npm 锁；`just setup` 安装后再执行 B04/B05 |
| 2026-11-13 | B06 / B07 | 进行中 | — | 统一 `justfile`、诊断入口、独立本地配置、测试 Secret 示例及 CI 检查入口 | 离线入口/配置检查与真实编译分开记录；未启动真实 Worker，未运行远程 Actions | 构建环境就绪后完成本地启动及 CI 验收 |
| 2026-11-13 | C03 / H01 / H02 | 进行中 | — | 固定版本 UI 准备、配置驱动资源准备、数据库入口及手动部署工作流；删除旧重复脚本 | UI 准备脚本离线测试 7/7；配置/资源核对/迁移/健康入口的离线替身测试 17 项通过；未下载真实归档、未远程建库或部署 | 真实 UI 下载、Wrangler/D1 路径与远程 smoke 仍待验收 |
| 2026-11-13 | B02 / B03 / B04 后续核对 | 阻塞 | — | 现场已存在真实 Cargo.lock、package-lock.json、node_modules 及 WASM target；未改写两份锁 | 后续 Cargo 离线解析缺 `aho-corasick 1.1.5`；尚无完整 WASM 编译通过证据 | 保留现有锁，补齐依赖后继续真实检查；不沿用此前“锁和 target 缺失”的环境结论 |
| 2026-11-13 | B07-R1 | 已完成 | — | tooling 导出实际函数并隔离 CLI；部署依赖准备与覆盖率工具准备分开 | 实际函数直接测试 10/10，验证随机独立 Secret、不输出值、0600、幂等、锁文件前置、无 npx 回退、部署不安装 Rust、工具安装失败前已获取本体依赖、Wrangler 本地日志及显式覆盖；替代沙箱受限的 subprocess stderr 断言 | 只证明工具控制流程；实际工具安装、Rust 编译与覆盖率仍待验收 |
| 2026-11-13 | B03 / B05 最新安装诊断 | 阻塞 | — | 用户真实 setup 错误及本机 OpenSSL 4.1.0 已核实；worker-build 工具版本与 worker crate 分开处理 | worker-build 0.7.5 的 native-tls 链使用 openssl-sys 0.9.111，不支持本机 OpenSSL 4；setup 已先 fetch 本体依赖再安装工具，失败顺序回归通过 | 调整 TLS 兼容的工具版本后真实重试；不因入口测试通过就把 release 打包标为完成 |
| 2026-11-13 | B05-R2 / B07-R2 | 进行中 | — | worker SDK 保持 0.7.5，worker-build 独立改为 Rustls 的 0.7.4；三份原名工作流分别检查构建、覆盖率和部署 Integration 固定产物 | 官方 crate 依赖已核对，无需降系统 OpenSSL；tooling 10 项直接函数测试通过；实际 `node scripts/tooling.mjs wrangler --version` 返回 4.111.0、exit 0；默认日志写项目目录并保留显式覆盖 | 真实工具安装、release 和远程三工作流仍待验收；Cloudflare 自动部署仅接受同仓库 main push 的成功 Integration |
| 2026-11-13 | B04 / 本体测试 | 已完成 | — | UUID 改 JS RNG，RSA 的 getrandom 0.2 启用 JS；修复 Send 两处 query! 传参借用，移除编译器指出的未用直接依赖；真实更新 Cargo 锁 | `cargo check --offline --target wasm32-unknown-unknown --locked` 通过；Rust host `--lib` 29/29、JS 80/80、SQL 49/49 通过 | B04 不再受依赖缺失阻塞；JS 后续新增缓存测试的全量计数另记；不把检查通过等同完整打包 |
| 2026-11-13 | B03 / B05 后续 | 进行中 | — | worker-build 0.7.4 已真实安装，doctor 全部 OK；构建辅助工具缓存改到项目 .tools/cache | OpenSSL 4 冲突已规避；tooling 直接测试增至 11 项；实际 Raywarden release 和 worker-build 完整打包仍分别取证 | 首次下载 wasm-bindgen 0.2.130 需要联网，在用户终端运行 just build；B05 尚未完成 |
| 2026-11-13 | H02 / 产物部署机制 | 进行中 | — | 预构建部署的 Wrangler 模块规则修正为 ESModule | 真实 Wrangler 4.111.0 fixture `--dry-run --no-bundle` 通过 | 只证明 CLI 接受部署机制，不代表 Raywarden 实际 release 或远程部署已通过 |
| 2026-11-13 | B05 / H03 实际产物 | 进行中 | — | 用户终端完成 wasm-bindgen/wasm-opt/esbuild 下载；真实 Rust release、worker-build、production dry-run 与产物清单生成已跑通 | dry-run 含 339 Assets，Worker 3573.40 KiB / gzip 1334.11 KiB；artifact / artifact-check 校验 391 文件通过 | 最终 strip="debuginfo" 配置重打包和实际产物 no-bundle 路径还在复验；未部署远程 |
| 2026-11-13 | B04 / B07 最终测试 | 已完成 | — | 共享工具和各层检查复验 | WASM check、Rust release、fmt/fmt-check 与 diff 检查通过；Rust 29/29、JS 81/81、SQL 49/49；clippy 退出 0，仍有 94 warning | 覆盖率和远程工作流未执行，不能由这些结果推断 |
| 2026-11-13 | B06 / E05 | 阻塞 | — | 尝试真实 just db-init，本地隔离配置生效 | 沙箱禁止监听 127.0.0.1，报 EPERM；不能完成 Wrangler 本地 D1 初始化 | 在允许本地监听的终端继续；D1/dev 与客户端流程尚未验收 |
| 2026-11-13 | B05-R3 / H03-R1 | 进行中 | — | release 改为 strip="debuginfo"，保留 WASM target_features；dry-run 仅清理对应环境的 deploy-check 输出，避免旧哈希 WASM 混入清单 | 重打包成功，target_features 警告消失；真实 release WASM 4,682,698 字节，WebAssembly.compile 验证 67 exports；修后 production dry-run 4680.94 KiB / gzip 1427.92 KiB | 清理旧产物后再次 dry-run、manifest 与真实产物 no-bundle 路径正在最后确认；不清理整个 .wrangler |
| 2026-11-13 | B05 / 最终产物校验 | 已完成 | — | strip="debuginfo" 真实重打包成功，保留 target_features；按环境清理旧 dry-run 输出，避免遗留 WASM 进入产物 | production dry-run 与实际预构建产物 `--dry-run --no-bundle` 均通过；339 Assets、一个 WASM、67 exports；4680.94 KiB / gzip 1427.92 KiB；manifest / artifact-check 391 文件通过；no-bundle 路径没有 custom build/Cargo | 本地 D1/dev 仍受 EPERM 监听限制；覆盖率、远程 Actions、远程数据库和部署、真实客户端解密未验收 |
| 2026-11-13 | B07-R3 / 脚本精简（预算 20） | 已完成 | — | 9 个脚本收敛为 6 个；部署相关 3 个入口并为 deploy.mjs；Rust 安装并入 tooling；数据库和部署共用唯一 Wrangler 执行器；资源核对命令改为 just resources | just ci 通过：Rust 29/29、JS 86/86、SQL 49/49、格式、WASM check、clippy；后者保留 94 条既有 warning；Justfile 格式与 diff 检查通过 | 远程 Actions、覆盖率和真实 D1/dev 仍需各自验收 |
| 2026-11-13 | C03-R1 / UI 源资产归位（预算 15） | 已完成 | — | tools 中 CSS/JS 原样迁至 static/overrides，删除遗留 Python 缓存及空目录；更新 include_str、UI 准备与测试来源；独立的等价域名生成器保留为可选工具 | 两个源文件迁移前后 SHA256 完全一致；UI 准备、客户端 JS、Rust 编译和 source 资产摘要校验通过 | 源文件与生成的 static/web-vault 分开维护 |
| 2026-11-13 | B05-R4 / 精简后产物验收（预算 20） | 已完成 | — | 复用新入口重新完成 production dry-run、manifest 与预构建上传路径复验 | 339 Assets、1 个 WASM；4680.94 KiB / gzip 1427.93 KiB；393 文件校验通过（新增 2 个源资产）；实际 --no-bundle dry-run 未触发 custom build/Cargo；显式 production 不受 CLOUDFLARE_ENV=dev 影响 | 未操作线上资源；本地 D1/dev 需用户终端继续 |
| 2026-11-13 | B06 / E05 查询输出探针 | 阻塞 | — | 尝试共享 Wrangler capture 模式的真实子进程输出验证 | 本环境中子 Node 退出 0 但 stdout 为空；独立原生 spawn 和 execFile 探针同样复现，未计为通过；成功与失败传播的函数边界测试已通过 | 与既有本地监听限制一起保留为本地 D1/dev 验收限制；不把替身测试等同真实数据库运行 |
| 2026-11-17 | B07-R4 / 原生命令入口（预算 25） | 进行中 | — | 删除 tooling 命令框架；安装/锁/构建/迁移/种子转 Justfile 原生命令；toolchain 声明 targets，优先 Cargo 原生代理并清理继承 RUSTUP_TOOLCHAIN；Node 由 .node-version 选择 | Secret 与程序化 Wrangler 契约 5 项通过；独立原生探针丢 stdout，因此实际 fixture 明确跳过；本轮完整构建与 CI 结果待统一记录 | 不把 11/13 的构建或测试计数作为新入口通过证据；线上未读写 |
| 2026-11-17 | E03-R1 / 冻结基线（预算 20） | 进行中 | — | 0014 完整 schema 内登记 0001–0014 历史，删除独立基线清单；初始化脚本只判断空库和异常历史，随后原生 migrations apply | 14 个历史迁移原样保留；后续只追加 0015+，不修改或回填冻结 schema；本轮 SQL 与执行路径验证待汇总 | 真实旧库升级和线上状态未核对，不自动补造历史 |
| 2026-11-17 | C03-R2 / UI 准备分工（预算 20） | 进行中 | — | prepare-ui.sh 负责离线/下载/归档、暂存和整体替换；patch-ui.mjs 负责版本与 HTML；源资产仍为 static/overrides | 三种模式及失败保护按本轮新实现分别验证，结果待汇总 | 不以脚本文件数量衡量完成；真实客户端仍独立验收 |
| 2026-11-17 | B07-R4 / 原生工具入口（预算 25） | 已完成 | — | 安装、锁、检查、构建直接使用 Justfile 原生命令；toolchain targets 与 Cargo 原生代理选择生效；CI 原生读取 .node-version 并消费现有锁 | just doctor 确认 pinned nightly13、WASM/host target；just ci 退出 0；Rust 29/29、SQL 49/49、JS 81 项中 80 pass + 1 skip；clippy 退出 0，94 条既有 warning | skip 由独立原生子 Node stdout 探针复现，不计为通过；coverage、远程 Actions 未运行；实际分钟未单独计时，未补造估值 |
| 2026-11-17 | E03-R1 / 冻结基线与离线验收（预算 20） | 已完成 | — | schema 冻结至 0014 并内置 14 条历史；database 只判断初始化前提，Justfile 原生 apply / execute 种子；后续只追加 0015+ | 本轮 SQL 49/49；14 个旧迁移及两份锁的 SHA 全未改 | 该卡完成基线和离线验收，不代表真实旧库或本地 D1 已运行；线上未读写 |
| 2026-11-17 | C03-R2 / UI 准备分工（预算 20） | 已完成 | — | prepare-ui.sh 编排离线/下载/归档和整体替换；patch-ui.mjs 负责版本与 HTML，保留 static/overrides 源资产 | UI 行为测试通过；真实原生 dry-run 调用离线 UI 准备后保留 256 个 Web Vault 文件；未改第三方预编译 JS | 本轮未重新验证真实网络下载；客户端解密闭环独立验收 |
| 2026-11-17 | B05-R5 / 原生产物路径验收（预算 25） | 已完成 | — | 原生 just dry-run production 经 just build 完成，生成清单并验证预构建上传路径 | 最终 262 文件（256 Web Vault + 4 bundle + 两锁），仅 1 WASM；4680.94 KiB / gzip 1427.93 KiB；artifact / artifact-check 通过；实际 no-bundle dry-run 未触发 Cargo/custom build；CLOUDFLARE_ENV=dev 仍选显式 production | 本地 D1/dev 端到端需用户终端；coverage、远程 CI/部署和真实客户端未验收；本轮未读写线上资源 |
| 2026-11-17 | H02-R2 / 交付边界收敛（预算 20） | 已完成 | — | Integration 仅上传最终 bundle、Web Vault、两锁及清单；删除无消费者的 GitHub 输出写入；保留 commit/env/config 摘要、最终文件哈希和 no-bundle 校验 | 最终清单 262 文件：256 Web Vault、4 bundle、两锁；只有 1 WASM；重新 manifest、artifact-check 与真实 no-bundle dry-run 通过，无 Cargo/custom build；JS 最后 81 项 = 80 pass + 1 skip | Wrangler Read 计数含目录，不当作资产文件数；本地 db-init 本轮仍报 EPERM listen127.0.0.1，记录于 native-db-init.log；线上未读写，coverage/远程 CI 未运行 |
| 2026-11-17 | B06-R1 / 启动配置一致性（预算 15） | 已完成 | — | 删除数据库与部署 CLI 的隐式 WRANGLER_CONFIG 覆盖；本地固定 wrangler.local.jsonc，远程固定 wrangler.jsonc 加显式环境；程序化显式 configPath 保留 | 3 个真实入口回归验证配置一致；部署/artifact 33/33；完整 JS 84 项中 83 pass + 1 环境 skip；错误 WRANGLER_CONFIG 指向不存在文件时 just config production 仍读取固定配置成功 | 未访问或修改线上资源；本地初始化与迁移不再分流 |
| 2026-11-17 | B06-R2 / 本地启动烟测（预算 25） | 进行中 | — | 尝试创建 loopback socket 与执行 just dev；命令已提供给用户终端，并补充首页/config/alive/prelogin/未鉴权 sync 验收步骤 | 执行沙箱中的 socket 创建被 EPERM 拒绝；just dev 已完成 release/WASM 打包并加载全部 local 绑定与本地 Secret，随后沙箱网络接口枚举 uv_interface_addresses 报错退出；未将此算为服务启动成功 | 等待用户终端 Ready 或实际错误输出，继续真实 HTTP 验收；日志 local-dev-start.log；不修改账户或密码库数据 |
| 2026-11-17 | B06-R2 / 用户终端本地启动验收（预算 25） | 已完成 | — | 用户终端实际完成 just db-init 与 just dev，Worker 显示 Ready on http://localhost:8787；随后提供四项实际 HTTP 响应 | alive/config/prelogin 均 200，未鉴权 sync 为 401 Missing token；config 使用本地地址，prelogin 为 PBKDF2 600000 次；只读 SQLite 检查确认 14 条迁移记录、users 与 user_key_id 存在、账户数为 0 | B06 与 B 阶段构建/启动门槛通过；未验证页面交互、DO/R2、账户初始化、登录或实际同步，不将 E05 整卡或客户端闭环计为完成；未操作线上资源 |
| 2026-11-17 | E03-R2 / 单链迁移与离线验收（预算 25） | 已完成 | — | 增加 0000 原始 users/folders/ciphers 三表，原有 0001–0014 不变；删除独立 schema 和 database 初始化脚本；新库、升级共用原生迁移 | SQL 51/51；新全链与切换前快照的表、列、默认值、索引、外键签名一致，外键检查通过；v7 样例升级保留关联数据，已有完整结构重复执行 0000 保留数据与原历史；两份锁及 14 个旧迁移 SHA 未改 | 本卡完成代码与离线验收；新链真实 D1 执行仍单独取证，不自动补缺失历史，不把切换前 14 条记录当作新链已验收 |
| 2026-11-17 | B06-R3 / 统一本地运行入口（预算 15） | 已完成 | — | db-migrate 默认 local，显式 local/dev/production；db-init 为本地兼容别名；dev 依赖 Secret、UI 与本地迁移；文档同步单链与旧库边界 | JS 75 项 = 74 pass + 1 既有 stdout 环境 skip；实际 Justfile 参数探针验证默认/local/db-init 固定本地 config/persist、production 配置检查后 remote；非法环境和缺独立 D1 的 dev 在 Wrangler 前被拒绝 | 参数探针使用临时替身，不操作数据库；不视为真实 D1/Worker 验收，未读写线上资源；未记录实际耗时，不补造估值 |
| 2026-11-17 | P05-R1 / 恢复文档纠偏（预算 15） | 已完成 | — | 备份文档改为当前状态与待验收恢复边界，删除不存在的自动备份、S3 密钥和旧命令说明；说明 D1 与 R2/KV 文件需一起恢复，先在隔离环境核对；保留官方导出与 Time Travel 参考 | 对照三份实际工作流；核对官方 D1 导入导出、Time Travel 链接；README 改为准确入口，未新增恢复脚本 | 只完成文档纠偏，不表示备份/恢复自动化或生产演练已完成；未读取线上数据或 Secret |
| 2026-11-17 | B07-R5 / 删除无消费者的工具分支（预算 20） | 已完成 | — | 删除独立 wrangler runner，将仅部署使用的流式 spawn 收入 deploy；去掉无调用方 capture 及对应旧 skip 测试；config 只解析远程部署，删本地分支与重复 npm UI 别名；删除 db-init 别名，dev 直接依赖本地 db-migrate；附件模块名更正 | 最终 JS 72/72、0 skip，包含真实流式部署子进程失败回归；SQL 51/51；just --tempdir /tmp dry-run production 退出 0，真实 release/worker-build/最终 Worker 打包通过，日志 simplify-dry-run.log；4680.94 KiB / gzip 1427.92 KiB，manifest/artifact-check 262 文件通过；实际 no-bundle dry-run 退出 0，仅一个 WASM，未触发 Cargo/custom build，日志 simplify-no-bundle.log | Rust 源码未变，29/29 为此前证据，本轮未重跑整套 CI；临时目录选项只用于验证环境，未加入产品配置；未读写线上资源 |
| 2026-11-17 | E03-R3 / 新链真实 D1 尝试（预算 20） | 阻塞 | — | 用真实 Wrangler 在 /tmp 一次性持久化目录尝试原生迁移 | SQL 执行前即因 listen 127.0.0.1 的 EPERM 失败，日志 migrations-native-cli.log；未改用户 .wrangler/local 或远程库 | 正常终端下次 just dev 自动应用本地待执行迁移后再取证；不把 SQLite 或参数探针记为真实 D1 已通过 |
| 2026-11-17 | A05 / 架构与优化路线文档（预算 20） | 已完成 | — | 新增 architecture.md，说明 JS/Rust/DO 请求链、分层职责、认证与数据一致性、单链迁移、构建交付边界及后续优化卡；README 加入口 | 对照实际入口、路由、模型、Justfile 与工作流；相对文档目标和 diff 格式检查通过；后续任务均按不超过 30 分钟拆分 | 文档描述现有代码与待验收范围，不宣称单用户约束、受控初始化或客户端闭环已完成 |
| 2026-11-17 | A06-R1 / 三仓入口与数据模型审计（预算 20） | 已完成 | — | 固定 ww1 ab378e5、ww2 7a9f6b9 与 Ray 当前工作树；解析 Axum 并补 JS/DO streaming 路由、核对 SQL/配置/工作流 | 有效方法路径分别 164/108/168；Ray 同名覆盖 ww2 108/108、ww1 146/164，18 项差集逐项分类；字段/表名差异不直接认定功能缺失 | 仅入口覆盖，不作为行为完成率；未更新参考仓库或操作线上 |
| 2026-11-17 | A06-R2 / 业务语义与失败场景审计（预算 25） | 已完成 | — | 并行审查账户认证与密码库/文件/通知两组域，追到处理器、模型 SQL 与 JS 状态；区分参考差距、共同问题和有意变化 | 确认新类型6–8、attachments2、Send计数与轮换、单用户、2FA、新协议字段、大JSON容错等缺口；内存SQL复现字段保留、类型投影、长度失败与TOTP/单用户差异 | 没有修改业务实现；真实HTTP/客户端仍未验收；共性CAS问题不算Ray独有移植遗漏 |
| 2026-11-17 | A06-R3 / 移植审计报告与回归复核（预算 20） | 已完成 | — | 重写 feature-parity.md，形成覆盖矩阵、P01–P04、D01–D13、完整18项入口差集与补齐门槛；架构和README链接对齐 | 本次 just test：Rust29/29、JS72/72、SQL51/51，0skip；ww1选定兼容/迁移测试12/12；文档明确现有测试未覆盖全部反例 | 现有测试通过不能标记完整移植；受控初始化、客户端、邮件/推送与云端验收分别记录 |
| 2026-11-17 | E03-R4 / 恢复派生结构快照（预算 20） | 已完成 | — | 恢复 sql/schema.sql，定位为完整迁移链生成的当前结构参考；Justfile schema 在内存SQLite生成，无新增脚本；正式建库/升级仍只用迁移 | SQL52/52，含快照重放与全链DDL一致、无业务数据/历史及外键检查；15个迁移生成16表/29对象，重复生成字节一致；14个已发布迁移SHA未变 | 快照用于阅读、评审和临时分析，不是初始化/升级或备份入口；不恢复手工历史登记；未修改用户数据库或线上资源，业务移植缺口仍待修复 |
| 2026-11-17 | E03-R5 / 按功能重写迁移基线（预算 25） | 已完成 | — | 按用户明确要求忽略旧迁移历史兼容，将15个历史碎片重写为账户、保险库、认证与会话、短期验证、Send五份完整CREATE；索引紧随表，schema重新生成 | 新旧内存库16表/29显式DDL对象一一对应，除格式空白外SQL完全相同；列顺序/默认值/PK/FK一致；完整just test通过：Rust29/29、JS72/72、SQL35/35；保留14种业务SQL场景，去掉重复模式和旧兼容测试 | 只重组DDL未修业务审计缺口；旧SQL备份于/home/vj/Codes/.raywarden-backups/20261117T054107Z；未执行清库、未读写实际用户DB或线上；旧历史不兼容新基线 |


| 2026-11-17 | B07-R6 / JWT 自动持久化（预算 25） | 已完成 | — | Rust/JS/NotifyDo 的签名与验证统一到 D1 jwt_keys；首次缺行才随机生成或精确沿用完整旧 Secret，并发重读赢家，读写失败不换钥；移除配置全局缓存及 once_cell_try | Rust 新增随机双 key/旧配置校验，Node 实跑 SQLite 并发初始化、已有行优先、数据库错误、旧密文解密与文件分支；SQL 核对 Rust/JS 同一查询及删账户保留 key | 不自动轮换；D1 包含服务端签名密钥，必须连同原行保留和备份；真实 Worker 重启与跨语言请求链仍需联调 |
| 2026-11-17 | B07-R7 / 等价域名自动缓存（预算 25） | 已完成 | — | 固定上游、5秒超时，首次读取和既有 cron 共用；D1 单行期限抢占，成功24h复用、失败1h重试，完整校验后 batch 原子替换，失败保留旧数据 | Rust 新增整份 JSON 验证2项；实际模型 SQL 回归6项，覆盖刷新期限、共享抢占、排除项与事务回滚 | 未发起实际 Worker 上游请求；新库离线时全局组为空，自定义分组不受影响 |
| 2026-11-17 | B07-R8 / 删除准备步骤与文档对齐（预算 20） | 已完成 | — | 删除 init-env、域名种子生成器及对应 Just 命令/示例/旧测试；dev 只准备 UI 和迁移；保留用户实际 .dev.vars；更新配置/架构/部署/恢复文档及 schema；Node 最低22.13适配内置SQLite测试，CI仍24 | 7份迁移生成18表/31显式对象；结构一致性、空数据、FK通过；相对文件链接与 diff 检查通过；just --dry-run dev 和 just config production 检查通过 | 代码/文档快照：/home/vj/Codes/.raywarden-backups/20261117T060103Z-runtime-simplify；更早旧历史库不自动转换，未清库或操作线上 |
| 2026-11-17 | B05-R6 / 完整回归与 release 产物复验（预算 25） | 已完成 | — | 最终 just ci 退出0：Rust33/33、JS77/77、SQL44/44，无跳过；fmt/WASM check/clippy通过，保留94条既有clippy警告；真实worker-build release完成 | 首次 dry-run 退出0但带0B WASM，既有artifact校验拒绝；完全相同命令重跑退出0，4754.07KiB/gzip1449.61KiB，唯一WASM4755830B与build哈希一致；artifact/artifact-check确认262文件 | 首次异常原因未确认、重跑未复现，不认定为工具bug或增加workaround；日志runtime-auto-ci.log、runtime-auto-dry-run.log、runtime-auto-dry-run-recheck.log保留在.wrangler/verification；未执行真实D1、HTTP、上传或部署 |

| 2026-11-17 | B07-R9 / 合并部署配置模块（预算 15） | 已完成 | — | 将 config.mjs 的 JSONC 解析、显式环境选择和资源隔离检查原样收入 deploy.mjs；删除独立文件，测试统一从 deploy 导入，部署说明同步 | just test-js 77/77，无跳过；Node 语法检查、just config production、diff 检查通过；实际调用和文档无旧模块引用 | 配置检查与现有 CLI 行为保留；patch-ui、Justfile 和工作流未改，未访问远程或重新打包；日志 merge-deploy-js.log |


| 2026-11-17 | B07-R10 / Wrangler 配置收敛（预算 20） | 已完成 | — | 两套配置启用schema、补/two-factor优先路由，生产DOMAIN完整HTTPS，显式注册展示禁用/HeavyDo分片1/LOG_LEVEL=info；删除远程dev及冗余说明、默认html_handling；用户确认保留keep_vars | 两套实际配置的D1/R2身份和四个限流namespace隔离契约通过；旧资源身份、DO migration内容与修改前逐项一致；源配置快照20261117T072157Z-wrangler-config | 未读取Dashboard变量或Secret，未部署、改资源或操作实际DB；取消keep_vars前另行核对Dashboard普通变量 |
| 2026-11-17 | B07-R11 / 生产部署入口与工作流（预算 25） | 已完成 | — | 删除远程dev和环境参数分支，远程just固定production；db-migrate仍默认local且仅显式production才remote；Integration固定生产产物，Cloudflare手动仅run_id，保留原三工作流与仅部署职责 | 定向部署/产物Node24/24，完整JS78/78；可信来源/SHA/哈希校验、真实子进程失败传播与--env空字符串契约保留 | 旧带environment参数命令不再支持；实际预构建路径dry-run确认继承CLOUDFLARE_ENV不改变目标且不触发构建；远程Actions未执行 |
| 2026-11-17 | B07-R12 / 应用日志级别（预算 15） | 已完成 | — | 共享init从普通变量读LOG_LEVEL，支持六级、忽略大小写/首尾空白、默认和非法值回退Info；Worker/cron/两DO构造入口统一OnceLock初始化，删除重复panic hook | 新增Rust表驱动解析测试，定向1/1，完整Rust34/34与WASM检查通过 | 只控制Rust应用日志；不新增模块级矩阵，不改变JS console或平台invocation日志策略 |
| 2026-11-17 | B07-R13 / Send 独立限流（预算 20） | 已完成 | — | Send匿名密码授权汇合点使用SEND_ACCESS_RATE_LIMITER，生产3103/本地4103阈值15/60；登录等敏感操作改项目独立3101/4101、维持5/60；复用原平台调用实现 | 新增2项实际Rust调用链契约，覆盖旧文本/文件与identity两grant；完整CI通过；真实Worker打包列出两个limiter绑定 | 保留原key、检查顺序、缺binding/后端失败策略及已有bearer路径；不修复P03访问计数缺口，真实分布式限流未联调 |
| 2026-11-17 | B05-R7 / 配置与预构建产物验收（预算 25） | 已完成 | — | 完整just ci退出0：Rust34/34、JS78/78、SQL44/44，无跳过；fmt/WASM check/clippy通过，保留94条既有clippy警告；真实release、dry-run与产物清单校验完成 | 4756.32KiB/gzip1449.35KiB，唯一WASM4758128B可解析且与build相同，262文件校验；实际deployArtifact注入--dry-run的--no-bundle路径退出0且无custom build/Cargo，继承假CLOUDFLARE_ENV仍固定生产；相对链接/diff检查通过 | 日志wrangler-simplify-ci.log、wrangler-simplify-dry-run.log、wrangler-simplify-no-bundle.log在.wrangler/verification；没有上传、操作实际DB或执行真实客户端/DO/R2联调 |

| 2026-11-17 | B07-R14 / Worker JavaScript 集中管理（预算 25） | 已完成 | — | 审计8个JS均从入口可达，无闲置文件；全部迁入src/worker，保持文件名和同目录依赖，entry两处生成代码引用改为../../build/index.js；更新两Wrangler入口、JS/Python测试源码路径、文档与8文件职责表 | 本轮JS78/78、SQL44/44，无跳过；所有相对生产import可解析，迁移前后仅生成代码导入和入口注释有文本差异；真实just dry-run退出0，4756.37KiB/gzip1449.36KiB，WASM4758128B可解析且与build相同，artifact/artifact-check确认262文件；链接/diff检查通过 | 快照20261117T073821Z-worker-js；未改Rust业务或重跑Rust整套CI（上轮34/34证据保留），未部署或操作实际DB；附件与Send的不同Range行为后续单独整理，前端资产继续在static/overrides |

| 日期 | 任务 ID | 状态 | 实际分钟 | 修改 / 产物 | 验证命令与结果 | 下一步或阻塞 |
| --- | --- | --- | ---: | --- | --- | --- |
| 2026-11-17 | B07-R15 / 附件上传与下载迁回 Rust（预算 25） | 已完成 | — | Rust 处理签名 GET/HEAD、Azure PUT 和 multipart；保留归属、配额、待上传记录与失败清理；完成上传以 D1 batch 发布元数据并通知 | 新增附件 Rust 用例与 3 项实际 SQLite batch 回归；workerd 实跑上传、下载、签名拒绝及失败补偿 | 不增加旧接口未有的并发上传锁；签名下载的设备信息仍仅用于通知上下文，不额外改变原授权语义 |
| 2026-11-17 | B07-R16 / Send 文件流迁回 Rust（预算 25） | 已完成 | — | Rust 处理旧式、新式和 Azure 上传及签名 GET/HEAD；流式解析文件，保留抢占、会话复核、条件发布和失败解锁 | 新增 Send Rust 与 SQL 回归；workerd 验证超过 2 MiB 的 multipart、长度不足、额外字段和上传中会话撤销 | 额外字段可在 R2 完成后被解析器发现，但发布 D1 前删除对象并解锁；不声称跨 D1/R2 原子事务，也未修复 P03/D01 |
| 2026-11-17 | B07-R17 / 共享流式存储与 Range（预算 25） | 已完成 | — | R2 使用 8 MiB 分块及失败 abort，下载保留原生 ReadableStream；KV 保留原始字节和 metadata 格式及 25 MiB 上限；附件和 Send 共用单 Range/If-Range/HEAD 实现 | workerd 核对原生下载流对象身份、分块顺序、中断清理、历史 KV 读取和实际 25 MiB+1 拒绝且零 KV.put；有效单 Range 及 416 通过 | Range 统一为严格单段解析，比旧附件解析更严格；不整文件缓存 R2 上传，KV 仍需在上限内缓冲 |
| 2026-11-17 | B07-R18 / Rust 入口与生成包装（预算 20） | 已完成 | — | 删除 src/worker 下全部 8 个手写 JS；入口、JWT、通知复用 Rust；两 Wrangler 指向生成的 build/index.js；实际文件上传复用既有 HeavyDo，下载保留原生流 | workerd 验证元数据路由、CORS、内部通知隔离及原生 WebSocket 101；资源 ID、DO migrations、限流和运行变量与改前一致 | keep_vars 保留；前端覆盖、工具和测试仍用 JS；代码快照位于 .raywarden-backups/20261117T075750Z-rust-worker，未读写真实数据库或部署 |
| 2026-11-17 | B07-R19 / 编译后 Worker 回归入口（预算 25） | 已完成 | — | 新增 just test-worker，在不监听端口、不访问外网和实际数据库的 workerd 中执行真实编译 WASM；Integration 在 dry-run 后执行，Cloudflare 仍只部署产物 | 20/20 组通过；D1/R2/KV 为内存测试绑定，实际 SQL 事务另由 SQLite 回归验证；日志 rust-worker-runtime.log | 测试绑定不能替代真实云端 D1/R2/DO、平台限流或客户端验收；不将这些项目记为已完成 |
| 2026-11-17 | B05-R8 / 纯 Rust CI 与产物复验（预算 25） | 已完成 | — | 完整 just ci 退出 0：Rust57/57、JS40/40、SQL50/50；fmt/WASM check/clippy 通过，剩余 89 条 clippy 警告；release、production dry-run、artifact/artifact-check 及实际预构建 no-bundle dry-run 通过 | Worker4826.71KiB/gzip1401.01KiB；唯一 WASM4877730B 可解析且与 build 相同；清单262文件；预构建部署未触发 custom build/Cargo；文档及 diff 检查通过 | 日志 rust-worker-ci-final.log、rust-worker-dry-run.log、rust-worker-runtime.log、rust-worker-no-bundle.log 保留于 .wrangler/verification；未部署、未转换旧迁移历史库，既有功能审计缺口继续保留 |

### ww1 31359e3 功能同步

以下卡均按一个协议或状态边界拆分，预算不超过 30 分钟。修改前快照为 `/home/vj/Codes/.raywarden-backups/20261117T082733Z-ww1-sync/source.tar.gz`；未重置原有工作树，未执行真实用户库迁移或部署。

| 日期 | 任务 ID | 状态 | 实际分钟 | 修改 / 产物 | 验证命令与结果 | 下一步或阻塞 |
| --- | --- | --- | ---: | --- | --- | --- |
| 2026-11-17 | W01 / 更新差异审阅（预算 20） | 已完成 | — | 对照 ww1 ab378e5→31359e3，按账户、密码库、Send 三域拆分；保留 Rust 入口与已有资源/部署决策 | 参考仓库干净且 HEAD 明确；功能新增、有意差异及旧缺口分别记入 feature-parity.md | 不把参考 601 项测试当成本项目结果；没有更新参考代码 |
| 2026-11-17 | W02 / V2 账户材料与协议（预算 25） | 已完成 | — | V1/V2 注册、首次 keys、公钥、profile/sync/token 共用映射；新增0008账户材料与代际快照，不清旧UUID key ID | Rust模型/版本边界、实际SQL与编译Worker HTTP均通过；注册验证状态入库、首次keys防覆盖与版本错误码有回归 | 普通V2客户端最低2026.10.1、桌面2026.10.2；固定前端未升级，注册受控初始化仍待实现 |
| 2026-11-17 | W03 / 密钥轮换与凭据竞争（预算 25） | 已完成 | — | 两rotation入口、完整集合/逐行快照/随机token同事务；桥接材料及防降级；密码/KDF/邮箱比旧verifier、材料、nonce | 同stamp升级、并发Cipher写、nonce/verifier竞争、重放和子写回滚；5×450KB合法rotation与两入口17MiB拒绝均实跑通过 | 上限16MiB，普通轮换严格撤销旧会话，不引access宽限；冲突409与普通资源400分别保持 |
| 2026-11-17 | W04 / PRF 与审批代际（预算 25） | 已完成 | — | PRF/挑战/审批捕获账户snapshot；密码/KDF/email仅对精确旧snapshot重标记wrapper，不改PRF密文或复活旧代际 | SQL正负retag、旧审批/PRF代际拒绝及HTTP邮箱CAS/改凭据保留有效PRF均通过 | 不声称省略key ID的旧客户端可被服务器完全识别；真实Passkey设备仍待验收 |
| 2026-11-17 | W05 / Cipher 新数据模型（预算 25） | 已完成 | — | 6–8类型、blob、500000字节限制、兼容payload回退、encryptedFor/keyID、archive/null取消归档和导入映射 | Rust类型独占字段、坏JSON与加密上下文；真实HTTP create/get/list/sync、组织导出转个人与大批导入通过 | 保留个人库范围，不加入组织协作 |
| 2026-11-17 | W06 / 密码库事务与通知（预算 25） | 已完成 | — | Cipher/Folder/附件/归档/import统一session+account+source guards与递增cursor；attachments2原子提交、资源事件代替泛化双发 | 同revision并发唯一赢家、末cursor失败全回滚、220项HTTP导入及450项SQL批量事务通过 | 通知尽力发送；真人双端重连与同步仍待取证 |
| 2026-11-17 | W07 / Send 访问与轮换（预算 25） | 已完成 | — | 领取token零计数；文本或有效文件授权原子计数与游标；key-only轮换、完整行条件、上传不覆盖并发count | 5个并发真实文本访问max2仅2成功；metadata/错误fileID/缺bytes不扣次；SQL与HTTP回滚、并发旧owner写拒绝通过 | 保留更严格的已有下载撤销策略，内部access_stamp仍轮换 |
| 2026-11-17 | W08 / 文件指针与清理（预算 25） | 已完成 | — | 0009追加随机暂存指针和无FK清理队列；删除/替换触发器登记旧key，generation确认；R2批量删除 | SQL6项附件事务、队列5项，实际HTTP lost ACK保采用文件、替换失败保旧、并发输家不删赢家通过 | 非D1/R2分布式事务；使用唯一暂存key，不是备份或完整孤儿扫描 |
| 2026-11-17 | W09 / 附件协议与授权（预算 20） | 已完成 | — | 稳定无token URL与默认60秒metadata能力；Bearer multipart可替换ready，Azure仅pending；保留旧capability与URL别名 | R2原生流、Range/HEAD、8MiB分块、中断、KV实际25MiB+1、旧raw格式与ready替换四场景通过 | 下载token不能写ready附件；未替换前端构建输入或要求新增运行Secret |
| 2026-11-17 | W10 / D1 大小与类型边界（预算 25） | 已完成 | — | Cipher直接多行读取；轮换count+逐行完整独立参数，移除整库聚合shadow路径；手工i64文件大小用number绑定 | SQLite限制2MB/函数32参数下旧5×450KB聚合失败、新SQL通过；真实WASM发现BigInt绑定500后修正，64组复跑通过 | 官方平台总响应/查询/CPU限制仍适用；不宣称无界密码库 |
| 2026-11-17 | W11 / TOTP 与兼容配置（预算 25） | 已完成 | — | TOTP step原子CAS、proof用户/会话/用途/key/状态绑定，provider snapshot和changes事务断言；兼容空列表、flags白名单与config no-store | TOTP4组真实启停/并发/跨会话/失败保Remember；配置2项Rust回归通过，兼容声明按源码与编译核对 | proof有时限但非单次；旧式request/enable/disable、set-password和其他旧审计缺口未冒充完成 |
| 2026-11-17 | W12 / 真实SQL Worker回归（预算 25） | 已完成 | — | workerd测试DO使用每次创建/清理的临时SQLite，D1仅API适配；R2/KV在内存，无监听/外网；分域测试共用同一入口 | 最新compiled WASM真实64/64通过，退出0；首次62/64日志保留，修复账户rotation409映射及fixture重复读body后完整复跑 | 不等同生产Cloudflare D1/R2/DO、实际浏览器/扩展或外部邮件/推送验收 |
| 2026-11-17 | W13 / 完整CI与交付产物（预算 25） | 已完成 | — | just ci退出0：Rust74/74、JS40/40、SQL92/92，0skip；fmt/WASM/clippy完成，clippy159条警告未清理；真实release与两种dry-run通过 | Worker5132.56KiB/gzip1512.26KiB，唯一WASM5190648B与build相同；artifact/artifact-check262文件；预构建no-bundle不触发Cargo/custom build | 日志ww1-sync-ci-verified.log、ww1-sync-runtime-final.log、ww1-sync-dry-run-verified.log、ww1-sync-no-bundle.log均在.wrangler/verification；原始失败日志保留 |

本轮没有新增 Rust/npm 依赖。构建时发现锁文件在任务期间出现 bumpalo/cc/uuid 三个补丁更新且缓存缺失，原因未确认；先保留 `Cargo.lock.unexpected-patch-update`，再用原生 `cargo update --offline --precise` 回到任务开始时已缓存版本。最终 Cargo.lock 字节与启动快照一致，`0001`–`0007` 也逐字节未变。源码指纹在构建前后相同；最终 WASM SHA256为 `2eb3afef2a947586ab82aba7046baca06c0d3fa7b7f6f54e62c7b5af4ddb3a0b`。

### Jiff、依赖与 JWT 整理（2026-11-17）

本轮最终完整 CI、release 打包、真实 workerd 和预构建部署预演均已通过。代码基线快照：`.raywarden-backups/20261117T094033Z-jiff-dependencies-jwt/source.tar.gz`（位于仓库上级目录）。实际应用数据库、迁移 SQL 和线上资源未改动。

| ID | 预算（分钟） | 状态 | 工作与验收 |
| --- | ---: | --- | --- |
| UP01 | 25 | 已完成 | 应用 chrono 全部迁到 Jiff 1；共享 UTC 毫秒字符串与微秒 API，保留旧偏移日期的按时间点比较及边界；Worker SDK 自身仍引入 chrono |
| UP02 | 25 | 已完成 | 用户完成 cargo update/fetch；Worker 0.9、RustCrypto 新稳定依赖已适配，WASM 树仅有 getrandom 0.4.3；删除 getrandom02 和直接宏依赖；worker-build 0.9.0、Wrangler 4.163.0 / workerd 1.20261116.1 配套安装，真实锁文件保留 |
| UP03 | 25 | 已完成 | JWT 严格整数时间、必需 exp、溢出保护与 TTL 配置校验；附件 exp 改 i64；API Key v2 用途隔离派生和完整随机 nonce，旧密文继续读取；已有账户丢 key 拒绝随机替代；9 组新增真实 Worker 回归通过 |
| UP04 | 20 | 已完成 | 最新完整 CI：91 Rust / 40 JS / 98 SQL；真实 Worker 73/73；普通编译无警告，clippy 161 条非阻断告警；release、两种 dry-run 及262文件清单/摘要校验通过 |

最终产物为 5659.04 KiB / gzip 1659.16 KiB；唯一 WASM 为5726383字节，SHA256 `6045e492e73d89b0aa355ddda1bc9addd1901168043470725b740b9b59e2d214`，与真实运行回归使用的 WASM 相同。构建前后源码/配置摘要一致。最终 no-bundle 预演未触发 Cargo 或 custom build。

通过日志位于 `.wrangler/verification/`：`jiff-ci-updated-tools.log`、`jiff-runtime-updated-workerd.log`、`jiff-dry-run-final.log`、`jiff-artifact.log`、`jiff-no-bundle.log`。原工具版本拒绝 SDK、沙箱 DNS 下载失败、旧 workerd 的 tracing API 首请求异常分别保留在 `jiff-dry-run.log`、`jiff-worker-build-install.log` / `jiff-dry-run-updated-tool.log`、`jiff-runtime.log`，没有用旧产物替代本轮验收。新 SDK 需要更新本地 runtime，无需为此修改 compatibility_date 或开启 traces。

构建工具固定版本由 `package.json` 提供，`just setup` 安装新版；只替换工具也可使用部署文档中的原生命令。后续 Cargo 更新不会自动升级 npm 或安装工具，需分别更新并验证。真实客户端、实际云端服务、已有旧迁移历史处理和生产部署仍独立验收。

### 本次审计后的优先修复卡

以下四张修复卡已在本轮补入并通过隔离回归；具体实现和边界见 W02–W12。真实客户端和线上验收仍按原计划独立完成。P/D 编号均指向 [功能移植审计](feature-parity.md)。

| ID | 预算 | 工作与产物 | 验收条件 |
| --- | ---: | --- | --- |
| M01 / P01 | 25 | 补齐 Cipher 6–8 的请求、存储和响应 | 三种新类型创建/导入可接受，普通序列化与实际 sync/list SQL 均保留密文字段；功能开关与实现一致 |
| M02 / P02 | 25 | 普通 Cipher 更新保存 attachments2 | 当前用户及Cipher归属约束有效，Cipher与附件key/名称一起成功或失败；补实际更新路径回归 |
| M03 / P03 | 25 | 对齐 Send token 与访问次数状态转换 | 领token不扣次；文本真实访问、有效文件访问才原子计数；错误fileID/只看元数据不扣次；同token并发受maxAccessCount约束 |
| M04 / D01 | 25 | Send 轮换仅修改重包key和revision | 请求中的名称/备注/内容/访问策略不覆盖现有值；保留账户轮换事务与范围校验 |

P04 继续复用 D04、E06、F03–F06 的唯一邮箱、单用户和受控初始化卡，不另建重复实现。剩余 D05、D09、D13 及旧兼容流程按当前功能对齐记录处理；不能把本轮已修的 D02/D04/D06–D08/D10–D12 继续列成未开始，也不能因隔离回归通过而关闭真实客户端验收卡。新增 pedantic 警告清理单独拆 25 分钟卡，不用大范围自动修复混入本轮业务同步。

新增修复卡时在此记录完整范围、15–25 分钟预算、验收条件和依赖；原卡在所有必要修复与验收通过前保持未完成。每阶段结束后更新本表，不覆盖之前的失败证据。

## 9. 参考资料

- [当前功能资产与验证限制](feature-parity.md)
- [统一运行配置表](runtime-config.md)
- [统一开发、数据库与部署入口](deployment.md)
- [现有备份与恢复说明](db-backup-recovery.md)
- [Raywarden Rust 入口](../src/lib.rs)、[入口分流](../src/dispatch.rs)、[ApiService](../src/api.rs)、[路由集合](../src/api/routers.rs)
- [ww1 接口说明](../../ww1/docs/endpoints.md)
- [ww2 项目说明](../../ww2/README.md)

后两项是当前并排检出的参考仓库；Raywarden 的构建与运行不应依赖它们存在。
