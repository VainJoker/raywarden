# Rust 架构重构设计

设计日期：2026-11-17，实施进度更新至2026-11-18。本文先于代码修改写入，作为实施和验收依据。现有行为与运行边界见 [architecture.md](architecture.md)，历史功能缺口见 [feature-parity.md](feature-parity.md)。本文不把重构等同于补齐注册、单用户约束或真实客户端验收。

## 1. 当前代码的问题

目前 `src` 有 103 个 Rust 文件，约 28,261 行（包含单元测试）。问题集中在职责和依赖方向：

| 位置 | 观察 | 维护影响 |
| --- | --- | --- |
| `api.rs` | 状态、入口、通用响应和 HTTP 错误输出放在一起 | 修改协议格式需要同时理解运行入口；`ApiService` 只有静态调用，`ApiResponse` 无消费者 |
| `api/service/claims.rs` | 同时保留 AppState、旧 Arc<Env> 和未使用 AuthUser 鉴权入口 | 容易改错实际生效的鉴权路径 |
| `infra.rs` | `cfg/cryptor/dber/jwtor` 命名及通配重导出 | 类型和函数来源不清，`DB` 同时是句柄容器和静态函数命名空间 |
| `controller/ciphers.rs` 与 `attachments.rs` | 互相调用 guard、附件响应补全和通知逻辑 | HTTP handler 成为共享业务接口，调整端点容易牵连其他端点 |
| `models/user.rs`、`cipher.rs`、`send.rs` | 数据库行、请求响应、纯校验、SQL 混在大文件中 | 同名 DB 类型承担太多职责，模型出现反向依赖 API Claims 的情况 |
| SQL 回归 | 部分断言仍执行生产已不用的旧轮换/CRUD 方法；按固定源码路径提取 SQL | 测试通过可能没有覆盖实际写入路径，也会阻碍合理拆分 |

文件长度只用于定位阅读成本，按职责和事务边界决定拆分。保留真正有状态的类型，例如 AppState、NotifyDo、存储句柄；单纯组织函数时使用模块和自由函数。

## 2. 设计原则

1. 保持单 crate，使用 Rust 模块、显式导入和受限可见性。暂不引入 ORM、通用 Repository trait、依赖注入容器或多 crate 工作区。
2. HTTP 层负责提取参数、状态和错误协议；业务逻辑负责授权后的编排；持久化模块负责行数据和具体 SQL。纯校验和编解码不读取 Worker 环境。
3. 共享业务行为由具名 service 模块提供，controller 不再调用另一个 controller 的内部辅助函数。跨资源事务保留一个明确的编排入口。
4. 用结构体表达数据与实际状态，用枚举表达有限状态。后续拆 DTO、数据库行、已验证上下文时保持序列化协议；不在本轮批量包装所有 String ID 或实现一套泛化状态机。
5. 按请求加载配置与 D1 密钥；同一请求内通过 Arc 共享配置及 D1 句柄。SDK 的 D1Database 不实现 Clone，必要的 Arc 保留。新增数据库绑定错误使用 Result 传播。
6. 每一步能通过真实运行回归；路径迁移与业务规则变更分开。删除函数先查生产调用及测试用途，测试造数与生产行为断言分开处理。

## 3. 第一轮目标结构

```text
src/
  lib.rs                       Worker 事件和初始化
  dispatch.rs                  进入应用前的 DO 分流与流保留
  errors.rs                    错误枚举、Result、错误构造
  api.rs                       handle_request：组装、执行、提交后通知
  api/
    state.rs                   请求状态及其 fallible 构建
    response.rs                RawJson、HTTP 状态和错误响应协议
    middleware.rs
    routers/                   URL 和方法映射
    controller/                HTTP handler
    service/
      claims.rs                唯一生效的 AppState 鉴权提取器
      cipher_mutation.rs       密码库共享快照及提交边界
      ciphers.rs               密码项与归档共用的修改、附件密钥更新及通知编排
      attachments.rs           供多个端点使用的附件响应投影
      maintenance.rs           cron 编排（原 controller/purge）
      ...                      现有具名业务逻辑
  models/                      本轮保留现有 SQL 文件位置
  infra/
    config.rs                  配置及通用环境读取
    db.rs                      查询错误上下文和严格行解码函数
    crypto.rs
    jwt.rs
    jwt_keys.rs
    delivery.rs                邮件及管理事件投递
    time.rs
    webauthn.rs
    storage/
      mod.rs                   R2/KV 与原生响应流
      range.rs
      cleanup.rs               持久清理 outbox
  durable/                     HeavyDo / NotifyDo 平台适配
```

`AppState` 负责持有真实状态；`db` 模块的通用函数不再挂在 `DB` 类型上。`ApiService::run` 收敛为 `api::handle_request`，普通 Worker 和 HeavyDo 使用同一入口。HTTP 错误映射放在 `api/response.rs`，核心错误不再通过 HTTP trait 输出状态码。保留现有错误码及 wire shape。

通用环境读取只合并相同语义的实现。JWT 旧 Secret 导入必须区分不存在、空值、非字符串及读取失败，继续使用专用严格读取路径。存储的 Range 与清理模块归入 storage，但不合并各自职责。

## 4. 后续业务组织

第一轮稳定后，按真实业务能力逐个收敛为 `account/`、`vault/`、`send/`、`notifications/`。每个模块只按需要包含 `http`、`types`、`validation`、`store` 和具名事务模块；不要求每个目录都配齐相同的几层。

依赖方向为 HTTP → 业务用例 → 持久化/平台能力。跨账户、Cipher、Folder、附件、Send 的密钥轮换仍由一个用例编排器组成同一个 D1 batch。模型改为接收明确的用户/会话快照或 statement 参数，逐步解除对 API Claims 的依赖。共享的原子提交规则集中维护。

在搬动模型 SQL 之前，先整理测试源码定位，再逐项删除已无生产消费者的旧写入路径。fixture 可直接 INSERT；关键行为断言继续执行当前生产 SQL，并通过编译 WASM 验证真实调用及参数绑定。不会为维持旧测试而保留第二条生产写入路径。

## 5. 安全与兼容约束

- 路由、HTTP 方法、成功/失败状态、JSON 字段和现有错误码保持兼容；OAuth、2FA challenge、身份 challenge 分别保留协议，5xx 不暴露内部错误。
- 普通 access/refresh 的用途、签名、时间、stamp 与设备会话校验完整保留。匿名 Send 与文件 capability 保持独立授权，不能统一套登录中间件。
- 账户代际、资源快照、并发修改和完整集合断言继续在同一个 D1 事务中执行，禁止拆成先查后写。
- 上传的长度限制、流中断处理、随机暂存 key、提交不确定时的保留策略、清理 outbox 与 generation 确认保持原有语义。
- NativeStream 下载、HEAD/Range、WebSocket 101、分流前不消费正文及 HeavyDo 共用业务链继续保持。
- D1 密钥已有行优先、空库首次初始化、并发重读赢家、读取失败不换钥、旧 API Key 密文读取保持不变。

## 6. 分步实施与验收

预算是每张工作的拆分上限，不补造实际耗时。A01–A06 和 B01–B06 均已完成；下表保留原计划，实际结果见两轮实施记录。

| ID | 预算 | 工作 | 验收 |
| --- | ---: | --- | --- |
| A01 | 20 min | 分离 API 状态、入口、响应；移除无用 ApiResponse 和 ApiService 壳 | 普通 Worker/HeavyDo 均调用同一函数；现有响应兼容 |
| A02 | 15 min | 删除旧 Arc<Env> / AuthUser 提取器；配置在请求内共享 | 仅保留实际使用的 Claims 提取器；现有认证回归通过 |
| A03 | 25 min | 基础模块命名、显式导入、DB 模块函数、统一通用 env 读取 | 来源明确；缺 binding 通过 Result 返回；JWT 严格读取未弱化 |
| A04 | 20 min | 存储模块聚合，cron 移到 service，删除空 utils 与无用类型 | 导出类、Range/流、定时清理及 SQL 测试定位正确 |
| A05 | 25 min | 把 controller 之间共享的 guard、附件投影和通知移入业务模块 | 两个 controller 不相互调用；事务与 JSON 不变 |
| A06 | 25 min | 运行 CI、release、真实 Worker 和产物预演，更新架构说明 | 对比原有 91 Rust / 40 JS / 98 SQL / 73 Worker 基线，无跳过；新产物对应新源码 |
| B01 | 25 min | 集中 SQL 测试的生产源码定位 | 一个函数来源明确，拆文件后不误取同名函数 |
| B02 | 25 min | 删除旧 user 轮换/密码/KDF 写路径，断言迁到现行事务 | 并发与失败回滚检查继续覆盖实际用例 |
| B03 | 25 min | 删除旧 Cipher CRUD，清理测试造数依赖 | 当前快照保护的写路径成为唯一生产实现 |
| B04 | 25 min | 按 types/codec/store 拆 Cipher | serde、SQL、兼容版本门槛完整保留 |
| B05 | 25 min | 拆账户行数据、请求协议、轮换编排 | 每个职责有独立入口，密钥事务不拆散 |
| B06 | 25 min | 收敛 Send 的 token、流、访问和提交模块 | 匿名访问计数、能力用途及并发文件回归通过 |

任何步骤发现协议或事务需要改变，另列功能修复，先完成当前结构步骤的回归。此重构不执行 `db-migrate`、不清理应用数据、不部署生产，也不新增运行配置或依赖。

## 7. 第一轮实施记录（2026-11-17）

设计先行落盘后，A01–A06 已完成；B01–B06 保留为后续工作，本轮没有重写模型或删除旧 SQL 写入方法。

实际修改：

- `api.rs` 从235行收敛到38行；状态和 HTTP 响应分别移入独立模块。删除 ApiService、ApiResponse、AuthUser、旧 Arc<Env> 提取器和未使用的 StandardClaims。
- `AppState` 直接持有共享 D1 句柄，配置使用 Arc，按请求加载；删除 DB 容器，数据库辅助函数成为模块函数。绑定失败使用 Result 返回，不使用 expect。
- 基础模块和存储目录按目标结构组织，移除通配重导出、重复环境读取和空 utils。JWT 专用严格读取保留，cron 移到 maintenance。
- 密码项 controller 从850行收敛到554行。归档与密码项共用 `service/ciphers.rs`，附件与密码项共用附件投影，guard/commit 独立维护；controller 之间的共享辅助调用已移除。SQL 测试更新对应生产来源，没有复制 SQL。
- 复用 String/Option 的 clone_from，去掉拆分后不需要的导入；没有为压低行数或告警数引入转发层和 lint 屏蔽。

验收结果：

| 检查 | 结果 |
| --- | --- |
| `just ci` | Rust 96/96、JS 40/40、SQL 98/98；fmt/WASM 检查通过，普通编译无警告；Clippy 159条非阻断告警，原为161条 |
| 原有测试保留 | 所有原生测试函数名保留；新增5项 HTTP 错误/RawJson 契约测试 |
| 真实 workerd | 74/74；新增 D1 缺绑定/配置读取后绑定失效的脱敏500、CORS及后续请求可用检查 |
| SQL 对照 | 与修改前源码中239处 SQL 字面量对照，规范化 Rust 换行续接后完全相同，重复次数相同 |
| release 与部署预演 | 新源码重新编译；普通 dry-run、262文件清单/摘要校验、预构建 no-bundle dry-run 通过 |
| 改动范围 | Cargo/npm锁、依赖清单、Justfile、两份 Wrangler 配置与全部迁移 SQL 均与源码快照逐字节一致 |

唯一 WASM 为5844419字节，SHA256 `157af28df445627c75d825887110d6921e68f793aca587ec61230e883733de0d`。最终 bundle 为5774.30 KiB / gzip 1669.33 KiB。源码/配置摘要在构建前后相同，bundle 中的 WASM 与运行回归使用的文件一致。此轮关注职责和所有权，没有据此宣称包体或执行时间下降。

源码快照位于仓库上级 `.raywarden-backups/20261117T102629Z-rust-architecture/source.tar.gz`。通过日志位于 `.wrangler/verification/`：`rust-architecture-ci-verified.log`、`rust-architecture-runtime.log`、`rust-architecture-dry-run.log`、`rust-architecture-artifact.log`、`rust-architecture-no-bundle.log`。整合期旧导入、SQL测试来源未同步时的失败日志保留，最终结果以这些通过日志为准。

实际数据库没有迁移或清理，生产没有部署。单用户初始化、真实客户端及云端服务验收仍按原功能计划单独完成。

## 8. 第二轮实施记录（2026-11-18）

B01–B06 已完成。快照：仓库上级 `.raywarden-backups/20261118T015548Z-rust-models/source.tar.gz`。本轮改动按原设计落在模型、Send 用例及相关回归定位上，没有引入新依赖、配置或数据库迁移。

| 工作 | 当前结果 |
| --- | --- |
| B01 / SQL 来源 | `tests/sql_source.py` 集中登记所有生产 SQL 源文件；按函数体边界读取，忽略字符串、字符和注释中的括号；缺失、重复函数、无函数体声明及重复查询前缀明确失败；6项 reader 回归通过 |
| B02 / 旧账户写法 | 删除9个无生产消费者的旧方法，包括旧轮换、密码/KDF更新及不带条件的 verifier 迁移；保留真正被登录调用的 `migrate_legacy_password_if_current` |
| B03 / 旧密码库写法 | 删除无消费者的旧 Cipher CRUD/清理入口与整个 ArchiveDB；造数使用明确 fixture INSERT，更新/归档断言改执行当前写入语句及快照 guard |
| B04 / Cipher | `cipher/{mod,types,codec,store}.rs`；1673→1261行，原10项 native 回归保留，模块显式导出，无旧接口转发 |
| B05 / User | `user/{mod,row,requests,credentials,store}.rs`；1269→933行，原公共使用接口与3项注册回归保留，SQL 集中 store |
| B06 / Send | service 拆为 mod、token、access、upload、mutation、rotation、cleanup；模型提供 insert statement 与快照 predicate，service 负责 Claims、guard、配额和统一事务，模型不再反向依赖 API |

SQL reader 用于登记的生产源码定位，并非通用 Rust parser；遇到尚未支持的嵌套块注释会明确拒绝，避免把注释中的查询当成可执行 SQL。新增源码语法需要先补对应读取回归。

旧轮换测试已迁到 `service/account_keys.rs::rotate` 的真实 claim、逐行快照及 write_token 门控语句。回滚用例先确认 Cipher、附件和 Send 更新各命中1行，再在实际末尾 approval cleanup 注入故障，验证账户材料及所有包装 key 一起回滚。SQL 层的资源/写入 token 断言与 HTTP 的资源归属校验分别验证，不再混为同一个证据。

新增真实 Worker 回归：完整自有轮换材料混入他人附件时，在写入事务前返回明确归属错误，账户/密码项/附件/会话都不变；移除外部附件后同一材料和会话成功，作为正对照。单条/批量归档正常，混合其他用户条目的选择被整体拒绝，已有条目和游标不发生部分更新。

| 验收 | 结果 |
| --- | --- |
| 完整 CI | Rust 96/96、JS 40/40、SQL 104/104；所有原生 Rust 测试保留；普通编译无警告，Clippy 158条非阻断告警（前轮159） |
| 真实 workerd | 76/76（原74组全部保留，新增归档和附件归属两组） |
| 生产 SQL | 239→208处，删除31处旧 SQL；使用相同提取器对照源码快照，没有新增或改写保留的 SQL 字面量 |
| 产物 | release、普通 dry-run、262文件清单/摘要、预构建 no-bundle dry-run 均通过 |
| 配置边界 | Cargo/npm清单与锁、Justfile、两份Wrangler配置、全部迁移 SQL 与快照逐字节一致；实际数据库和线上环境未操作 |

唯一 WASM 为5825454字节，SHA256 `14df03813d852e37f5878e04d73df0da19b29af4f811d6b6dbb062976e0f3184`；bundle 为5755.78 KiB / gzip 1664.98 KiB。构建前后源码/配置摘要相同，bundle 与真实运行回归使用同一份 WASM。此处记录实际产物，不据此推断运行速度。

通过日志位于 `.wrangler/verification/`：`rust-models-ci.log`、`rust-models-sql-final.log`、`rust-models-runtime.log`、`rust-models-dry-run.log`、`rust-models-artifact.log`、`rust-models-no-bundle.log`。SQL 初次校验发现的旧 collection_guard 定位失效已更新；WebAuthn fixture 的未关闭 SQLite 连接也已按实际分配栈定位并修正，没有屏蔽告警。

账户唯一性、受控初始化、客户端解密、外部服务与云端部署仍按原功能计划独立验收；这轮没有把结构重构当成功能缺口的完成证明。

## 9. 第三轮设计：业务聚合与认证边界

本节在第三轮代码修改前写入。继续整理有真实跨层调用和多处维护入口的部分，附件流重构与133处数据库访问器的借用化另行安排。

| ID | 预算 | 改动与验收 |
| --- | ---: | --- |
| C01 | 25 min | 聚合 Send 到 `src/send/`：HTTP、路由、现有用例平移，模型拆 types/store；删除旧声明，不留旧路径转发；域外仅暴露路由、同步列表、identity grant、轮换、清理和轮换请求类型 |
| C02 | 20 min | 2FA 写入改接收中性的借用会话快照，由 Claims 在 API 侧构造；不再由模型依赖 API；stamp/nonce/factor snapshot 与 Remember 清理继续同事务 |
| C03 | 25 min | 邮箱 factor proof 的签发/校验移入具名业务 service，两个 controller 共用；保持邮箱和 TOTP proof 的独立用途、状态、会话及严格过期边界 |
| C04 | 20 min | 单列功能修复：统一登录和 profile/sync 对“要求二次验证”的判断，修复 Email-only/WebAuthn-only 被报告为 false；Remember/disabled 不计入，未知旧 provider 的现有登录处理保持原样 |
| C05 | 25 min | 账户查询/插入 SQL 收回已有 user/store，删除只转取 db 的 user service；WebAuthn 验证 DTO 改直接字段转换；共享设备 header 解析退出 controller |
| C06 | 25 min | 保留既有96 Rust/40 JS/104 SQL/76 Worker基线，补2FA状态与proof绑定回归；验证 SQL、完整构建、真实 workerd 和产物预演 |

Send 目标为 `send/{mod,http,routes,types,store,token,access,upload,mutation,rotation,cleanup}.rs`。域内接口不再通过全局 API service 导出；保留现有 AppState、Claims、共享事务、通知与限流依赖，不为目录迁移新建通用上下文框架。

会话快照仅携带 SQL 要比较的借用字段，不代表无需再检查数据库授权，也不派生可泄漏会话内容的 Debug/Serialize。模型层继续在写入 SQL 中比较实时会话和因子快照。

C04 改变状态输出，独立于机械迁移验证。共享判断以现有登录条件为准：启用、非 Remember、非内部记录。不会借修复状态展示而忽略未知旧因子、放宽登录或改变恢复码对未知因子的处理策略。当前真实可配置的 TOTP、Email、WebAuthn 及 Remember-only、disabled 场景须分别覆盖。

C01–C06 已按此设计实施，实际结果见下一节。运行配置、依赖和迁移链保持原范围，不操作应用数据库或部署线上。

## 10. 第三轮实施记录（2026-11-18）

源码快照：仓库上级 `.raywarden-backups/20261118T022532Z-rust-domains/source.tar.gz`。本轮先写第9节设计，再完成业务聚合、认证边界和单列的状态修复。

| 工作 | 当前结果 |
| --- | --- |
| C01 / Send | HTTP、路由、用例、类型和持久化聚合为 `src/send/` 的11个模块；删除旧 controller/router/model/service 声明及路径，不保留转发层。域外暴露5个 crate 内操作，以及账户轮换请求所需的公开 `RotateSendData` |
| C01 / 可见性 | 行数据、请求和实现细节收窄到 Send 内；删除无人调用的 `SendDB::update/delete` 封装，保留当前使用的 statement 构造。请求 `id` 虽未使用，仍按字符串解析并拒绝数字，未通过删字段放松旧输入契约 |
| C02 / 会话边界 | `SessionSnapshot<'a>` 仅借用 user/stamp/device/session 字段；Claims 在 API 侧验证用途后构造，2FA 模型不再引用 API。原 SQL 与绑定顺序不变，写入仍检查实时会话、因子快照并原子清理 Remember |
| C03 / 邮箱 proof | 签发和验证移入 `service/twofactor.rs`，两个 controller 共用；保留用途、账户、stamp、会话、邮箱状态、300秒有效期及零宽限期，不与 TOTP proof 互换 |
| C04 / 状态修复 | 登录与 profile/sync 共用因子判断，修复仅启用 Email 或 WebAuthn 时错误显示未开启2FA。Remember、disabled 和内部记录不计入；未知旧 provider 继续遵循已有登录策略，恢复码清理范围未改 |
| C05 / 职责整理 | KDF 查询投影和注册 INSERT 归入 user 模型/store，删除只转取数据库的 user service；WebAuthn 验证请求直接转换字段；设备 header 与客户端版本解析由共享 auth service 提供，调用方不再依赖另一个 controller |

新增真实 Worker 回归分别验证：profile/sync 对各类因子的状态一致；Email/TOTP proof 不能跨用途使用，邮箱状态变化后旧 proof 失效且不会清除 Remember；新会话可正常访问 profile，但不能复用旧会话的邮箱 proof，重新验证得到的新 proof 可以完成操作。原有4组 TOTP 回归全部保留。

| 验收 | 结果 |
| --- | --- |
| 完整 CI | Rust 98/98、JS 40/40、SQL 104/104；fmt/WASM 检查通过，普通编译无警告；Clippy 保持158条非阻断告警 |
| 原有测试 | 原96个 native 测试全部保留，新增会话快照和因子分类2项；真实 Worker 原76组全部保留 |
| 真实 workerd | 79/79；使用本轮新编译的 release WASM，执行实际 HTTP、SQLite 事务和存储替身回归 |
| 生产 SQL | 修改前后均208处，字面量和重复次数完全相同；移文件没有复制或改写查询 |
| 产物 | 普通 dry-run、262文件清单/摘要检查、预构建 no-bundle dry-run 全部通过；构建前后170个源码、测试、脚本及配置文件摘要一致 |
| 改动范围 | Cargo/npm清单与锁、Justfile、工具链、两份Wrangler配置及全部迁移文件与快照逐字节一致；应用数据库和线上环境未操作 |

唯一 WASM 为5844836字节，SHA256 `9f6eb6ed9fc4aa41d1ffa3c34da78367f18f311c12075c7a496ffdac56f18015`；bundle 为5774.71 KiB / gzip 1668.71 KiB。真实运行回归与 bundle 的 WASM 逐字节相同；目录聚合不作为运行速度或包体下降的证明。

通过日志位于 `.wrangler/verification/`：`rust-domains-ci-final.log`、`rust-domains-runtime.log`、`rust-domains-dry-run.log`、`rust-domains-artifact.log`、`rust-domains-no-bundle.log`。源码/SQL/测试保留对照记录为 `rust-domains-comparison.json`，构建摘要核对为 `rust-domains-final.json`。

接下来先完成原功能计划中的唯一所有者、关闭公开注册和独立授权初始化，再固定 Web Vault 与一个扩展验证登录、解密、同步和会话撤销。账户/密码库按业务聚合、附件 HTTP 与存储编排拆分，以及数据库访问器借用化均保留为有明确收益时再做的结构工作，不继续通过搬目录代替功能验收。

## 11. 第四轮设计：配置能力与参考行为对齐（2026-11-18）

本节在本轮实现前写入。参考本地 ww1 `31359e3` 与 ww2 `7a9f6b9`，不修改参考仓库。将上一轮列出的真实缺口补成可测试的行为，再复查配置、路由及产品范围内的功能差异；不把 CSS 展示等同服务端功能，不增加组织、SSO 或紧急访问后端。

| ID | 预算 | 工作与验收 |
| --- | ---: | --- |
| D01 | 25 min | 单独日志模块解析全局/模块过滤，auth/api/db/external/notify 确实分类；覆盖默认、非法值、off 与模块覆盖 |
| D02 | 25 min | 实现完整 VW_CSS 开关矩阵及自定义样式加载；保留既有变量别名，ETag 随输出变化，公开缓存不混配置 |
| D03 | 20 min | 补客户端 onboarding flag 的实际输出，与参考端 config/client 补丁对照；注册权限不受展示开关影响 |
| D04 | 25 min | 通知事件用具名类型、级别及筛选策略；保留旧事件过滤兼容，按收件人发送验证码的通道保持独立 |
| D05 | 25 min | 登录、失败、刷新、同步、设备审批及 Passkey 通知接实际结果，拒绝路径不误报成功，不记录 token/验证码/密文 |
| D06 | 25 min | 密码库、Send、账户/2FA 安全操作事件对齐，移除旧泛化路径双发；提交失败不产生成功事件 |
| D07 | 25 min | CORS_ALLOWED_ORIGINS 与旧 ALLOWED_ORIGINS 共用一个严格策略；主入口/DO/错误/预检一致，显式无效列表不放开 |
| D08 | 20 min | DEMO_PAGE_ENABLED 默认关闭；通过 Rust 受控提供保留的 demo，禁止静态产物绕过；展示页不豁免原 API 鉴权 |
| D09 | 25 min | 重新核对两个参考仓库的路由、配置及已有功能审计，修正本轮发现的配置相关遗漏并登记剩余产品功能缺口 |
| D10 | 25 min | 集中配置解析与事件/展示职责，删除重复判断；不为配置增加数据库表或依赖框架 |
| D11 | 25 min | Rust/JS/SQL/真实 Worker 回归与 release、产物预演，更新配置、架构及功能对照记录 |

已有运行基线为 Rust 98、JS 46、SQL 104、Worker 79。测试按真实边界扩展，验证通过前不写完成结论。`DOMAIN` 仍由生产 Worker Secret 提供；单用户约束、受控初始化、旧兼容端点和真实客户端验收不能因新增配置被标为完成。实际数据库、Secret 和生产部署不在本轮操作范围内。

## 12. 第四轮实施记录（2026-11-18）

D01–D11 已完成。源码快照位于仓库上级 `.raywarden-backups/20261118T035625Z-configuration/source.tar.gz`。参考仓库仍为 ww1 `31359e3`、ww2 `7a9f6b9`，仅阅读本地检出，没有修改或更新参考仓库。

| 能力 | 实际改动 |
| --- | --- |
| 模块日志 | `infra/logging.rs` 解析全局与 auth/api/db/external/notify 覆盖，按实际 target/module_path 分类；支持全局 off 后单独启用模块，保留原 once-per-instance 初始化和 console 输出 |
| 展示与 onboarding | `service/ui.rs` 集中全部15个 VW_CSS 项；支持四套布尔写法、旧 Passkey 名回退、自定义 CSS 加载开关。移除基础 CSS 中与开关冲突的固定隐藏规则。onboarding 输出前端实际消费的独立 `suppressOnboardingInterstitials`，不再混入注册设置 |
| 管理通知 | `infra/admin_notify.rs` 使用具名事件和级别，接入24类参考事件及旧 Ray 名称；验证码邮件留在 delivery。具体用例成功后发布，generic Mutation 只保留客户端同步，避免管理通道双发 |
| 通知边界 | 登录失败仅指明确凭据拒绝，正常2FA挑战、429、版本门槛及数据库故障不误报；不存在/已停用因子不发重复停用事件；security-stamp 保留原安全通知；失败投递不撤销业务结果。管理消息只含事件、级别和账户 ID |
| CORS | `infra/cors.rs` 共用于主 API、DO 分流、预检及入口错误，支持新名与旧名回退；空值/星号允许任意来源，显式无效列表保持拒绝；不启用 cookie credentials。删除只转发 CORS 构造的 middleware 文件 |
| Demo | 默认关闭、通过 Rust 受控返回，设置 CSP/no-store；准备 UI 时删除静态副本，生产路由明确 Worker 优先。页面改用当前密码、邮箱验证码、TOTP proof 和 bearer usage API；V2/Argon2 明确提示使用正式客户端 |
| 配置与复核 | Wrangler 补齐真实配置项和注释；生产新增可选项留作注释以保留 Dashboard 覆盖，本地显式默认。`feature-parity.md` 第0节重新核对当前能力及剩余差异，历史证据保留 |

| 验收 | 结果 |
| --- | --- |
| 完整 CI | Rust 114/114、JS 52/52、SQL 104/104；fmt/WASM 检查通过，普通编译无警告；Clippy 保持158条既有非阻断提示 |
| 原生回归保留 | 原98项中97个测试函数名保留；原单级日志测试由8项解析/真实过滤回归替代，另补 UI、CORS、通知筛选与错误分类 |
| 真实 workerd | 92/92；原79组保留，新增展示4组、CORS/demo2组、管理通知7组；实际执行编译后 HTTP、SQLite 事务及存储替身 |
| 生产 SQL 与配置边界 | 与快照对照208处 SQL 字面量及重复次数完全相同；依赖清单/锁、工具链、Justfile、全部 SQL 与迁移文件逐字节相同，没有新增依赖或迁移 |
| Demo 密码学边界 | 原17个编码/密码学 helper 与快照逐字相同；6项 Node VM 客户端测试实际运行 WebCrypto，验证重包装后仍能解出原用户 key，并检查验证码、proof、会话和错误脱敏 |
| release 与部署预演 | 新源码 release、普通 dry-run、262文件清单/摘要、预构建 no-bundle dry-run 全部通过；构建与运行测试使用同一份 WASM |

唯一 WASM 为5901393字节，SHA256 `935d6c55e4538f1d89dd1873768be09e80aca768e49dbe8422d3fab213426d38`；bundle 为5829.94 KiB / gzip 1691.20 KiB。构建前记录190个输入的摘要，所有生产源码、静态源文件和配置在构建后相同；实际运行期间仅修正一个测试插件的 SDK binding 类名和既有401响应期望，没有改动生产代码或重新构建不同产物。

第一次运行暴露了测试契约错误：普通 Object 不会被 worker 0.9 识别为 `Ratelimit` binding，原 mock 实际走了缺失 binding 回退；修正为对应类并断言真实调用次数。同时将错误密码与被掩码的查询故障期望对齐现有401响应。最后92组全部通过，未为测试改变生产认证或限流行为。

通过日志在 `.wrangler/verification/`：`configuration-ci-final.log`、`configuration-runtime.log`、`configuration-dry-run.log`、`configuration-artifact.log`、`configuration-no-bundle.log`。`configuration-sql-diff.json`、`configuration-demo-crypto.json`、`configuration-final.json` 分别记录 SQL、密码学 helper 和产物摘要对照。整合期首次失败日志保留，最终结论以通过日志为准。

功能对照仍明确保留 P04（唯一用户、服务端关闭注册、独立所有者初始化）、D05（verifier成本记录及升级）、D09（未知邮箱KDF策略）。当前固定 Web Vault 2026.7.0 不能通过 V2 账户的2026.10客户端门槛；V1账户不受该条件限制，V2可选升级/注册继续不默认启用。旧 set-password 状态流及 TOTP 三入口并非当前流程的简单别名，未用空实现补齐。真实浏览器/扩展、云端资源和真实通知外发仍须分别验收。

这轮没有清理或迁移应用数据库，没有读取、转换远程 Secret，没有推送、部署生产或发送真实通知。继续建设时先处理所有者初始化和指定客户端闭环，再按失败证据决定下一轮结构优化。

## 13. 第五轮设计：从零部署的阻断修复（2026-11-18）

本节先于本轮修复写入。目标是验证“没有 Worker、没有应用表、没有账户”的真实起点，修复可确认的阻断，并给出有前提、结果和验证方式的部署文档；不实际创建云资源、迁移用户数据库或部署生产。

| ID | 预算 | 工作与验收 |
| --- | ---: | --- |
| E01 | 25 min | 注册统一要求独立所有者初始化授权，白名单必须为一个完整邮箱；所有现有注册别名共用同一规则，缺失配置拒绝创建 |
| E02 | 25 min | `/setup` 验证 OWNER_SETUP_TOKEN，空库才签短期、绑定域名和邮箱的 HttpOnly/SameSite 初始化凭据；仅授权浏览器开放注册展示，客户端仍生成账户密钥 |
| E03 | 20 min | 追加唯一常量索引约束，数据库拒绝第二用户和并发输家；已有多用户库迁移失败停止，不删除/合并用户 |
| E04 | 25 min | 首部署通过 Wrangler secrets-file 写入运行时 Secrets；DOMAIN 来自选定公开入口，ALLOWED_EMAILS/OWNER_SETUP_TOKEN 来自受保护环境变量；临时文件限权、成功失败均清理 |
| E05 | 20 min | 首次开户、普通注册拒绝、授权过期/混用、并发和初始化后再用的真实 Worker 回归；保留资源归属用例的异常历史库场景 |
| E06 | 25 min | 检查配置、Cookie、域名与已有账户兼容，修正本轮可复现问题，不无证据改变验证码/密钥轮换等协议 |
| E07 | 25 min | 从零文档覆盖资源创建、Secret 准备、第一次 CI/部署、唯一账户初始化、登录同步、后续部署和恢复边界；每步解释用途与预期 |
| E08 | 25 min | 完整 CI、release、真实 Worker 与预构建 dry-run，记录实际结果和仍未验证的真实云端/浏览器边界 |

新增 `OWNER_SETUP_TOKEN` 只用于所有者初始化，不能替代主密码或生成客户端加密材料。生产邮箱移至 Worker Secret，缺失时不允许初始化；本地保留虚构邮箱。保留当前默认 workers.dev：`DOMAIN` 每次部署由账户子域名与 Worker 名推导，或优先使用显式 custom-domain 路由，再作为 Secret 写入，不要求提前创建空 Worker。后续部署可以沿用已有的邮箱/初始化 Secret，只有显式提供的环境值才更新它们。数据库/私钥不进 GitHub artifact。

## 14. 第五轮实施记录（2026-11-18）

从零部署检查确认并修复了首次 Secret 上传、公开注册缺少所有者授权、数据库没有用户数量约束、DOMAIN 接受非 origin 值，以及固定 Web Vault 不能使用 localhost HTTP API 的问题。

| 项目 | 最终实现 |
| --- | --- |
| 开户授权 | `service/setup.rs` 统一严格单邮箱、独立随机令牌、空库检查和十分钟初始化 JWT；`controller/setup.rs` 提供无缓存、防嵌入的表单与签发接口。所有注册别名、注册邮件准备都先校验授权，注册成功清除 Cookie |
| 用途隔离 | Cookie 为 HttpOnly/SameSite=Strict，HTTPS 使用 Secure；绑定 origin、邮箱、purpose、nbf/iat/exp。普通 API/refresh/factor token 不能代替初始化授权，初始化凭据不授权保险库访问 |
| 单用户约束 | 追加 `0010_single_user.sql` 的常量唯一索引；重复和并发开户返回409，其他数据库错误仍传播。已有多用户库迁移失败且保留数据；原隔离测试显式模拟异常历史多用户，不放松生产约束 |
| 首次发布 | 保留默认 workers.dev 和可选唯一 custom domain；从入口推导 DOMAIN，以权限0700/0600的临时目录/文件随代码上传 Secrets。邮箱与初始化令牌由 GitHub Secrets 传入，未提供的旧 Secret 保留，成功失败均清理临时文件 |
| 配置校验 | DOMAIN 必须为规范 HTTPS origin，禁止凭据/路径/query/fragment，HTTP仅供loopback兼容。部署脚本与Rust使用相同的单邮箱/令牌边界，workers.dev 名称符合DNS label，健康请求带明确User-Agent |
| 本地客户端 | 实际浏览器证明固定2026.7.0客户端拒绝HTTP API，包括localhost。`wrangler.local.jsonc` 统一 `dev.local_protocol=https` 与 `DOMAIN=https://localhost:8787`，无需更改生产入口或Rust产物 |
| 文档 | 重写[从零部署指南](deployment.md)，逐步解释资源、Secret、workflow、受控开户、验收、更新重试和备份边界；同步README、配置表、架构与当前功能审计 |

验证结果：

| 检查 | 结果 |
| --- | --- |
| 原生完整 CI | 格式、Rust119、JS64、SQL108、WASM检查通过；clippy警告模式通过，现有代码仍有159条警告，不等于零告警 |
| 本地HTTPS修复后Node回归 | 65/65通过；仅配置与测试变化，不需要重新编译Rust |
| 实际release WASM/workerd | 100/100通过，覆盖初始化别名、严格Cookie/用途/过期、邮件code保护、并发冲突及已有密码库/文件/会话回归 |
| 普通Wrangler dry-run与artifact | 通过，262个交付文件的摘要校验通过 |
| 真实预编译CLI路径 | Wrangler4.163.0接受 `--dry-run --no-bundle --secrets-file`，必需与额外Secrets识别并脱敏，没有custom build或网络访问；私有临时配置已删除 |
| 真实浏览器基础链路 | Chromium159 + 固定Web Vault2026.7.0，临时HTTPS Worker和10份真实本地D1迁移：UI授权开户→自动登录→创建登录项→刷新锁定/主密码解锁→退出重登；两次读取均逐值确认用户名和随机密码一致，没有用API注入代替UI操作 |

浏览器验收后的临时库为1个用户、1个Cipher、10条迁移记录，单用户索引存在，Cipher持久化内容不含测试用户名/密码明文。另以仅配置 `dev.local_protocol=https`、没有CLI协议覆盖的方式重启临时服务，HTTPS alive返回200。浏览器和Wrangler已停止，临时库、凭据、浏览器副本及1.8GiB编译target缓存已清理；脱敏摘要和HTTP状态保存在上述临时验证目录。

唯一WASM为5967799字节，SHA256 `cdcad6b51f79b19a697bb900e96f04caf247158a4980c9ccb2ffa464c0824503`；发布bundle为5894.79KiB / gzip1707.23KiB。构建前记录159个源码、配置和脚本输入；最终仅本地HTTPS配置有已说明的变化，Rust、生产配置、静态源和产物均未变化。运行回归修正了一个旧展示测试：普通注册始终关闭，只有真实空库授权Cookie才能开启初始化展示，onboarding设置仍独立。

工具准备和日志移至独立临时目录后完成验证，避免生成目录清理影响证据。日志位于 `/tmp/raywarden-zero-deploy-verification/`，源码备份位于工作区外 `.raywarden-backups/20261118T052047Z-zero-deploy/`；它们不进入仓库或交付artifact。本轮没有读取实际环境文件、操作用户数据库、创建远程资源、上传线上Secret或执行生产部署。

固定前端退出时曾短暂记录 `Null or undefined account` / organizations UserId 控制台错误，约一秒后正常返回登录页，重登与原密码项解密均通过。保留为非阻断前端兼容问题，不修改第三方预编译bundle来掩盖错误。

D05（逐账户verifier成本记录与升级）、D09（未知邮箱KDF隐私策略）、V2与固定旧版Web Vault的版本限制仍明确保留；邮件/推送、真实云资源、扩展及完整备份恢复需要独立验收。
