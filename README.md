# 离线合作方事件 Webhook 接入服务

一个完全离线、仅依赖 **Python 3.11+ 标准库** 的合作方事件接入服务。合作方按各自
密钥对请求做 HMAC-SHA256 签名；服务先按协议**规范化被签名内容**，再依次验证
**密钥版本 → 时间窗 → 签名**，通过后才把事件交给下游。所有接收结果、拒绝原因和
可重放的原始体都持久化在 SQLite 中，提供按合作方与时间段查询的命令行接口。

## 设计要点

### 1. 协议规范化（`partner_webhook/canonical.py`）

协议版本 `webhook-v1`，被签名内容为以下 9 个字段，以 `\n` 拼接、UTF-8 编码，
字段顺序固定，与 HTTP 头的传输顺序/大小写无关：

```
webhook-v1
<HTTP 方法，大写>
<请求路径，不含 query>
<合作方 ID>
<密钥版本>
<Unix 秒级时间戳>
<事件 ID>
<合作方源序号>
sha256=<原始字节体的 SHA-256 十六进制摘要>
```

签名覆盖**原始字节体**的哈希：载荷哪怕只差一个空格（JSON 语义相同但字节不同），
规范化串也不同，签名立即失效。签名比较使用 `hmac.compare_digest` 恒定时间比较。

### 2. 密钥版本与生效时间（`config.py`）

每个合作方可同时配置多个密钥版本，每个密钥带 `not_before` / `not_after`
（边界包含，`null` 表示不限）。切换密钥时让新旧两个窗口**重叠**：

- 密钥在请求**声称时间**必须已生效——覆盖切换瞬间发出、稍晚到达的在途请求；
- 密钥在**当前验证时刻**必须未退役——密钥一过 `not_after`，旧签名一律拒绝，
  已过期签名无法重新进入。

### 3. 验证流水线（`service.py`）

任一步失败即持久化一条 `rejected` 流水并返回，绝不进入下游：

1. 必填头与协议版本；
2. 合作方与密钥版本（含双重生效窗口检查）；
3. 服务端时间窗 `|now - claimed_ts| <= max_skew_seconds`（边界包含）；
4. 规范化 + HMAC-SHA256 签名；
5. 事件 ID 去重 / 同 ID 异载荷冲突隔离；
6. 接受事件并在**同一事务**写入下游 outbox。

### 4. 幂等、冲突隔离与乱序（`storage.py`）

- **重复投递**（同 `partner_id + event_id` 且载荷哈希相同）：返回 200
  `duplicate`，事件与 outbox 不重复写入；每次投递都留流水。
- **冲突**（同 ID 但载荷哈希不同）：返回 409 `conflict`，原事件不被覆盖、
  冲突载荷隔离留痕，不进下游。
- **乱序**：事件各自带不同 ID 与合作方源序号 `source_seq`，按序号排序存储与
  下发，不会被误判为重复。

### 5. SQLite 持久化与迁移（`migrations/0001_init.sql`）

| 表 | 作用 |
| --- | --- |
| `raw_bodies` | 按 SHA-256 去重保存原始字节体，支持重放 |
| `ingest_records` | 每次投递（含全部拒绝/重复/冲突）的追加流水 |
| `accepted_events` | 已接受事件，`(partner_id, event_id)` 主键去重 |
| `outbox` | 下游投递队列，与接收同事务，崩溃后可重投 |

迁移按文件名顺序执行、幂等可重复执行，通过 `PRAGMA user_version` 记录版本。
0003 只新增可验证追加账本的三张表（`event_logs` / `log_leaves` / `log_nodes`），
不改写上表任何列或行。

#### 5.1 下游 HTTP 发送工人（`outbound.py`，`migrations/0002_delivery.sql`）

`outbox` 原先的 `drain-outbox` 只把本地状态改成 `delivered`，并不会把事件
送出去。新的发送工人是**独立进程**，真正向合作方登记的 HTTP 接收地址投递
`raw_bodies` 的原始字节；它**不重新验证入站签名**，不读取正文索引/档案加工
库，也不转发入站签名或密钥。

**交付约定**

| 项 | 约定 |
| --- | --- |
| 地址 | 每个合作方登记一个固定 URL；登记后**不可原地更换**（表触发器 + 应用层双重拒绝） |
| 方法/正文 | `POST`，正文就是 `raw_bodies.body_blob` 原始字节（含空体、非 UTF-8） |
| 请求头 | `X-Partner-Id`、`X-Event-Id`、`X-Source-Seq`、`X-Body-Sha256`、`X-Delivery-Key` |
| 头值 | 单值可打印 ASCII；含换行/控制字符/非 ASCII 直接拒绝发送（不静默改写） |
| `delivery_key` | `sha256(长度前缀的 partner/event/摘要)` → `dk1_…`；重试、重开、换进程都相同；跨合作方同号事件不同 |
| 发送前校验 | 重算长度与 SHA-256；正文缺失或与登记不符 → **本地坏数据故障，绝不出网** |

**回执确认**：仅当 HTTP 状态 2xx **且** UTF-8 JSON 对象回执的
`delivery_key` 与 `body_sha256` 都恰好等于本次请求值时才算送达（额外字段
忽略；重复键、空响应、非 JSON、超 64KiB 均判无效回执）。3xx 不跟随跳转，
按永久失败；其他 4xx 永久失败（429 除外）；网络断开/超时/5xx/429/无效回执
可重试。

**退避**：第 n 次失败后等待 `min(60, 2**(n-1))` 秒（n 从 1 计）；429 带
**仅十进制数字**的 `Retry-After` 时取较大值，否则用默认值。

**排队与占用**

- 按合作方分别排队，队首 = 该合作方最小 `outbox.id` 且未送达的事件；队首
  退避/被占用/永久失败时后续事件**不得超车**，其他合作方不受影响。
- 永久失败必须操作者明确 `outbox-retry` 后才能再发；此前尝试全部保留，人工
  重试重置该轮退避计数。
- 领取用 `BEGIN IMMEDIATE` 短事务落库，写入一次性 `lease_token` 与到期时间；
  **网络请求期间不持有数据库写锁**。占用过期后其他工人可接手，旧工人的迟到
  回执只写 `late_*` 字段，绝不覆盖新结果、不放开队列、不重复完成。
- 只承诺**至少一次**发送：过期请求无法撤回，接收方可能收到重复，用稳定的
  `delivery_key` 支持远端去重。
- 一轮运行有显式 `--max-attempts` 与单请求 `--timeout`；将来才到期的队首
  不等待、不忙循环，直接报告 `deferred_head`（`blocked_by`/`wait_seconds`）。
- `--now` 可注入当前时刻（退避/占用到期测试），正常运行默认真实时间。

**新增表**：`delivery_endpoints`（固定地址）、`outbox_delivery`（队首状态与
占用）、`delivery_attempts`（逐次尝试，含状态码/原因/时间/迟到回执）、
`delivery_operator_actions`（人工动作审计）。既有收件表与历史
`outbox.status='delivered'` 记录不受影响（后者没有状态行，不会被重发）。

旧 `drain-outbox` 已**停用**：退出码 2 并提示改用 `outbox-endpoint` /
`outbox-run` / `outbox-queue` / `outbox-attempts` / `outbox-retry`。

### 6. 离线接收库提取器（`partner_webhook/salvage.py`，损坏镜像抢救）

备份介质出现坏页时，SQLite 查询读到损坏位置会整次失败，其他页上完好的
数据也取不出来。提取器**直接解释 SQLite 文件页**（表 B-tree 内部/叶子页、
cell 指针、含 9 字节形式的 varint、record 头与 serial type、跨溢出页载荷
拼接，本地载荷长度按 SQLite 实际规则计算），**不经过 SQL 引擎、不调用
sqlite3 或任何现成恢复工具**，从主库镜像中抢救 `accepted_events` 与
`raw_bodies` 里仍能确认的事件及原始请求体，供人工核对后重新导入。

```bash
python3 -I partner_webhook/salvage.py --db 镜像.db --out 新输出目录 \
    [--max-payload-bytes N] [--max-pages N] [--max-diagnostics N]
```

- **只读源文件**：绝不修改、修复或清空源库；旁边存在非空 `-wal` /
  `-journal` 文件时直接拒绝（尚有未归并状态）；已有输出目录拒绝覆盖。
- **目录先行**：从第 1 页 `sqlite_schema` 表树定位两张目标表的根页并核实
  列布局；目录不能完整读取、布局不符、主库头无效等整体拒绝（退出码 1），
  不靠扫描全文件猜测字节。索引、outbox、ingest_records 与 freelist 不参与。
- **坏页隔离**：内部页头可信时分别读取子树，坏子树登记路径后继续；叶页
  cell 指针列表完整时单个 cell 损坏只隔离该条记录；指针循环、越界、非法
  serial type、载荷不自洽、溢出链缺失/成环、同一页被重复占用均有检查，
  不会死循环或读取任意偏移。被歧义占用影响的记录一律不算已确认。
- **资源上限**：单条载荷、访问页数、诊断条数均可配置；达到上限留下未完成
  原因，不会截掉后仍宣布全库提取成功。
- **输出**：`events.jsonl`（业务列 + 源 rowid + 根页/叶页/cell 位置 + 两表
  关联状态）、`bodies.jsonl`（正文摘要核验结果 + 源文件片段偏移/长度，
  另一段程序可直接从镜像拼回正文）、`bodies/`（已验证正文按摘要命名，
  未验证的隔离在 `bodies/quarantine/`，不覆盖同名文件）、
  `diagnostics.jsonl`、`summary.json`（计数、未完成原因、证据边界）。
- **退出码**：0 完整提取；2 部分结果（存在损坏/歧义/失配/资源上限）；
  1 整体拒绝（格式不受支持、目录不能解释、旁文件未归并等）。
- **证据边界**：输出只代表本次从镜像中按结构解码得到的内容；正文的
  SHA-256 校验仅证明提取字节与登记摘要一致，不证明投递签名或原接收决策。
  没有事件引用的正文（可能来自拒收/冲突）照样保留并标注未关联，不判为损坏。

正常收件与查询仍沿用 `cli.py` 的已有入口，提取器是完全离线的独立命令。
验收演示（真实建库 → 破坏 → 提取 → 独立核对）：`bash demo_salvage.sh`。

### 7. 本地 JSON 正文索引与结构查询（`indexstore.py` / `query.py`）

合作方会把一组测量放在同一个事件正文里。若把 `metric` 与 `value` 各自摊平
再搜，会出现「同一事件里温度 20、湿度 80 也命中温度>30」的误报。本索引为
本地分析单独建库，**按数组元素保留归属**，让组合条件能查对。

```bash
# 首次建立 / 之后每次同步（源库只读，索引库独立）
python3 -I partner_webhook/cli.py --db webhook.db \
    index-sync --index-db analysis-index.db
python3 -I partner_webhook/cli.py --db webhook.db \
    index-status --index-db analysis-index.db

# 查询必须指定合作方；表达式用 JSON 给出
python3 -I partner_webhook/cli.py --db webhook.db \
    index-query --index-db analysis-index.db --partner acme \
    --expr '{"any":{"path":["measurements"],"where":{"and":[
               {"eq":{"path":["metric"],"value":"temperature"}},
               {"gt":{"path":["value"],"value":30}}]}}}'
```

#### 正文解释

数据来自正常接收库的 `accepted_events` 与其关联的 `raw_bodies`，经 SQLite
**只读连接**读取。正文先核对登记摘要与长度，再做严格 UTF-8 JSON 解释：

- 根必须是对象；同一对象内重复键直接拒绝（不采用后值覆盖）；
- 不接受 NaN / Infinity / -Infinity、BOM、截断文本、尾随内容；
- 数字保留原文十进制（不经 float / REAL），`1`、`1.0`、`1e400`、相邻超大
  整数都能精确保留。

不是这种 JSON 的正文**仍是合法收件**：索引逐条登记 `reason_code` 与原因，
把该事件标为 `skipped`，其他事件继续索引。非文本字节、错误字段不会被强行
转字符串混进搜索结果。

#### 表达式语法（有限集合）

| 操作 | 形状 |
| --- | --- |
| `and` / `or` | `{"and":[expr, ...]}` / `{"or":[...]}`，列表必须非空 |
| `not` | `{"not": expr}`，按当前作用域真假取反 |
| `any` | `{"any":{"path":[...], "where":expr}}` |
| `exists` | `{"exists":{"path":[...]}}` |
| `eq`/`lt`/`lte`/`gt`/`gte` | `{"eq":{"path":[...], "value":标量}}`，有序比较只接受数字 value |

规则：

- 每个表达式对象**只允许一个操作**；未知键、多余参数、空逻辑列表、非标量
  比较值都会明确报错（CLI 退出码 2，错误只写 stderr，stdout 为空，不会留下
  半份结果），不会退化成普通文本检索。
- `path` 是字符串段数组，每段就是对象真实键名；点、斜杠、空格、空键名都
  没有特殊含义，空 `path` 表示当前值本身（在 `any` 里即「当前元素/数组」）。
  **只有 `any` 可以跨过数组**，字符串段永远不会被当作数组下标；根必须是
  对象，因此根级路径只能按键名进入。
- `any` 把数组每个元素作为当前对象，只有同一个元素满足整个 `where` 才算
  命中；嵌套 `any` 的内层路径从内层元素出发。两个并列 `any` 各自找元素，
  允许命中不同元素——不会擅自加同元素限制。
- 缺失 ≠ 显式 `null`：`exists` 对显式 `null` 仍为真，`eq null` 只命中真正
  写了 `null` 的位置。`eq` 按 JSON 类型比较（`false` ≠ `0`，`1` = `1.0`，
  `"1"` ≠ `1`）；有序比较只适用于数字，类型不符或路径缺失为假。
- `any` 目标缺失 / 非数组 / 空数组均为假。
- 顶层 `not` 只在指定合作方的**可查询事件集合**（`status='indexed'`）内取反，
  未通过正文检查的事件不会因此变成命中。
- 输出 `total`（完整匹配数）与 `events`（当前页事件身份），按 `event_id`
  稳定排序；分页在 SQL 中先算完整条件再截页，不会先截候选再生效 `any`/`not`。
  总数与分页行来自同一只读事务、同一代索引。合作方筛选必填。


### 8. 设备档案加工管线（`docarchive.py` / `jsonpatch.py`，乱序 JSON Patch 还原）

合作方有时只发送档案改动的几个位置而不重发整份档案。本管线在**独立的
SQLite 加工库**里把乱序到达的 `seed` / `patch` 事件还原成设备当前档案，
不使用正文搜索索引保存加工状态，也不改变签名收件与坏库提取的行为。

#### 来件约定（同一合作方内 `document_id` 标识一份档案，合作方间可重号）

正文为 UTF-8 JSON 对象，只用严格解析器解释（重复键/NaN/截断一律拒绝）：

- `kind=seed`：含 `document_id`、`revision=0`、`document`（任意 JSON 值）；
- `kind=patch`：含 `document_id`、`base_revision`、`revision`、`operations`；
  修订号为**规范非负整数字面量且不是布尔值**（拒绝 `01`、`1.0`、`true`），
  且 `revision == base_revision + 1`，`operations` 是 JSON Patch 操作数组；
- 其他 `kind` 或非对象正文登记为**非档案来件**；约定字段缺失、多余、重复
  键、类型错误都**指明所在事件**，原因落库，不做任何强制转型。

加工库保留源合作方、事件 ID、正文 SHA-256/长度与正文摘要（预览），源
`accepted_events` 只读；加工状态不借用也不标记原 outbox。

#### RFC 6902 / 6901 语义（`jsonpatch.py`）

- 支持 `add`/`remove`/`replace`/`move`/`copy`/`test` 六种操作，顺序有意义；
- JSON Pointer：空串指根，`~1`→`/`、`~0`→`~`，未知转义拒绝；对象空键、
  数字键、带斜杠键都按原名访问；数组只接受规范非负十进制下标（拒绝
  `01`/负数/越界），`-` 仅供 `add` 到末尾，不能作读取位置；
- `add` 父节点必须已存在（可替换对象成员、插入数组元素）；`replace`/
  `remove` 必须找到目标；`copy` 复制独立树，改副本不影响原值；`move` 先
  取出再删除、按删除后的档案定位插入点，不能移进自己的后代；
- `test` 按结构与值比较：对象成员顺序无关、数组顺序有关、布尔≠数字、
  `1`==`1.0`，有限十进制数字保留原文不经过 float；
- `remove` 根产生“本修订没有档案”（`absent`）状态，后续只有根 `add` 能
  重新建档——这与档案内容为 JSON `null`（仍是 `present`）不同；
- **原子性**：每次 patch 先深拷贝工作副本再逐条应用，任一操作失败即整体
  丢弃、指出第几个操作及失败位置，调用方原档案不留下半改对象；失败事件
  仍保留查账，并阻断其后续修订（不能跳过接下一版）。

#### 乱序、分支与人工选择（`docarchive.py`）

- seed 与 patch 可乱序到达；缺 seed 或缺前一版的修改先标记**等待前版**，
  补齐后沿修订链接执行；
- 两个不同源事件声明同一档案同一修订（哪怕操作一样）即**分支**，不按到达
  时间或 event_id 自动选。无人工选择时只公布从唯一 seed 出发、每一跳均无
  分支且执行成功的**最长前缀**：已到第 2 版后又收到另一条 0→1，公布退回
  第 0 版，原第 2 版仍在账上但被含糊的第 1 版阻断；两个 seed 同样视为
  分支，未选择前不公布内容；
- 提供持久化的本地选择/撤销：按合作方、档案、修订号指定采用的源事件 ID
  （seed 也可选）。选择必须存在且属于该坐标，错误选择不改任何状态；选择
  后立即重算，已明确选择的修订后来再出现竞争分支仍尊重原选择，同时保留
  新分支“未被选中”的诊断；撤销后恢复无偏好分支判定。不生成伪造来件、不
  删除竞争事件；所有操作只影响本合作方的对应档案。

每条来件的处置可解释为：已采用 / 等待前版 / 分支未选 / 未被选中 /
操作失败 / 被前方阻断 / 非档案来件 / 约定不符，并能沿当前内容查回采用过
的事件链。

#### 持久化与命令

```bash
# 从接收库（只读）导入新来件并重算（加工库独立，重复同步是无操作）
python3 -I partner_webhook/cli.py --db webhook.db \
  archive-sync --archive-db archive.db
# 查看当前公布档案（含 state：present/absent/none 与采用事件链）
python3 -I partner_webhook/cli.py --db webhook.db \
  archive-document --archive-db archive.db --partner acme --document-id dev-9
# 查看来件处置与原因（可按合作方/档案过滤）
python3 -I partner_webhook/cli.py --db webhook.db \
  archive-dispositions --archive-db archive.db [--partner acme] [--document-id dev-9]
# 查看一份档案的修订候选、分支与人工选择
python3 -I partner_webhook/cli.py --db webhook.db \
  archive-revisions --archive-db archive.db --partner acme --document-id dev-9
# 人工选择 / 撤销（错误选择退出码 2 且不改状态）
python3 -I partner_webhook/cli.py --db webhook.db \
  archive-select   --archive-db archive.db --partner acme --document-id dev-9 \
                   --revision 1 --event-id p1
python3 -I partner_webhook/cli.py --db webhook.db \
  archive-deselect --archive-db archive.db --partner acme --document-id dev-9 --revision 1
```

- 每次同步在源库一个只读读事务里取来件快照；加工侧的导入登记、当前档案
  与处置结论在**同一个写事务**共同提交，当前内容的读取看不到“版本已升而
  内容还没改”的中间状态；进程在写入新档案后、提交前真正退出，重开仍是旧
  结果，重新同步即可继续（`--simulate-crash-before-commit` 可演练）；
- 不要求保留每份完整历史档案，不自动修复或回发源数据。
- 验收演示（真实签名收件 → CLI 加工/读回，115 项断言，含手写小例子）：
  `python3 -I scripts/archive_acceptance.py`；一键演示：`bash demo_archive.sh`。


#### 索引生命周期

- 索引库与接收库分离；同步只以 `mode=ro` + `query_only` 打开源库，**同步
  失败不会写坏在线接收库**。
- 源库在一个只读读事务里取事件集快照；索引侧全部写入在**同一个写事务**：
  解析/复用正文节点 → 登记事件 → 发布。提交前退出，上一代索引仍完整可查；
  重开后执行一次 `index-sync` 即得到新一代。不会出现「事件登记已更新但查询
  仍命中旧字段」的中间状态。
- 同步语义：新增事件进入索引；同一事件换正文则整份替换（新代重新登记，旧
  正文节点在发布时清理）；源表已不存在的事件从索引移除；未变化的正文按
  `(摘要, 解析器版本, 长度)` 复用，不重复解析。同摘要被多事件引用时节点
  按摘要共享、只读不改写。重复同步不增加重复节点或事件。
- **查询不读源库**：同步后可暂时无法访问源库仍能执行（验收演示会实际改名
  源库后查询）。

### 9. 可验证追加账本（`merkle.py` / `eventlog.py` / `verifylog.py`）

合作方交来事件后，服务端在接收事务里把事件追加进**按合作方独立**的哈希账本。
合作方保存当时的检查点，事后用离线核验入口就能核对：事件确实记在账里，且之后
的账本只增加了事件、没有删除或替换旧前缀。这项能力记录**接收端的承诺**——不证明
下游已经收到数据，也不证明正文的业务真实性。

#### 哈希协议（两端的唯一编码）

H 为 SHA-256；一片叶子的原文依次拼接：

```
ASCII "PWLOG1"
|| u32be(len(partner_id UTF-8)) || partner_id UTF-8
|| u32be(len(event_id UTF-8))   || event_id UTF-8
|| u64be(source_seq)
|| 32 字节正文 SHA-256 原文
```

- 叶哈希 `H(0x00 || 叶原文)`，内部节点 `H(0x01 || 左 || 右)`，空树根 `H(空字节)`；
- 身份**不做 Unicode 规范化**，也不允许用分隔符拼接替代长度前缀；
- 长度超出 4 字节、序号超出 8 字节的整数明确拒绝（布尔值不算整数）。

非空树只有一叶时根就是叶哈希；其余情况取「严格小于叶数的最大 2 次幂 k」切成
左右两树后递归组合。**不补虚拟叶**，也不把最后一片复制配对。本实现对该规则适用
于任意树长（3、5、9 叶等非满二叉树都按同一递归处理）。

#### 安装与追加

```bash
# 在已有接收库上为合作方安装账本（纳入已有 accepted_events）
python3 -I partner_webhook/cli.py log-install --partner acme
# 之后照常收件；首次接受的事件在同一事务里追加叶子
```

- 安装按 `accepted_events.ingest_record_id` **递增**纳入历史，与可能稀疏/倒序的
  `source_seq` 无关；叶子序号从 0 连续增长。
- 每个合作方首次安装时随机生成独立 `log_id`；重复安装只复核，**不换号、不重排、
  不追加**。已安装账本与 `accepted_events` 不一致时明确拒绝。
- 安装逐条核对正文确实存在、长度与摘要吻合；任何一条不符都整次拒绝，不留半份
  账本。新来件沿用实际接收路径取得的原字节摘要。
- 安装持有数据库写锁；期间到达的收件等待锁释放后再判定，不会漏掉交界处的事件，
  也不会被算错位置。
- 追加只发生在**首次接受**：重复投递、同号异载荷冲突、拒收都不追加。
- 只新增 `event_logs` / `log_leaves` / `log_nodes` 三张表；`raw_bodies`、
  `ingest_records`、`accepted_events`、`outbox` 的业务含义与行都不变。

#### 并发与回滚

接收事务先 `BEGIN IMMEDIATE` 取得 SQLite 跨进程写锁，再判断去重/冲突并在同一事务
内追加叶子。因此两个独立进程同时收件时，已接受记录与叶子一一对应，叶序号连续，
不依赖 Python 线程锁。接收过程中任何异常都回滚整个事务：不会留下幽灵叶子，也不
会出现 `accepted_events` 已提交而账本没记。

#### 检查点、在账证明与一致性证明

```bash
# 当前检查点（单行一致读取；已发出的旧检查点不因新收件改变）
python3 -I partner_webhook/cli.py log-checkpoint --partner acme --out cp-09.json
# 指定旧 tree_size 重建旧前缀（只读持久节点，不重扫事件/正文）
python3 -I partner_webhook/cli.py log-checkpoint --partner acme --tree-size 5 --out cp-05.json
# 为旧前缀下的一条事件生成在账证明
python3 -I partner_webhook/cli.py log-prove-inclusion --partner acme \
  --event-id evt-5 --tree-size 5 --out proof.json
# 为旧/新检查点生成前后追加关系证明
python3 -I partner_webhook/cli.py log-prove-consistency --partner acme \
  --old-checkpoint cp-05.json --new-checkpoint cp-09.json --out cons.json
```

检查点文件包含 `log_id`、`partner_id`、`tree_size`、`root_hash`（以及 `format`、
`version`、`protocol`）。

- **在账证明**返回叶原文对应字段（事件 ID、source_seq、正文摘要）、`leaf_index`
  和从叶到根的兄弟路径。对应递归规则：索引在左树时递归左树再附右树根；在右树时
  递归右树再附左树根。不存在的事件、尚未进入指定前缀的事件、越界树长都报错。
  证明不携带其他事件的身份或正文，也不接受「另附整份清单」来核验。
- **一致性证明**使用最小子树递归 `C(m, D, b)`：`m` 等于段长时 `b=true` 返回空路径、
  `b=false` 返回本段根；否则按该段 k 切分，`m<=k` 时先递归左段再附右段根，
  `m>k` 时先递归右段（`b=false`）再附左段根。实现通过节点范围按需读取，不取出
  整个 D。`0->n` 与相同树长的证明都为空（相同树长还要求两根相等）。两端检查点
  的合作方、`log_id`、协议必须相同，大小不能倒退；生成时拒绝根与本地相应前缀
  不符的检查点。

#### 持久节点与读取代价

`log_nodes` 保存**已经形成**的完整子树节点（`level` 为子树高度，`node_index` 为
起始叶 / 2^level）。正常追加只合并受新叶影响的 O(log n) 个节点，旧节点从不改写；
旧树根、在账路径与一致性路径都从这些节点按需组合。生成一条证明不扫描全部事件、
全部叶子或原正文。`--show-reads` 会输出本次操作的节点读取计数，计量范围是
`event_logs` 元数据点查、`log_nodes` / `log_leaves` 的主键点查次数与返回行数
（不含 SQLite 内部页读取与检查点文件本身）。验收脚本实测：20000 叶时读取当前
检查点 0 次节点、旧前缀一半 5 次、在账证明 15 次、一致性证明 24 次，全部走
主键索引（执行计划为 `SEARCH ... USING INDEX`，没有 `SCAN log_nodes`）。

#### 离线核验入口（不访问数据库）

```bash
# 调用方明确传入自己保存且信任的检查点 + 待验叶子
python3 -I partner_webhook/verifylog.py inclusion \
  --checkpoint cp-05.json --proof proof.json \
  --event-id evt-5 --source-seq 7 --body-sha256 <64 hex>
# 调用方传入两份可信检查点 + 一致性证明
python3 -I partner_webhook/verifylog.py consistency \
  --old-checkpoint cp-05.json --new-checkpoint cp-09.json --proof cons.json
```

`verifylog.py` 只 import 标准库与 `merkle.py`，不 import `sqlite3`、不读账本节点
文件。它只用调用方的可信根与证明里的叶字段/路径重建根，**绝不把证明自带的根当作
可信根**。错叶、错位置、修改/缺少/多余路径节点、非法十六进制、布尔值冒充整数、
跨合作方、跨 `log_id`、树长倒退都返回失败与非零退出码。空树检查点不能为叶子出
证明；一叶树的在账路径为空、一致性 `0->1` 路径为空，均有实际可用行为。

#### 信任边界

没有签名服务，也没有全网见证。哈希证明依赖**调用方自己保管的可信检查点**：如果
调用方从未保存过检查点，或保存的检查点本身被替换，这些证明无法救回。本服务也
不能独自阻止它向两名从未交换过检查点的客户展示两套不同历史（split-view），更
不证明正文的业务真实性。要防止 split-view，需要客户之间或第三方见证交换检查点。


## 目录结构

```
partner_webhook/
  canonical.py   协议规范化
  crypto.py      HMAC-SHA256 签名与恒定时间校验
  config.py      合作方/多版本密钥配置与生效窗口
  storage.py     SQLite 持久层与迁移
  service.py     验证流水线（与传输层解耦，可注入时钟）
  generator.py   本地请求生成器（签名 + 环回发送）
  server.py      http.server 环回收件服务
  cli.py         命令行入口（在线收件、查询与索引命令）
  salvage.py     离线接收库提取器（直接解释 SQLite 文件页，不经过 SQL 引擎）
  strictjson.py  严格 UTF-8 JSON 解析（拒绝重复键/NaN/截断，数字精确保留）
  jsonpatch.py   RFC 6901 JSON Pointer 与 RFC 6902 JSON Patch 解释器（原子、精确数字）
  docarchive.py  设备档案加工管线（独立 SQLite 加工库、乱序/分支/人工选择）
  indexstore.py  持久正文索引（路径 + 类型 + 数组实例，代际发布）
  query.py       有限 JSON 表达式校验、SQL 编译与分页查询
  direct_eval.py 小样本独立核对器（直接解释 JSON 树，不走索引 SQL）
  outbound.py    下游 HTTP 发送工人（按合作方队首、持久占用、逐次尝试）
  receiver.py    可控下游接收器（本机环回，保存字节/头部/落地键）
  merkle.py      可验证追加账本的哈希协议与证明核验（纯函数，不依赖 SQLite）
  eventlog.py    按合作方独立的追加账本（节点持久化、检查点、证明生成）
  verifylog.py   离线核验入口（不 import sqlite3、不读账本节点文件）
migrations/0001_init.sql
migrations/0002_delivery.sql  下游投递：接收地址、投递状态/占用、逐次尝试、人工动作
migrations/0003_event_log.sql 按合作方独立的可验证追加账本（叶位置与子树节点）
partner_webhook/migrations/   同一迁移的包内副本（打包安装时随包分发，需与上者保持同步）
config.example.json
tests/           自动化测试
scripts/salvage_acceptance.py   提取器验收材料（真实建库/破坏/独立核对，可复跑）
scripts/index_acceptance.py     正文索引验收材料（真实收件/同步/查询/独立核对）
scripts/archive_acceptance.py   档案加工验收材料（真实收件/乱序/分支/选择/崩溃恢复）
scripts/archive_examples.py     档案加工手写小例子（期望不来自正式加工函数）
scripts/outbound_acceptance.py  下游发送验收（受控接收器、退避、断开、并发接手、迁移前记录）
scripts/prooflog_acceptance.py  账本验收（检查点、在账/一致性证明、离线核验、并发、回滚、大样本）
scripts/prooflog_reference.py   账本哈希协议的手写递归参考实现（不 import 正式节点/证明函数）
demo.sh          在线收件端到端演示（本地环回，不连外网）
demo_salvage.sh  提取器验收演示（真实破坏与退出码矩阵）
demo_index.sh    正文索引验收演示（反例、跨元素、同步增删改、崩溃恢复）
demo_archive.sh  档案加工验收演示（乱序等待、分支退回、人工选择、跨方拒绝）
demo_outbound.sh 下游发送演示（登记地址、429 退避、永久失败与人工重试、逐字节核对）
demo_prooflog.sh 账本演示（安装、检查点、在账/一致性证明、离线核验、源库移走）
```

## 快速开始

```bash
# 1. 建库并执行迁移
python3 -I partner_webhook/cli.py init-db

# 2. 启动收件服务（默认 127.0.0.1:8080/webhook/events）
python3 -I partner_webhook/cli.py serve --port 8080

# 3. 另开终端，用本地生成器签名并投递
python3 -I partner_webhook/cli.py send \
  --partner acme --key-version v1 \
  --event-id evt-1 --sequence 1 --body '{"order":1}'
```

也可作为模块运行：`python3 -m partner_webhook.cli ...`，或安装后使用
`partner-webhook` 控制台脚本（`pip install -e .`）。

## 命令一览

| 命令 | 说明 |
| --- | --- |
| `init-db` | 建库并执行迁移（幂等） |
| `serve` | 启动本地环回 HTTP 收件服务 |
| `send` | 生成签名请求并投递（`--badge` 破坏签名、`--ts-offset` 测时间窗） |
| `query` | 按 `--partner/--start/--end/--result` 查询接收流水 |
| `events` | 查询已接受事件（按源序号排序） |
| `record <id>` | 查看单条接收记录（含完整请求头） |
| `body <id>` | 导出记录保存的可重放原始字节体 |
| `replay-event <id>` | 用保存的原始体重投（`--key-version` 换密钥、`--refresh-timestamp` 刷新时间戳、`--now` 模拟时钟） |
| `outbox-endpoint --partner P --register URL` | 登记合作方固定接收地址（不可原地更换） |
| `outbox-endpoint --partner P --list` | 查看已登记地址 |
| `outbox-run [--partner P]` | 真实 HTTP 发送一轮（`--max-attempts`、`--timeout`、`--lease-seconds`、`--now`） |
| `outbox-queue --partner P` | 查看该合作方队列与队首状态 |
| `outbox-attempts --partner P --event-id E` | 查看某事件逐次尝试、人工重试与迟到回执 |
| `outbox-retry --partner P --event-id E` | 人工重试永久失败事件（重置该轮退避计数） |
| `drain-outbox` | **已停用**（退出码 2；不会在未确认时虚报成功，请用 `outbox-run`） |
| `stats` | 接收/投递汇总统计 |
| `index-sync` | 从接收库（只读）同步本地 JSON 正文索引，发布新一代 |
| `index-status` | 查看当前索引代、事件状态与跳过原因 |
| `index-query` | 用 JSON 表达式查询索引，必填 `--partner` |
| `archive-sync` | 从接收库（只读）导入 seed/patch 并重算档案版本（独立加工库） |
| `archive-document` | 查看一份档案的当前公布内容、状态与采用事件链 |
| `archive-dispositions` | 查看每条来件的处置（等待/分支/失败/阻断等）与原因 |
| `archive-revisions` | 查看一份档案的修订候选、分支与人工选择 |
| `archive-select` / `archive-deselect` | 按坐标人工选择/撤销采用的源事件 |
| `log-install --partner P` | 安装/复核合作方可验证追加账本（纳入已有事件） |
| `log-status [--partner P]` | 查看账本树长、根、叶数与已接受事件数 |
| `log-checkpoint --partner P [--tree-size N] --out F` | 读取当前或指定旧树长的检查点 |
| `log-prove-inclusion --partner P --event-id E [--tree-size N] --out F` | 生成在账证明（`--show-reads` 输出节点读取计数） |
| `log-prove-consistency --partner P --old-checkpoint A --new-checkpoint B --out F` | 生成前后追加关系证明 |

离线核验（不访问数据库，退出码 0 成立 / 1 核验失败 / 2 输入非法）：

| 命令 | 说明 |
| --- | --- |
| `python3 -I partner_webhook/verifylog.py inclusion --checkpoint A --proof P --event-id E --source-seq N --body-sha256 HEX` | 用调用方可信检查点核验一条事件的在账证明 |
| `python3 -I partner_webhook/verifylog.py consistency --old-checkpoint A --new-checkpoint B --proof P` | 用两份可信检查点核验前后追加关系 |
| `python3 -I partner_webhook/verifylog.py checkpoint --checkpoint A` | 解析并显示一份检查点 |

离线抢救（独立于上表，不经过在线入口）：

| 命令 | 说明 |
| --- | --- |
| `python3 -I partner_webhook/salvage.py --db 镜像 --out 目录` | 直接解释 SQLite 文件页，从主库镜像抢救事件与原始体；退出码 0/1/2 见上文 |

时间边界参数支持 Unix 秒或 ISO-8601（如 `2026-11-14T00:00:00Z`）。

## 密钥交接操作建议

1. 新密钥 `v2` 配置一个**早于切换时刻**的 `not_before`，旧密钥 `v1` 的
   `not_after` **晚于切换时刻**，形成重叠窗口；
2. 合作方逐步切到 `v2`，重叠期内 `v1` 在途请求仍被接受；
3. 重叠窗口结束后 `v1` 自动失效，任何旧签名重放都被拒绝（`key_expired`）；
4. 需要重放历史原始体时，用 `replay-event <id> --key-version v2
   --refresh-timestamp` 以新密钥和当前时间重新签名。

## 测试

```bash
# -I 隔离模式运行，不读取外部 PYTHONPATH；-t . 保证 tests 包被正确导入
python3 -I -m unittest discover -s tests -t . -v
```

覆盖场景：

- 规范化字节差异（JSON 空白符、路径、方法、时间戳、序号变化均使签名失效）；
- 头顺序/大小写不影响验证；错误签名、非十六进制签名、错误密钥拒绝；
- 新旧密钥交接重叠窗口、`not_before`/`not_after` 边界、过期签名不可重入；
- 时间窗边界（偏差恰好等于上限接受、超出 1 秒拒绝）；
- 重复投递幂等、同 ID 异载荷冲突隔离、乱序源序号保留与排序；
- 全部拒绝分支持久化、原始体摘要可导出重放；
- HTTP 端到端（环回）、CLI 查询/导出/outbox/重放；
- 进程重启后记录一致、去重与冲突规则继续生效、迁移幂等；
- 提取器：三种页长的正常库逐字段核对 SQL 参照、空/含零/非 UTF-8 正文、
  跨多页溢出大正文、大 rowid（9 字节 varint）与大整数列、未关联正文保留；
  叶页/单 cell/溢出链切断/溢出成环/共享页/目录损坏/布局不符/截短文件/
  正文摘要失配/非空 WAL 旁文件/资源上限/输出目录已存在的退出码与隔离粒度；
  提取前后源文件摘要不变、片段可独立拼回正文、提取模块不 import sqlite3。
- 正文索引：严格 JSON（重复键/NaN/Infinity/截断/非 UTF-8/根非对象）、
  数字精确判等与排序；同元素组合条件（温度 20 + 湿度 80 反例）、嵌套与
  并列 `any`、`not`、缺失/null/false/0、空数组、点/斜杠/空键、数字不冒充
  下标；合作方隔离、分页先算条件再截页、非法表达式退出码；同步新增/替换/
  删除、重复同步不重复解析、共享摘要不互相改写、未提交崩溃后旧代完整、
  源库不可用时仍可查询。

正文索引验收材料可复跑：`python3 -I scripts/index_acceptance.py`（100 项
断言，含逐表达式与直接 JSON 解释器的交叉核对）。

- 档案加工：RFC 6901 指针（空键/~ 转义/未知转义/对象数字键 vs 数组规范
  下标/`-` 语义）；六操作、move 删除后定位与禁入后代、copy 独立树、test
  精确比较（超大整数、布尔≠数字、`1`==`1.0`）；原子回滚不改原对象、根
  remove 的 absent 与 null 区分；信封缺失/多余/重复键/类型错误不转型；
  乱序等待、分支退回与最长前缀、人工选择/撤销、两个 seed 冲突、失败阻断
  后续、合作方隔离、重复同步无操作、重开状态保留、未提交崩溃恢复、源库
  只读与 outbox 不被借用。

档案加工验收材料可复跑：`python3 -I scripts/archive_acceptance.py`（115 项
断言，真实签名收件 + 手写小例子独立核对）。

- 下游发送：投递契约纯函数（稳定 `delivery_key`/合作方隔离/头值往返/退避
  公式与 `Retry-After`/回执严格校验/64KiB 上限）；按合作方队首与不超车；
  429 提前运行零请求、到期同键重送；200 但空体/非 JSON/摘要错/重复键/超大
  均不算送达；主动断开后同键重试只产生一份业务记录；永久失败需人工重试并
  保留历史；两进程并发占用不抢、过期接手、旧回执迟到不覆盖；已送达不重发、
  正文失配不出网、旧 `drain-outbox` 停用。

  下游发送验收材料可复跑：`python3 -I scripts/outbound_acceptance.py`
  （131 项断言，含真实环回、受控接收器、两进程并发与迁移前库）。

- 可验证追加账本：固定编码（长度前缀、无 Unicode 规范化、超范围拒绝）；
  任意树长的根/在账路径/一致性路径与手写递归参考实现逐项一致（0..9 全部
  (m,n) 与每个在账位置）；旧库上安装按 ingest_record_id 纳入历史、重复安装
  不换号、正文缺失/长度或摘要不符整次拒绝；重复/冲突/拒收不追加、同号
  不同事件与二进制正文照常追加；两个独立进程交错收件时叶序号连续且与
  accepted_events 一一对应；提交前抛错回滚不留幽灵叶；旧前缀/证明只按主键
  读 O(log n) 个节点；`0->n`、相同树长与一叶树行为；离线核验对错叶、错
  位置、改/缺/多节点、非法十六进制、布尔冒充整数、跨合作方、跨 log_id、
  树长倒退全部给出非零退出码；数据库移走后凭据仍可核验。

  账本验收材料可复跑：`python3 -I scripts/prooflog_acceptance.py --bulk 20000`
  （381 项断言，含真实签名收件、离线子进程核验、手写参考实现与 20000 叶
  节点读取证据）。

  一键演示：`bash demo.sh`（在线收件）；`bash demo_salvage.sh`（离线抢救验收）；
`bash demo_index.sh`（正文索引验收：反例、组合条件、独立核对、同步增删改与
崩溃恢复）；`bash demo_archive.sh`（档案加工验收：乱序、分支、人工选择）；
`bash demo_outbound.sh`（下游发送演示：登记地址、429 退避、人工重试、逐字节核对）；
`bash demo_prooflog.sh`（账本演示：安装、检查点、在账/一致性证明与离线核验）。
