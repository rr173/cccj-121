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
  cli.py         命令行入口（在线收件与查询）
  salvage.py     离线接收库提取器（直接解释 SQLite 文件页，不经过 SQL 引擎）
migrations/0001_init.sql
partner_webhook/migrations/   同一迁移的包内副本（打包安装时随包分发，需与上者保持同步）
config.example.json
tests/           70 个自动化测试
scripts/salvage_acceptance.py   提取器验收材料（真实建库/破坏/独立核对，可复跑）
demo.sh          在线收件端到端演示（本地环回，不连外网）
demo_salvage.sh  提取器验收演示（真实破坏与退出码矩阵）
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
| `drain-outbox` | 按源序号顺序投递 outbox（下游占位实现） |
| `stats` | 接收/投递汇总统计 |

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

一键演示：`bash demo.sh`（在线收件）；`bash demo_salvage.sh`（离线抢救验收）
