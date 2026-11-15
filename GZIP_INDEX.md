# 可定位 gzip 索引

本目录新增的 `partner_webhook/gzip_index.py` 与 `partner_webhook/deflate_codec.py`
为已接受事件的 gzip 原始正文建立**独立 SQLite 断点索引**。收件库始终以只读 URI
打开，本功能不修改收件、档案、投递、账本或差量工具，也不把源 gzip 改写成自定义
分块压缩格式。

## 命令

```bash
python3 -I partner_webhook/gzip_index.py build \
  --source-db webhook.db --partner-id globex --event-id evt-1 \
  --index seekable.sqlite --spacing 65536 \
  --max-output 536870912 --max-optional-header 65536 --tmp-dir /tmp

python3 -I partner_webhook/gzip_index.py extract \
  --source-db webhook.db --partner-id globex --event-id evt-1 \
  --index seekable.sqlite --start 12345 --length 4096 \
  --output tail.bin

python3 -I partner_webhook/gzip_index.py verify \
  --source-db webhook.db --index seekable.sqlite
```

提取范围是左闭右开 `[start, start+length)`。`length=0` 合法，`start` 可等于解压
总长；负起点、负长度、越过总长和覆盖已有输出文件都会失败。

## 生产解码路径

`deflate_codec.py` 自行实现：

- LSB-first 位读取和跨字节游标；
- 规范 Huffman 码长分配、前缀边界和符号解码；
- stored、fixed Huffman、dynamic Huffman 三类 DEFLATE 块及同成员混用；
- 动态码表的 HLIT/HDIST/HCLEN、16/17/18 码长回退、保留符号拒绝；
- length/distance 额外位、无历史距离拒绝、逐字节重叠回引；
- 32 KiB 环形滑动字典和字典环绕；
- gzip FEXTRA、FNAME、FCOMMENT、FHCRC、多连续成员、CRC32 与模 `2^32` ISIZE。

生产代码只把 `zlib.crc32` 用于 CRC32；不调用 `zlib.decompress`、
`zlib.decompressobj`、`gzip.decompress` 或第三方可定位 gzip 库。标准库压缩/解压
只出现在测试、演示和基准的参考路径中。

## SQLite 索引格式

索引只允许下列四张表：

### `header`

一行，保存 magic、格式版本、固定 64 KiB 页大小、S、解压上限、可选 gzip 头上限、
解压总长、成员数、断点数、所有绑定行的根 SHA-256 以及本行 SHA-256。

### `source_binding`

保存合作方、事件 ID、源 `raw_bodies.body_sha256`、源压缩长度、整份压缩正文的
SHA-256 和本行摘要。合作方 ID 与事件 ID 共同绑定，其他合作方的同号事件不能使用
该索引。

### `page_checksums`

每个固定 64 KiB 压缩页一行：页号、页内偏移、页长、页 SHA-256 和行摘要。页是局部
提取的实际校验边界。

### `checkpoints`

主键为解压偏移，状态是有界 JSON 及其 SHA-256、行摘要。状态字段：

| 字段 | 缺失后的影响 |
| --- | --- |
| `bit_pos` | 无法恢复压缩字节中的位游标，只能从成员开头重跑。 |
| `block_type` | 不知道 stored/fixed/dynamic 状态，无法继续当前块。 |
| `bfinal_seen` | 无法判断当前 DEFLATE 成员是否已遇到 BFINAL。 |
| `stored_bytes_remaining` | stored 块内部断点无法知道剩余字面字节数。 |
| `lit_lengths` / `dist_lengths` | dynamic 块无法重建当前 Huffman 表；不能靠重读块头规避长块恢复。 |
| `window`（最多 32 KiB） | 无法解析引用断点之前历史的 distance，尤其无法处理环绕和重叠拷贝。 |
| `output_offset` | 无法把恢复游标映射到解压位置，也不能判断跳过多少字节。 |
| `crc32_state` | 跨成员继续时无法完成该成员 CRC32。 |
| `member_index`、成员起止和头长度 | 无法定位成员边界、可选头和跨成员后的下一个 gzip 头。 |

索引不保存全部解压载荷，也不依赖仍存活的构建进程。断点只落在完整 literal 或完整
length/distance 指令之后；stored 块可以落在字面字节边界之后，因此能位于很长块内部。
相邻解压位置间距不超过 `S+257`（257 是一条最长回引指令的最大输出增量边界）。

## 证据边界

- `build` 和 `verify` 读取全部 64 KiB 压缩页，校验每页摘要，并计算整份压缩正文
  SHA-256；`verify` 还重算所有断点状态、根摘要、成员 CRC32 和 ISIZE。
- `extract` 先核对事件身份、源长度、源 SHA-256 登记值、索引头和断点摘要，然后只
  读取恢复所需页；每一个实际读取页都按页摘要校验。它不会为了整源摘要而重读全部
  BLOB。若范围跨过完整 gzip 成员，会读取该成员尾部并核对 ISIZE；CRC32 仅当恢复
  点正好位于该成员第一个解压字节时可完整验证，否则局部读取不伪装成已重放全成员历史。
- 未访问压缩页的损坏不会影响一次局部提取；这不是漏检，而是局部读取的证据边界。
  只有 `verify` 能给出全源结论。
- 摘要只能发现意外损坏或不完整重写，不提供外部认证，也不能防御同时重写正文、
  摘要和索引的攻击者。

## 内存与统计

构建常驻内存只随 32 KiB 窗口、Huffman 码表、固定输入页和有限 SQLite 写入批次增长，
不随正文总长或断点总数增长。提取同样不载入全部索引，只用 SQL 查找起点之前最近的
断点。

每次操作独立输出实际读取页数、压缩字节数、实际解码字节和恢复断点；构建还输出成员
数、断点数和索引大小。局部提取的解码量不超过 `S + 请求长度 + 514`，跳过的字节也
计入解码量。

## 复跑入口

- 验收测试：`python3 -m unittest tests.test_gzip_index -v`
- 真实 HMAC 收件 + 新进程提取演示：`python3 -I scripts/gzip_hmac_demo.py`
- 8 MiB/32 MiB 基准：`scripts/gzip_benchmark.sh`
