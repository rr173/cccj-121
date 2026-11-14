#!/usr/bin/env bash
# 离线接收库提取器（partner_webhook/salvage.py）演示与验收。
#
# 用现有服务和标准 sqlite3 生成真实数据库（512/4096/65536 三种页长、
# 足以分裂内部/叶子页的事件量、跨多页溢出的大正文、空正文、含零字节正文、
# 大 rowid），复制镜像后针对已知页做破坏，逐项验证退出码、诊断与隔离粒度，
# 并用独立片段读取器和 SQL 参照做交叉核对。全程本地，不连外网。
#
# 用法：bash demo_salvage.sh [工作目录]（默认 ./demo_salvage_out，已存在则重建）
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${1:-$REPO_ROOT/demo_salvage_out}"

echo ">>> 验收工作目录: $WORK（重建）"
rm -rf "$WORK"
python3 -I "$REPO_ROOT/scripts/salvage_acceptance.py" --workdir "$WORK"

cat <<EOF

>>> 提取器单命令用法（可直接运行）：
      python3 -I $REPO_ROOT/partner_webhook/salvage.py --db <镜像.db> --out <新目录> \\
          [--max-payload-bytes N] [--max-pages N] [--max-diagnostics N]
    退出码：0 完整提取；2 部分结果（损坏/歧义/失配/上限）；1 整体拒绝。
>>> 验收输出保留在: $WORK
EOF
