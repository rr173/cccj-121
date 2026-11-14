"""测试包。

在 ``python -I``（隔离模式，不把当前目录加入 sys.path、不读 PYTHONPATH）
下运行测试时，主动把仓库根目录加入模块搜索路径，保证应用包可被导入。
"""

import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
