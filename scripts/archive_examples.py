"""档案加工的手写小例子：输入与预期处置/内容都在这里人工写明。

这些例子**不调用** ``partner_webhook.docarchive`` 的正式加工函数来生成答案，
只作为独立的期望值来源，供 ``archive_acceptance.py`` 对照。每条例子记录：

* ``name``：场景名；
* ``incoming``：按到达顺序排列的来件（seed/patch 信封原文，JSON 文本）；
* ``expected_disposition``：每条事件最终应得处置的稳定机器码；
* ``expected_document``：最终应公布的档案（``None`` + ``state='absent'``
  表示根删除后的「本修订没有档案」，与内容为 JSON null 不同）；
* ``explanation``：为什么是这个结论的人工说明。

正式管线若与这些手写期望不一致，验收即失败。
"""

from __future__ import annotations

# 处置码与 docarchive 保持同名，但这里只是字符串字面量，不导入加工模块。
ADOPTED = "adopted"
WAITING = "waiting_predecessor"
BRANCH = "branch_unresolved"
NOT_SELECTED = "not_selected"
OP_FAILED = "operation_failed"
BLOCKED = "blocked_by_predecessor"
NON_ARCHIVE = "non_archive"
INVALID = "invalid_contract"


HANDWRITTEN_CASES = [
    {
        "name": "空键与 ~ 转义按原名访问",
        "incoming": [
            '{"kind":"seed","document_id":"d","revision":0,'
            '"document":{"":{"a/b":1,"c~d":2}}}',
            '{"kind":"patch","document_id":"d","base_revision":0,'
            '"revision":1,"operations":['
            '{"op":"test","path":"//a~1b","value":1},'
            '{"op":"test","path":"//c~0d","value":2}]}',
        ],
        "expected_disposition": [ADOPTED, ADOPTED],
        "expected_document": {"": {"a/b": 1, "c~d": 2}},
        "state": "present",
        "explanation": "根下空键成员的指针以空段开头（双斜杠 //）；段内再做"
                       "RFC 6901 转义：//a~1b 解码为 ['', 'a/b']、//c~0d 解码"
                       "为 ['', 'c~d']。两个 test 成立，修订 1 采用。",
    },
    {
        "name": "对象数字键不是数组下标",
        "incoming": [
            '{"kind":"seed","document_id":"d","revision":0,'
            '"document":{"0":"name","arr":[7,8]}}',
            '{"kind":"patch","document_id":"d","base_revision":0,'
            '"revision":1,"operations":['
            '{"op":"replace","path":"/0","value":"renamed"},'
            '{"op":"replace","path":"/arr/1","value":80}]}',
        ],
        "expected_disposition": [ADOPTED, ADOPTED],
        "expected_document": {"0": "renamed", "arr": [7, 80]},
        "state": "present",
        "explanation": "对象上的 '0' 是普通成员名；只有遇到数组时 /1 才按下标"
                       "规范解析。01、负数、越界下标都会被判约定/操作失败。",
    },
    {
        "name": "同数组前移后移",
        "incoming": [
            '{"kind":"seed","document_id":"d","revision":0,'
            '"document":{"a":[0,1,2,3]}}',
            '{"kind":"patch","document_id":"d","base_revision":0,'
            '"revision":1,"operations":['
            '{"op":"move","from":"/a/3","path":"/a/1"}]}',
            '{"kind":"patch","document_id":"d","base_revision":1,'
            '"revision":2,"operations":['
            '{"op":"move","from":"/a/0","path":"/a/3"}]}',
        ],
        "expected_disposition": [ADOPTED, ADOPTED, ADOPTED],
        # 前移得 [0,3,1,2]；再把当前首元素移到末尾得 [3,1,2,0]
        "expected_document": {"a": [3, 1, 2, 0]},
        "state": "present",
        "explanation": "move 先取出再删除，并按删除后的数组定位插入点；"
                       "后移到末尾用插入语义 index==length，合法。",
    },
    {
        "name": "copy 后单独修改副本",
        "incoming": [
            '{"kind":"seed","document_id":"d","revision":0,'
            '"document":{"src":{"n":[1,2]}}}',
            '{"kind":"patch","document_id":"d","base_revision":0,'
            '"revision":1,"operations":['
            '{"op":"copy","from":"/src","path":"/dst"},'
            '{"op":"add","path":"/dst/n/-","value":3}]}',
        ],
        "expected_disposition": [ADOPTED, ADOPTED],
        "expected_document": {"src": {"n": [1, 2]},
                              "dst": {"n": [1, 2, 3]}},
        "state": "present",
        "explanation": "copy 复制的是独立树，对 /dst 的追加不影响 /src。",
    },
    {
        "name": "超大整数 test 不丢精度",
        "incoming": [
            '{"kind":"seed","document_id":"d","revision":0,'
            '"document":{"big":123456789012345678901234567891}}',
            '{"kind":"patch","document_id":"d","base_revision":0,'
            '"revision":1,"operations":['
            '{"op":"test","path":"/big",'
            '"value":123456789012345678901234567891}]}',
        ],
        "expected_disposition": [ADOPTED, ADOPTED],
        "expected_document": {"big": 123456789012345678901234567891},
        "state": "present",
        "explanation": "数字保留十进制原文，1 与 1.0 相等、相邻超大整数不等；"
                       "不先转 float，因此 test 精确成立。",
    },
    {
        "name": "null 内容与根删除是两种状态",
        "incoming": [
            '{"kind":"seed","document_id":"d","revision":0,"document":null}',
            '{"kind":"patch","document_id":"d","base_revision":0,'
            '"revision":1,"operations":[{"op":"remove","path":""}]}',
            '{"kind":"patch","document_id":"d","base_revision":1,'
            '"revision":2,"operations":['
            '{"op":"add","path":"","value":{"reborn":true}}]}',
        ],
        "expected_disposition": [ADOPTED, ADOPTED, ADOPTED],
        "expected_document": {"reborn": True},
        "state": "present",
        "explanation": "seed 内容为 null 仍是 present 的档案；remove 根后是"
                       " absent（本修订没有档案），此时 replace 根失败，"
                       "只有根 add 能重新建档。",
    },
    {
        "name": "后一步失败使整条修改回滚",
        "linear": False,
        "incoming": [
            '{"kind":"seed","document_id":"d","revision":0,'
            '"document":{"a":1}}',
            '{"kind":"patch","document_id":"d","base_revision":0,'
            '"revision":1,"operations":['
            '{"op":"replace","path":"/a","value":9},'
            '{"op":"test","path":"/a","value":1}]}',
            '{"kind":"patch","document_id":"d","base_revision":1,'
            '"revision":2,"operations":['
            '{"op":"replace","path":"/a","value":2}]}',
        ],
        "expected_disposition": [ADOPTED, OP_FAILED, BLOCKED],
        "expected_document": {"a": 1},
        "state": "present",
        "explanation": "第 1 个操作把 /a 改成 9，第 2 个操作 test 仍期望 1，"
                       "比较失败；第 1 个 replace 随工作副本一并丢弃，当前档案"
                       "仍是 seed；失败事件保留查账，修订 2 被阻断。",
    },
    {
        "name": "乱序到达先等待，补齐再沿链接执行",
        "linear": False,
        "incoming": [
            '{"kind":"patch","document_id":"d","base_revision":1,'
            '"revision":2,"operations":[{"op":"replace","path":"/v","value":2}]}',
            '{"kind":"patch","document_id":"d","base_revision":0,'
            '"revision":1,"operations":[{"op":"replace","path":"/v","value":1}]}',
            '{"kind":"seed","document_id":"d","revision":0,'
            '"document":{"v":0}}',
        ],
        "expected_disposition": [ADOPTED, ADOPTED, ADOPTED],
        "expected_document": {"v": 2},
        "state": "present",
        "explanation": "前两次同步时缺 seed/前版，处置为等待前版；seed 补齐后"
                       "从修订 0 沿 0→1→2 执行，一次重算全部采用。",
    },
    {
        "name": "同修订两个候选即分支，无选择只公布无分支前缀",
        "linear": False,
        "incoming": [
            '{"kind":"seed","document_id":"d","revision":0,'
            '"document":{"v":0}}',
            '{"kind":"patch","document_id":"d","base_revision":0,'
            '"revision":1,"operations":[{"op":"replace","path":"/v","value":1}]}',
            '{"kind":"patch","document_id":"d","base_revision":1,'
            '"revision":2,"operations":[{"op":"replace","path":"/v","value":2}]}',
            '{"kind":"patch","document_id":"d","base_revision":0,'
            '"revision":1,"operations":[{"op":"replace","path":"/v","value":11}]}',
        ],
        "expected_disposition": [ADOPTED, BRANCH, BLOCKED, BRANCH],
        "expected_document": {"v": 0},
        "state": "present",
        "explanation": "两条 0→1 即使内容相同也是分支；不按到达时间/event_id"
                       "自动选。公布退回唯一无分支的修订 0，修订 2 挂在含糊"
                       "的修订 1 之后，标记阻断但仍保留在账上。",
    },
    {
        "name": "两个 seed 冲突，未选择前不公布",
        "linear": False,
        "incoming": [
            '{"kind":"seed","document_id":"d","revision":0,'
            '"document":{"v":1}}',
            '{"kind":"seed","document_id":"d","revision":0,'
            '"document":{"v":2}}',
        ],
        "expected_disposition": [BRANCH, BRANCH],
        "expected_document": None,
        "state": "none",
        "explanation": "同一档案出现两个 seed 本身就是分支；没有人工选择前"
                       "不公布任何内容，必须先选定 revision=0 的事件。",
    },
    {
        "name": "非档案来件与约定不符",
        "incoming": [
            '{"kind":"heartbeat"}',
            '{"kind":"seed","document_id":"d","revision":true,"document":1}',
            '{"kind":"patch","document_id":"d","base_revision":0,'
            '"revision":2,"operations":[]}',
        ],
        "expected_disposition": [NON_ARCHIVE, INVALID, INVALID],
        "expected_document": None,
        "state": "none",
        "explanation": "未知 kind 是非档案来件；布尔冒充整数、revision 不等于"
                       "base_revision+1 都是约定不符，错误指明所在事件且不转型。",
    },
]


def explain_expected(case: dict) -> None:
    """打印一条手写例子的人工说明（供验收运行时阅读）。"""
    print(f"  · {case['name']}")
    print(f"      来件 {len(case['incoming'])} 条；期望处置 "
          f"{case['expected_disposition']}；最终状态 {case['state']}")
    print(f"      说明：{case['explanation']}")


__all__ = ["HANDWRITTEN_CASES", "explain_expected"]
