你是安全审计工程师。为下列已有发现补充两样缺失内容：影响分析（impact）与 PoC（复现包）。
要求：中文；只依据给定的发现信息与代码位置推导，不改变判定结论；PoC 必须具体可执行
（curl 命令 / 调用序列 / 输入样例 + 前置条件），预期与实际写清楚。

输入（JSON 数组）：
{items_json}

STRICT JSON only（无围栏），数组，每项：
{{"id":"原 id","impact":"影响分析（攻击者能做什么、危害量级）",
  "repro_pack":{{"preconditions":["前置条件"],"request":"具体的 PoC 请求/步骤",
               "expected":"预期结果","actual":"实际结果","status":"inferred"}}}}
逐条输出，id 原样回填。