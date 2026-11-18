// 实验主体（Node）：真实 sink 驱动 + canary + 正控。目标 sink: {sink}（{src_file}）
const fs = require("fs");

const CANARY = "/tmp/lab-canary";
const CMD = "echo PWNED > " + CANARY;

(async () => {{
  // ==== 加载真实代码（只读挂载 /work）====
  // const target = require("/work/{src_file}");     // ← 打开此行
  console.log("[ENV ] 目标: /work/{src_file}");

  // ==== 1) 攻击载荷（EXP）====
  // TODO: 按 sink 语义构造（node-serialize/unserialize、vm.runInNewContext、
  // prototype pollution → gadget、模板注入）。
  try {{ fs.unlinkSync(CANARY); }} catch (e) {{}}
  // target.entry(attackInput);                     // ← 打开此行
  const fired = fs.existsSync(CANARY);
  console.log(`[EXP ] 载荷执行: ${{fired}}`);
  if (fired) console.log("[RCE ] 任意命令执行实锤 · canary:", fs.readFileSync(CANARY, "utf8").trim());

  // ==== 2) 正控（通道语义真实）====
  // TODO: JSON.parse / 正常解析往返断言。
  console.log("[DONE] 实验结束（记录：真代码/桩化边界/canary/正控/分级）");
}})();
