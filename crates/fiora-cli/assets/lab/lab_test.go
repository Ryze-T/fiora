// 实验主体（Go）：真实 sink 驱动 + canary + 正控。目标 sink: {sink}
package lab

import (
	"os"
	"testing"
)

const canary = "/tmp/lab-canary"

func TestVuln(t *testing.T) {{
	// ==== 加载真实代码（go.mod replace 指向 /work 只读挂载）====
	t.Log("[ENV ] 目标包: /work（replace 已配）")

	// ==== 1) 攻击载荷（EXP）====
	// TODO: 按 sink 语义构造（gob 反序列化 / 模板注入 / 命令拼接）。
	os.Remove(canary)
	// target.Entry(attackBytes)                     // ← 打开此行
	fired := false
	if _, err := os.Stat(canary); err == nil {{
		fired = true
	}}
	t.Logf("[EXP ] 载荷执行: %v", fired)
	if fired {{
		b, _ := os.ReadFile(canary)
		t.Logf("[RCE ] 任意命令执行实锤 · canary: %s", string(b))
	}}

	// ==== 2) 正控（通道语义真实）====
	// TODO: 正常编解码往返断言。
	t.Log("[DONE] 实验结束（记录：真代码/桩化边界/canary/正控/分级）")
}}
