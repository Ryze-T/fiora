# Fiora 架构总览

> 面向二次开发与代码阅读。实现细节见各 crate 顶部文档注释；本文回答「东西在哪、怎么串起来、往哪扩」。

## 分层地图（对应 DESIGN.md 的 L0-L5）

```
crates/
├── fiora-core       L0 状态核心：三实体账本（FileRecord/Finding/Chain）+ Evidence
│                    AuditMeta（阶段/模型溯源）· TTL 租约调度 · 成本记账 · ProjectConfig · util
├── fiora-scanner    L1 候选生成：OpenGrep 桥 · Fiora Rules（三级规则库）· 规则起草通道
│                    技术栈/项目画像检测 · Surface Inventory（覆盖率分母）
├── fiora-evidence   L2 证据协议：预装配骨架 · 三者齐备（sink×source×entry）· 诚实分级
├── fiora-processor  L3 判定大脑：pi 驱动 · 三段式（triage/judge/revalidate）
│                    verdict 契约 · 机械核查（五族语义降级 + CVE 消歧）· 链式引擎 · 语义探索
├── fiora-verify     L4 验证：确定性差分（pre/post-patch）· 验证结论回填口（verify record）
├── fiora-report     展现层：用户模板渲染（暗色/自动统计/mermaid 链）· 验证就绪清单（report.json）
│                    · SARIF 2.1.0 导出（CI/Code Scanning）
├── fiora-eval       L5 评测：语料格式 · 打分器（recall/precision/每真洞成本）
└── fiora-cli        入口：clap 契约 + 命令分发（commands/ 按组拆分）
```

## 数据流

```
scan(规则+语义) → candidates ──┐
surface inventory ────────────┼→ evidence(骨架) → process(判定/verdict) → findings
INFO.md(业务上下文) ──────────┘                                  │
                                                                 ├→ chain(机制感知拼链) → chains
                                                                 └→ verify(确定性差分 + Agent 回填) → verification
findings + chains + verification + coverage → report(HTML) / eval(打分)
```

## 关键设计决定（为什么长这样）

| 决定 | 理由 |
|---|---|
| 三实体账本 + append-only | 换模型重跑 = 严格改进；身份锚定 sink+函数，title/行号不参与 |
| 判定必须挂证据 | `verdict.evidenceRef` 指向 Evidence；无证据的 TP 被 schema 拒收 |
| 两轴定级（危害 × 可达性） | `preconditions` 字段 + 报告部署形态矩阵；防「RCE」标签夸大 |
| 链式引擎带传输层检查 | HTTP SSRF 打不动裸 TCP——`Chain.reach = transport-gap` 标注弱链 |
| 验证三级诚实标注 | live > trigger > code-proof；徽章以真实执行为准，不冒充 |
| 规则/Prompt 全是运行时数据 | 改数据不重编译；三级规则目录可覆盖内置 |
| 报告溯源取自账本 | `AuditMeta`（stage/model/severity）append-only 记录；零模型跑就说零模型，不硬编码自述 |
| SARIF 确定性 + 身份指纹 | 丢误报、按 (file,line,id) 排序、`partialFingerprints` 键住 finding id（行号漂移不改身份） |

## 扩展点（二次开发入口）

| 想做什么 | 改哪里 |
|---|---|
| 加漏洞规则 | `fiora rules add`（或 `crates/fiora-scanner/rules/builtin/*.yaml` 提 PR） |
| 改判定 prompt | `~/.fiora/prompts/judge.md` 覆盖（不改代码） |
| 新 CLI 命令 | `crates/fiora-cli/src/commands/<组>.rs` + main.rs 契约 |
| 换审计 Agent 运行时 | `fiora-processor/src/pi.rs`（PiRunner，契约：JSON 事件流 + usage/cost） |
| 扩语义核查表 | `fiora-processor/src/guard_check.rs`（一族一个 GuardFamily 常量） |
| 换报告版式 | `docs/REPORT-TEMPLATE.md` 先改规范 → `fiora-report/src/template.{css,js}` → 契约测试 |

## 测试策略

- 单元/契约测试随 crate（`cargo test`，126）；报告有**模板契约测试**锁结构、SARIF 有确定性与严重度映射测试；
- e2e：fake-pi 脚本驱动全流程（不烧模型）；真实验证走 `docs/TUTORIAL.md` 的实验室；
- 回归：`fiora eval --corpus corpus --rule-only`（零模型下限门禁，CI 必跑）→ `fiora eval --corpus corpus`（判定通道不掉分）。
