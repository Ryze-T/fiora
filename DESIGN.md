# Fiora — 代码审计 Harness 产品设计文档（定稿）

> **Fiora**：证据挂载式 AI 代码审计 harness。以「证据挂载判定」与「漏洞链自动化」
> 为核心，工具管覆盖率、AI 管判断力、框架编排管完备性。
> 本文档是产品设计定稿，开发按里程碑执行。

---

## 0. 分工哲学（全项目总纲）

> **工具管「查得全」（覆盖率），AI 管「判得准」（判断力），框架编排管「不漏审」（完备性）。**

- 工具（规则/扫描）在定义范围内确定性穷尽，盲区由账本点名暴露；
- AI 两个角色：① 在已覆盖路径内做判断；② **自我挖掘**，排除已覆盖路径，专攻账本之外（零入口异常模块、零候选模块、怪异语义点）；
- 框架的职责是让 AI 在已覆盖路径里不漏水：候选 100% 落账、拒答留痕、结论挂证据、二次复核。

**设计原则**（P1~P8）：

| # | 原则 |
|---|---|
| P1 | 确定性工序归工具，判断性工序归模型 |
| P2 | 结论必须挂可复核证据（代码坐标级），程序可验 |
| P3 | 双通道候选：规则门控 + 自由探索，防召回天花板 |
| P4 | append-only、幂等、断点续跑、成本记账 |
| P5 | 判定纪律结构化：三者齐备 + 六问强制反驳 |
| P6 | 报告是产品：给人审阅的深度交付物 |
| P7 | 评测回归闭环 |
| P8 | 数据驱动：规则/prompt/模板皆运行时数据，改数据不重编译 |

---

## 1. 总体架构

```
fiora 单二进制（Rust workspace，cargo build 产出）
├── fiora-cli          # 命令行，ms 级启动
├── fiora-core         # 三实体账本 + 租约调度 + 成本记账
├── fiora-scanner      # L1：OpenGrep 引擎（内嵌）+ 语义探索通道
├── fiora-evidence     # L2：证据协议 + 预装配（无独立图引擎）
├── fiora-processor    # L3：pi durable 驱动（RPC）+ verdict + 链式引擎
└── fiora-report       # 展现层：单文件 HTML（审计报告书式）

内嵌运行时：pi（**内嵌执行器**，版本 pin，实现细节，产品表面零暴露；
  判定轨迹由 fiora 原生解析呈现为「审计轨迹」，不引导用户进入执行器会话）
内嵌引擎：  OpenGrep（LGPL-2.1，单二进制，JSON 输出桥接）
外部工具依赖：0 个
```

**交付形态**：单二进制（~80-120MB，内嵌 pi + OpenGrep），首启解压 runtime 到
`~/.fiora/runtime/`（hash 校验），`fiora doctor` 自检。多平台矩阵
（macOS/Linux × arm64/x64）。模型凭据 = `fiora init` 引导配置（复用 pi provider 体系），
不是安装负担。

---

## 2. L0 编排骨架

**理念**：审计是可中断、可续跑、永不丢成果的流水线；状态即产品。

### 数据布局

```
.fiora/
├── fiora.config.ts        # 项目配置 + 插件注册
├── INFO.md                # 仓库语义理解（业务/核心资产/信任边界），注入 prompt
├── files/<path>.json      # 文件账本：候选 + 分析历史
├── findings/<id>.json     # 漏洞发现（含 verdict + 证据引用）
├── chains/<id>.json       # 漏洞链（steps[] 引用 findingId）
├── evidence/<id>.json     # 证据附件（调用链/数据流坐标）
├── runs/<runId>.json      # 运行日志 + 成本
├── fiora.db               # SQLite 派生索引（可随时从 JSON 重建，永不写回）
├── rules/                 # 项目级规则（团队共享，git 提交）
├── prompts/               # 项目级 prompt 覆盖/追加
└── reports/               # 交付物
```

### 核心机制

- **三实体账本**：FileRecord（文件账）/ Finding（漏洞）/ Chain（链，一等公民，跨文件），
  稳定 id 引用；Evidence 独立存储挂 finding；
- **合并语义**：append-only + additive fill。Finding 身份 = `hash(漏洞类别, sink 符号,
  所在函数签名)`，title/行号不参与身份，换模型重跑 = 严格改进不重复；
- **调度**：本机多 worker + TTL 租约（claim/heartbeat/release，崩溃过期自动回收）；
  executor 接口预留分布式实现；
- **成本记账**：每批次/每 finding 记 tokens+USD（`agent.cost`），`--max-cost-usd`
  优雅中断续跑，报告算「每真洞成本」；
- **pipeline**：`scan → evidence → process(triage/judge/revalidate) → chain → report`，
  每阶段幂等可单独重跑（增量复跑由账本幂等性承担：已 `analyzed` 的文件不再进批次；
  `--diff` 语义的变更集筛选仍在路线图）。

### CLI

```
fiora init | scan | evidence | process | chain | report | status | doctor
fiora run    # 全流水线
```

> **现状注记（供贡献者）**：上表是设计面全景。已实现另含 explore/compose/trace/
> family/lab/eval/draft-rules/rules/models（见 docs/USAGE.md 命令全集）；
> `resume` 由账本幂等续跑承担（无独立命令）；`fiora.config.ts` 现为 `config.json`；
> `fiora.db` SQLite 派生索引未实现（JSON 直读已满足规模）；rules 的
> test/stats/new/export/update 在路线图。

---

## 3. L1 候选生成层

**理念**：宽进严出；候选是「值得看的地方」；没被看到的地方必须有名字。

### 双通道

- **通道 A（规则）**：OpenGrep 全仓扫描，三层规则资产库 → 归一化 Candidate
  （含 taint 命中的 source→sink 数据流片段）；
- **通道 B（语义探索 / 自我挖掘）**：pi agent 自由读码，**排除已覆盖路径**，预算配额制：
  ① 资产导向（INFO.md 定位核心资产，按入口配额）② 定向补盲（零候选模块）③ 怪异巡检
  （skip/bypass/后门/压制告警/临时方案）。产出带推理笔记 + session 可回溯的候选。

### 三层规则资产库（Fiora Rules）

| 层 | 内容 |
|---|---|
| 聚合层 | semgrep-rules 社区 + OpenGrep taint 规则 + 开源聚合集（去重/噪音分级/许可标注） |
| 原创层 | 实战沉淀的四大类规则（sqli/rce/cmdi/auth，含假阳性收窄经验）+ 30 个框架陷阱 matcher + 常见静态检查清单的等价移植（吸收成规则，不依赖原工具） |
| 起草层（✅） | `fiora draft-rules`：LLM 按覆盖盲区起草**标准 Semgrep YAML**（永不 eval 模型代码），落盘 `.fiora/rules-draft/draft.yaml` 并立刻过三级注册表校验，语法/契约不合规即拒收删文件；人工 review 后 `rules add --project` 入库。**只有一套规则引擎**（Semgrep YAML + 三级注册表），起草通道不引入第二套编译器 |

**规则可维护性**：三级目录（内置只读 → `~/.fiora/rules/` → `.fiora/rules/`，高级
id 覆盖低级）；Semgrep YAML 格式（行业标准）；`rules add <file|git-url>` 规则包机制
（manifest 版本/出处/许可）。规则 fixtures 回归（`rules test`）与命中战绩回流
（`rules stats`）在路线图。

### 技术栈检测与入口面

- sentinel 文件/lockfile → 技术栈标签，三用：规则门控、prompt 威胁亮点、报告技术面；
- **Surface Inventory**：确定性枚举全部信任边界入口（文件路由=文件系统枚举，代码
  路由=声明语法模式），覆盖率分母；
- 覆盖率三口径：入口面（主）/ sink 追踪率（辅）/ 文件覆盖（参考），缺口点名不藏。

### 范围边界

硬编码密钥 **纳入**（链的高价值节点）；SCA 依赖漏洞 **排除**（另一物种）；
IaC/容器配置二期。

---

## 4. L2 证据层（证据协议，非引擎）

**理念**：证据是确定性工件不是模型意见；透明断链；宁可诚实的不确定。

（讨论结论：不自研调用图引擎，pi agent 本身就是可达性追踪者，实测无图引擎不影响
判定精确率。L2 = 证据 schema + 追踪协议 + 确定性佐证。）

### 机制

1. **证据预装配**（确定性，无 AI）：入口清单 + OpenGrep taint 数据流片段 + 命中上下文
   组装成 Evidence 骨架，judge 时 agent 验证与延伸（砍 30~50% 重复追踪时间）；
2. **追踪协议**：agent 判定每条候选必须追出 entry→…→sink 调用链，**每跳 file:line**；
   追不到入口只能 `uncertain`，断链标 `unresolved` 显式暴露；
3. **三者齐备判定**：sink × source × entry 缺一不判 TP；callers 空 → dead-code；
4. **证据分级**：`dataflow-verified > callchain-verified > inferred > dead-code`，
   结论置信度锚定证据等级。

### 覆盖率保证（去掉调用图后的回答）

覆盖率是**账本数出来的**：文件/模式覆盖（OpenGrep 机械穷尽）+ 入口面覆盖（确定性
枚举）+ 审计覆盖（每入口/候选/命中落结论，「未审」是显式一行）。路径级判断性覆盖
由协议+复核+通道 B 压漏，异常（「引入 web 框架但 0 入口」）自动点名。

---

## 5. L3 审读层（大脑）

**理念**：把聪明但随意的 AI 改造成聪明且完备的审计员；链是漏洞的最高形态。

### 三段式流水线

```
triage（便宜模型，只读文本）→ P0/P1/P2/skip，~1¢/条
judge  （贵模型 xhigh，批次 session）→ 三者齐备 + 六问反驳 + verdict + 复现包
revalidate（独立 session 换视角挑刺 + 查 git 历史）→ 改判/砍误报（50%+），HIGH+ 才跑
```

- **批次粒度**：~5 文件/~10 候选 = 1 个 pi session（同模块同批判断质量更高）；
  pi 进程常驻 RPC，session 按批新建（上下文隔离）；批次断点续跑；
- **verdict schema 强校验**（zod + 一次修复），拒答结构化留痕；
- **不确定自动升级**：便宜模型判 uncertain → 升级最强模型重审；
- **多模型混跑**：`--reinvestigate` 换模型复审旧结论，按稳定 id 合并 = 严格改进。

### Prompt 体系（运行时数据，用户可定制）

核心判定协议 + 技术栈威胁亮点（按检测栈注入）+ INFO.md 业务上下文 + 候选与证据坐标
+ verdict JSON schema。`~/.fiora/prompts/` 可覆盖追加。

### 链式引擎（差异化核心）

**确定性拼接点 + LLM 组装**（不许空想）：
1. 从 TP findings 证据提取共享要素（同一数据对象/凭据/身份令牌/可写路径）；
2. 三种拼法：数据流拼接 / 权限递进 / 能力叠加；
3. 产出 `Chain{pattern, steps[], impact, severity}`，直接进报告链路图。

### 真实模型容错（实测教训）

- 结论词汇归一（needs-more-info/inconclusive 等 → uncertain），合理怀疑不硬失败；
- **逐条抢救**：批次输出部分损坏时，合法 finding 保留、坏条目落入拒答日志，
  既不整批死亡也不静默丢弃；
- **并行执行**：`--workers N` 工作池（单一代码路径，workers=1 即顺序版），
  批次经 TTL 租约认领，账本 tmp 唯一名 + 成本写锁消除并发竞态。

### 速度优化（质量护栏：账本覆盖、强制协议、uncertain 升级不许动）

| 手段 | 收益 |
|---|---|
| 横向并发（worker × session 并发，多 provider 分摊速率限制） | 最大杠杆，质量零损耗 |
| 流水线重叠（扫完一个模块即入审） | 首个结论 <10 分钟 |
| 分级深审（P0 最强模型/P2 便宜模型+抽查） | 成本降一个量级 |
| 上下文工程（证据预装配） | 单批次提速 30~50% |
| 确定性预裁剪（死代码/常量输入/白名单直接出结论） | 不进 AI 不花钱 |
| 增量复跑（账本幂等续跑；`--diff` 变更集筛选在路线图） | 高频场景体验 |

参考账：5k 文件全量 40~60 分钟（10 worker × 8 并发），增量分钟级。

---

## 6. L4 验证层（✅ 确定性差分已实现；**动态验证归 Agent 工作台**）

> **产品定位（2026-11 重定位）**：fiora 是 Agent 工作台背后的审计插件，只做确定性代码态
> 差分；**环境启动与动态执行验证由工作台 Agent（pi 等 coding agent）负责**，结论经
> `fiora verify record` 回填。原 OpenShell 沙箱编排（verify-env/prove）已移除，
> 适配公理与 boot recipe 知识沉淀于 ROADMAP.md 供 Agent 参考。

### 6.0 验证职责分界（插件契约）

```
fiora：判定（静态，code-proof 级）+ 确定性差分（verify diff）
Agent：环境启动 + 动态执行验证（canary 纪律见 SKILL.md 验证章）
  结论回填：fiora verify record --level live-prove|trigger-prove|code-proof|disproved
  报告展示：诚实三级徽章（live-prove > trigger-prove > code-proof > 未验证）
```

验证纪律（canary 无害化 / 一次性环境 / 正控往返 / 桩化边界声明 / 即用即毁）
由 SKILL.md 第二章承载，它是验证方法论的单一真源。

### 6.1 静态验证（已实现）

- **pre/post-patch 差分复现**：`git show rev:file` 取两侧内容，确定性探针
  （`probe_shape` 危险构造形状，非裸符号，修复后的安全变体不会误判）对比
  pre/post 状态 → `fixed / persisting / regressed / unknown`；
- **修复验证**：`fiora verify diff`（无 rev，工作树 fix-check）；
- **探针永不猜测**：文件缺失/符号不可判 = `unknown`，不是 `fixed`；
- 结果写入 `Finding.verification`（`Ledger::set_verification` 更新语义），报告展示。

## 7. L5 评测层（✅ 已实现，`fiora-eval`）

- **语料格式**：`corpus/<case>/case.json`（ground truth：file × category × sink token）
  + `repo/` 源树；内置 2 案例（go-webapp / py-api，5 条 ground truth）；
- **打分器**：recall / precision / 每真洞成本（$/TP）/ 漏报清单，micro 平均聚合；
  匹配语义：file+category 同 + sink token 子串（评测测「找到这类问题了吗」）；
- **`fiora eval --corpus`**：逐案例全流水线 + 打分 + metrics.json；
- **实战价值**：首跑即抓出 2 个真问题（auth 规则语法错误静默失效 → 召回 0%；
  复核成本漏记账），评测层是「改动可测量」的基础设施。
- ARVO/CyberGym 真实语料导入留二期。

---

## 8. 数据模型（核心 schema）

```
FileRecord { path, digest, techTags[], candidates[], analysisHistory[],
             status: pending|analyzed|skipped, lockedByRunId?, leaseExpiresAt? }
Candidate  { id, slug, channel: rule|semantic, matcherId, file, line, endLine,
             snippet, note?, techTags[], priority, sessionId?, evidenceId? }
Evidence   { id, sink{symbol,file,line}, sources[], entries[{symbol,file,line,route}],
             callChain[{from,to,quality: compiler|traced|llm|unresolved}],
             grade: DataflowVerified|CallchainVerified|Inferred|DeadCode,
             unresolvedHops[], tool }
Finding    { id, slug, title, severity, category, file, line, description,
             dataFlow?, evidenceRef, reproPack?, verdict?, chainIds[],
             agent{backend,model,thinkingLevel,runId,cost}, createdAt }
Verdict    { conclusion: TP|FP|uncertain, confidence, evidenceRef,
             rebuttals{parameterized,reachable,businessMethod,allowlisted,
                       userInputControlled,protectedByGuard,notes},
             reasoning }
ReproPack  { preconditions[], request, expected, actual, status }
Chain      { id, title, pattern: dataflow|privilege|stacking,
             steps[{findingId,note}], impact, severity }
AnalysisEntry { runId, agent, at, summary, findingIds[], refused?, refusalNote? }
```

---

## 9. 展现层：单文件 HTML 审计报告书（定稿版式 A）

**双读者设计**：负责人 30 秒看到风险结论；工程师照着证据修洞。

```
┌───────────────────────────────────┐
│  FIORA 安全审计报告                │
│  repo · 日期 · 范围声明            │
│───────────────────────────────────│
│  一、执行摘要                      │
│    3 CRITICAL · 7 HIGH · 链 2 条  │
│    核心结论：一句话定性            │
│  二、漏洞链路（叙述 + SVG 简图）    │
│    链-1: A→B→C（危害量化）        │
│  三、漏洞详情（按严重度排序）       │
│    #1 [CRITICAL] 标题              │
│       位置 · 证据链逐跳坐标        │
│       六问反驳记录 · 复现包        │
│       判定 TP (confidence)         │
│  四、负向结论（反驳掉的候选+理由）  │
│  五、覆盖率附录（三口径账本+未审）  │
│     · 方法说明 · 审计过程留痕      │
└───────────────────────────────────┘
```

- 单文件零依赖（CSS/JS/SVG/数据全内嵌），离线打开、git 归档、邮件转发；
- 证据链是灵魂：逐跳 file:line 可核验；
- 负向结论与覆盖缺口同等重要（透明即品牌）；
- 二期导出：Markdown/JSON 机器格式、飞书文档/多维表格。

---

## 10. 里程碑

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M0 | Rust workspace 骨架 + L0 三实体账本（单测） | ✅ |
| M1 | L1 双通道（OpenGrep 桥 + Fiora Rules + 语义探索通道） | ✅ |
| M2 | L2 证据协议 + 预装配 + 三者齐备校验 | ✅ |
| M3 | L3 三段式 + verdict + 链式引擎（pi JSON 模式驱动） | ✅ |
| M4 | 单文件 HTML 报告（版式 A 审计报告书） | ✅ |
| M5 | 示例仓库 e2e：`fiora run` 一条命令出报告 | ✅ |
| M6 | L4 验证层（差分复现 + 修复验证，`fiora verify`） | ✅ |
| M7 | L5 评测层（语料 + 打分器，`fiora eval`，recall/precision/$/TP） | ✅ |
| M8 | 生成式规则补盲（安全契约）+ `--workers` 并行 + 真实模型全链验证 | ✅ |
| 二期 | ARVO 语料导入 / 分布式 executor | ▢ |
