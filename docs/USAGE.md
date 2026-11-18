# Fiora Usage Guide

证据挂载式 AI 代码审计 Harness。完整命令参考、配置说明与工作流示例。

```
fiora <COMMAND>

Commands:
  init       一键初始化：工作区、规则、模型配置、运行时自举
  doctor     环境自检（运行时/规则/配置/凭据），--json 机器可读
  run        全流水线：scan → evidence → process → chain → report（含 compose 自动触发）
  scan       L1 规则通道候选生成（OpenGrep）
  explore    L1 语义通道：排除已覆盖路径的自我挖掘（消耗模型预算）
  evidence   L2 证据预装配（三者齐备骨架）
  process    L3 判定：triage → judge → revalidate（付费阶段）
  chain      漏洞链拼接（数据流 / 权限递进 / 能力叠加）
  compose    组合狩猎：把单点安全的发现组合成 super-0day（A+B 成链）
  trace      查看一条发现的完整判定轨迹（推理/工具调用/结果）
  verify     L4 验证：pre/post-patch 差分复现 / 修复验证 + Agent 结论回填
  eval       L5 语料评测：recall / precision / 每真洞成本
  draft-rules 按覆盖盲区起草 Semgrep 规则（草稿落盘，人工 review 后入库）
  rules      规则库管理
  report     生成单文件 HTML 审计报告
  status     账本状态快照
  family     能力族座次表（按 RCE/SSRF 等族聚合，按可达性排序）
  refine     把冗长的发现文本改写成可扫读短句
  enrich     为已有发现补充影响分析与 PoC
  localize   把发现文本本地化（中文），只改展示字段
  lab        trigger-prove 实验室脚手架（真代码 + 桩化 + canary + 正控）

Options:
  -h, --help     帮助
  -V, --version  版本
```

---

## 快速开始

```bash
# 0. 安装（任选其一）
curl -fsSL https://github.com/Ryze-T/fiora/releases/latest/download/fiora-macos-arm64.tar.gz | tar xz
export PATH="$PWD/fiora-macos-arm64:$PATH"   # 预编译；或 cargo build --release 从源码

# 1. 一键初始化（自动创建配置/凭据/规则，自举 pi 与 opengrep 运行时）
fiora init --root ./my-repo --model zai/glm-5.2 --api-key sk-xxx

# 2. 填写 <仓库>/INFO.md（业务/核心资产/信任边界，注入每个 AI 判定 prompt）

# 3. 一条命令出报告
fiora run --root ./my-repo
# 报告：my-repo/fiora-report/report.html
```

`--root` 默认为当前目录（`.`），`cd` 进仓库后可全部省略。

---

## 命令详解

### `fiora init` — 一键初始化

首次使用必跑。幂等：重复执行不会覆盖已有配置与 INFO.md。

```
fiora init [--root <DIR>] [--model <ID>] [--budget-model <ID>] [--thinking <LEVEL>]
           [--api-key <KEY>] [--api-key-env <VAR>] [--base-url <URL>] [--api <PROTOCOL>]
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--root` | `.` | 目标仓库根目录 |
| `--model` | pi 默认 | 判定模型（pi 模型 id，如 `openai/gpt-5.5`、`anthropic/claude-opus-4-8`、`zai/glm-5.2`） |
| `--budget-model` | 无 | triage / P2 批次的便宜模型（省成本关键档位） |
| `--thinking` | `xhigh` | 默认思考深度：`minimal\|low\|medium\|high\|xhigh\|max` |
| `--api-key` | 无 | API key，存入 `~/.fiora/credentials.json`（chmod 600），spawn 时注入，**不进项目配置** |
| `--api-key-env` | 按模型推断 | 指定存放 key 的环境变量名（key 留在你自己的环境里） |
| `--base-url` | 无 | 自定义网关端点（写入 pi 的 models.json，兼容既有配置） |
| `--api` | 按模型推断 | 网关通信协议：`openai-completions`（默认）/ `openai-responses` / `anthropic-messages` / `google-generative-ai` |

自动创建的产物：

| 文件 | 用途 |
|---|---|
| `<root>/.fiora/config.json` | 模型默认配置（后续命令自动读取） |
| `~/.fiora/credentials.json` | API key（chmod 600，用户级） |
| `~/.fiora/rules/builtin/*.yaml` | 内置 opengrep 规则的可编辑副本 |
| `~/.fiora/rules/README.md`、`<root>/.fiora/rules/` | 用户级/项目级规则目录 |
| `<root>/INFO.md` | 仓库语义理解模板 |
| `~/.fiora/runtime/` | pi + opengrep 运行时（自动引导） |

示例：

```bash
# OpenAI 兼容网关
fiora init --model openai/gpt-5.5 --api-key sk-xxx --base-url https://gw.example.com/v1

# Anthropic 协议网关（协议自动推断，也可显式覆盖）
fiora init --model anthropic/claude-opus-4-8 --api-key sk-ant-xxx --base-url https://gw.example.com/anthropic

# key 留在自己环境变量里（不落盘）
export MY_KEY=sk-xxx
fiora init --model openai/gpt-5.5 --api-key-env MY_KEY
```

### `fiora run` — 全流水线

```
fiora run [--root <DIR>] [--model <ID>] [--thinking <LEVEL>] [--workers <N>] [--no-ai]
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--model` | config.json | 覆盖判定模型 |
| `--thinking` | config.json | 覆盖思考深度 |
| `--workers` | `1` | 并行判定 worker 数（批次级并行，经 TTL 租约认领） |
| `--no-ai` | 关 | 只跑免费阶段（scan + evidence + report），不调模型；交付零模型报告，provenance 会写明未判定 |
| `--severity` | `high` | 书写阀（不是判定阀）：high=仅高危及以上写全契约（impact/PoC/前置），中低危只留最小字段省 token；**每条候选都会拿到判定结论**，报告展示范围跟随此参数 |
| `--explore <N>` | auto | 语义探索会话预算（此前自动跑项目画像，见 `fiora profile`）：auto=按未覆盖文件全量覆盖（大仓库会是数百上千个模型会话，启动时会先报数）；`--explore 0` 跳过探索只走规则通道 |

### `fiora scan` — L1 规则通道

```
fiora scan [--root <DIR>]
```

OpenGrep 全仓扫描 + 三级规则库（builtin < `~/.fiora/rules` < `<root>/.fiora/rules`，同 id 高级覆盖），候选入账。免费、秒级。

### `fiora explore` — L1 语义通道（自我挖掘）

```
fiora explore [--root <DIR>] [--budget <N>] [--rounds <N>] [--jobs <N>] [--model <ID>] [--thinking <LEVEL>]
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--budget` | 自动（全量覆盖） | 最多消耗的 pi 会话数（未覆盖文件数 / 8，不封顶） |
| `--rounds` | `1` | 狩猎轮数：轮 1 广扫，轮 2+ 沿线索深挖（0day 回路） |
| `--jobs` | `4` | 并发会话数（会话独立，结果单点合并） |
| `--thinking` | `high` | 探索思考深度 |

排除已覆盖路径，专攻规则盲区（零候选模块、语义异常、注释后门/压制告警）。plan/execute 分离：≥3 会话先出狩猎计划（假设清单），执行会话按假设分工；线索与覆盖核算追加到 `.fiora/hunt.md`（跨轮记忆）。

### `fiora evidence` — L2 证据预装配

```
fiora evidence [--root <DIR>]
```

为每条候选生成确定性证据骨架（sink × source × entry 三者齐备），挂载 `evidenceId`。免费。

### `fiora process` — L3 判定（付费阶段）

```
fiora process [--root <DIR>] [--model <ID>] [--thinking <LEVEL>] [--budget-model <ID>]
              [--workers <N>] [--no-revalidate] [--max-cost-usd <USD>]
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--workers` | `1` | 并行判定 worker |
| `--no-revalidate` | 关 | 跳过对抗性复核 |
| `--max-cost-usd` | 无 | 成本上限（到达后优雅停止，可断点续跑） |

triage（便宜模型排序）→ judge（贵模型深审：三者齐备 + 六问反驳 + 证据挂载）→ revalidate（独立 session 对抗复核，可改判）。

### `fiora chain` — 漏洞链拼接

```
fiora chain [--root <DIR>]
```

对 TP findings 按三种模式自动拼链：数据流拼接 / 权限递进 / 能力叠加。

### `fiora compose` — 组合狩猎（super-0day 面）

```
fiora compose [--root <DIR>] [--model <ID>] [--thinking <LEVEL>]
```

把单点安全的发现组合成 super-0day：观察账本 + hunt.md 线索 → 组合假设（A+B 成链 / C 破保证）
→ 逐条确认会话（真追代码，判定契约输出）→ 存活者收编为 finding。`fiora run` 在链组装后
自动触发（观察 ≥3 条时）；单跑用于重审/补猎。

### `fiora trace` — 审计轨迹

```
fiora trace <finding-id|session-id> [--root <DIR>] [--json]
```

fiora 原生呈现一条发现的完整判定轨迹（推理/工具调用/结果），轨迹随项目走（`.fiora/sessions/`）。

### `fiora verify` — 验证组（确定性差分 + 结论回填）

```
fiora verify diff   [--root <DIR>] [--pre <REV>] [--post <REV>] [--finding <ID>]
fiora verify record --finding <ID> --level live-prove|trigger-prove|code-proof|disproved [--note <S>] [--severity <LEVEL>]
```

| 子命令 | 说明 |
|---|---|
| `diff` | pre/post-patch 差分复现（`fixed / persisting / regressed / unknown`）；不带 rev = 工作树 fix-check。探针确定性（危险构造形状，非裸符号），永不猜测 |
| `record` | **Agent 验证结论回填**：工作台 Agent 启动环境验证后写回真值（诚实三级 + 证伪），报告自动带验证徽章 |

环境启动与动态执行验证由工作台 Agent 负责（SKILL.md 验证章），fiora 不起环境。

### `fiora eval` — L5 语料评测

```
fiora eval --corpus <DIR> [--model <ID>] [--thinking <LEVEL>] [--no-revalidate] [--rule-only] [--severity <LEVEL>] [--out <FILE>]
```

语料布局：`corpus/<case>/case.json`（ground truth）+ `corpus/<case>/repo/`（源树）。

- `--rule-only` = **下限门禁**：只跑规则通道，零模型、确定性、可进 CI。输出 `rule-recall`，
  分母是「规则可见」的期望（`visible_to_rule`），
- 判定通道（默认）输出 recall / precision / 每真洞成本（$/TP）/ 漏报清单
  `precision` 只在判定通道有意义。候选未判定时报告 `n/a`，不伪造 100%。
  它的分母是「判定为真阳性的发现」，判出语料未标注的真实问题也会被算进去
  （输出里单独打印「未标注判定 N 条」），所以语料标注越全，这个数字越接近真值。
  把它当成**标注边界内的下限**来读，而不是绝对精度。

`--severity`（默认 `all`）只改**测量范围**：交付口（`run` / `report`）默认只看高危，
但评测不该继承交付过滤器：判定层把一条真阳性评成 MEDIUM 时会被挡在账本外、
记成漏报，那测的是「两个过滤器是否一致」，不是能力。想要旧口径就显式
`--severity high`。

**匹配口径**：同一个 `file` 且 sink 命中期望的 `sink_symbol`，再满足「类别等价」（
等价词表 ∪ 同族 ∪ 超族（`missing-authorization` / `broken-access-control` / `idor`
同属授权面，鉴权与授权在超族 `auth-mega` 互通）；或两条结论落在同一关注面
（access / injection / execution）。理由：TP 的身份锚点是 `sink_symbol + enclosing_fn`，
类别只是词表选择；但跨关注面（越权 vs SQLi）不能互相顶替。

`case.json` 里的 `"visible_to_rule": false` 标注「单文件规则看不见，需要跨文件语义」的期望
（如租户身份取自请求头、路由挂载缺鉴权）。这类期望不进规则下限分母，它们的分母是语义通道，
用来量化 **AI 通道的边际价值**；如果规则反而命中了它们，`eval --rule-only` 会打印警告
提醒修语料标注。

### `fiora draft-rules` — 起草规则补盲

```
fiora draft-rules [--root <DIR>] [--model <ID>]
```

按覆盖盲区让模型起草**标准 Semgrep YAML 规则**，写入 `<root>/.fiora/rules-draft/draft.yaml`。
草稿立刻过一遍三级注册表（`RuleRegistry::load`）校验：语法/契约不合规直接拒收并删除文件，
不会污染规则库。人工 review 后 `fiora rules add <file> --project` 入库生效（`scan` 自动纳入）。

> 起草通道只产出**数据**，永不执行模型生成的代码，也不存在第二套规则引擎。

### `fiora rules` — 规则库管理

```
fiora rules list
fiora rules add <file> [--project]     # 入库（先校验）；--project 放项目级随 git 共享
fiora rules validate [file]            # 结构与 id 契约校验
```

列出三级规则库（来源/严重度/id/语言）；`add/validate` 管理规则资产。
（`stats/test/new/export/update` 在路线图，见 README 已知边界。）

**覆盖语义**：同 id 时高级胜出，低级的同 id 规则**不会**一起进扫描，
所以你可以用一条同 id 的用户级规则收窄、甚至彻底替换一条内置规则
（`~/.fiora/rules/builtin/` 是内置语料的可编辑副本，改这里即生效）。
副本由 `fiora init` / `fiora scan` 与二进制语料保持同步：未改动的副本随升级
刷新，被改过的副本保留并提示「已覆盖内置规则」；旧版本安装会先把原文件备份成
`<name>.bak` 再刷新。

### `fiora doctor` — 环境自检

检查项分两级：**必需项**（node / pi 运行时 / opengrep / 规则库 / 配置）✗ 时退出码 1
（CI 门禁用）；**能力项**（docker）✗ 只关闭「主动验证」（skill 不启动动态验证），
不影响退出码。`--json` 输出 `healthy`（必需项）与 `activeVerification`（docker 开关）
两个字段，Agent 按 `activeVerification` 决定是否进入动态验证。**fiora 不代替用户
安装 docker**。

```
fiora doctor [--root <DIR>] [--json]
```

体检 pi/OpenGrep 运行时、规则库、模型配置、凭据五项。`--json` 输出机器可读
（Agent 集成入口）。

### `fiora enrich / refine / localize` — 报告精修

```
fiora enrich   [--root <DIR>]   # 补影响 + PoC（网络→curl / 代码执行→触发 harness / 文件→操作序列）
fiora refine   [--root <DIR>]   # 文字精炼为短句分点（每句 ≤25 字）
fiora localize [--root <DIR>]   # 中文化（不动身份字段/代码/路径）
```

### `fiora report` — 生成报告

```
fiora report [--root <DIR>] [--out <FILE>] [--severity high|all]
              [--sarif <FILE>] [--fail-on <LEVEL>]
```

默认输出 `<root>/fiora-report/report.html` + `report.json`。单文件零依赖、离线可开、可归档。

- **展示范围**：默认只含高危及以上（`--severity all` 显式放开）；低危仍落账；
- **`report.json`** 含 `verificationChecklist`：每条 TP 一条验证任务（族/档位/CWE/前置/
  repro/建议验证等级/打法提示），Agent 程序化消费驱动验证；
- **`--sarif <FILE>`**：导出 SARIF 2.1.0（GitHub Code Scanning / 各类 SARIF 消费方可直接吃）。
  误报（FalsePositive）不进结果；按 `(file, line, finding-id)` 排序，同一账本导出字节稳定；
  每条 finding 带 `partialFingerprints.fioraFindingId/v1`，行号漂移不改变身份；`enclosing_fn`
  落 `logicalLocations`；规则条目带 CWE 与 `security-severity`；
- **`--fail-on <LEVEL>`**：CI 门禁，存在 `LEVEL` 及以上的发现则退出码 1（`all|info|low|medium|high|critical`，
  与展示口径同一套 `severity_threshold`）。`--fail-on` / `--sarif` 的 `LEVEL` 非法值直接报错，不静默降级。

GitHub Actions 最小接法：

```yaml
- run: fiora report --root . --sarif fiora.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: fiora.sarif }
```

### `fiora profile` — 项目画像（模型提取）

```
fiora profile [--root <DIR>] [--model <ID>] [--refresh]
```

模型自己读仓库（工具会话）提取：项目画像 / 技术栈 / 入口面 / 信任边界 /
**历史 CVE 模式**（编号只写确信存在的，无据不编）/ **狩猎优先级**（结合本仓
结构的主动推理），落 `.fiora/profile.json`（可审计），注入判定、探索计划、
组合狩猎三个会话做注意力引导。`fiora run` 自动执行（已存在则沿用，`--refresh`
重提）。模型不可用时自动跳过，流水线照常。

> 注意与 `--profile <档位>` 区分：那个是 judge/budget **模型组合档位**（见下节），
> 这个是**仓库画像**。

### `fiora status` — 账本状态

```
fiora status [--root <DIR>]
```

文件/发现/链的计数与状态分布。

---

## 多模型与运行档位

一次配置多个模型，跑的时候按档位切换（或单次覆盖）：

```json
{
  "defaultModel": "mimo/mimo-v2.6-flash",     // 默认 judge
  "budgetModel": "mimo/mimo-v2.6-pro",        // 默认省钱档（triage/P2/复核）
  "models": {                                  // 模型池：命名可复用
    "flash": {"model": "mimo/mimo-v2.6-flash", "thinking": "high"},
    "opus":  {"model": "anthropic/claude-opus-4-8"}
  },
  "profiles": {                                // 运行档位：judge/budget 组合
    "fast": {"judge": "flash", "budget": "flash"},
    "deep": {"judge": "opus",  "budget": "mimo/mimo-v2.6-pro"}
  },
  "activeProfile": "deep"                      // 默认生效档位
}
```

> **协议职责边界**：模型协议（openai-completions / openai-responses / anthropic-messages /
> google-generative-ai …）由 pi 运行时执行；fiora 只写 models.json 路由 + 注入凭据
> （`$VAR` 自引用，key 不落项目）。provider 前缀到协议的猜测表在
> `fiora-processor::protocol_for`，猜不准时 `--api` 显式覆盖。

```bash
fiora models                          # 查看模型池与档位（--json 机器可读）
fiora process --profile fast          # 运行时切档
fiora process --model zai/glm-5.3-flash   # 单次显式覆盖（最优先）
```

**解析优先级**：CLI `--model/--budget-model` > `--profile` / `activeProfile` 档位 > 默认槽。
档位里的值可写**模型池名**（自动展开）或**直接写模型 id**；模型池条目可带 `thinking` 档。

## 会往被审计仓库写什么

审计本身只读源码，但**状态与产物落在被审仓库里**（随仓库走、可复现、可增量）：

| 路径 | 内容 | 建议 |
|---|---|---|
| `<root>/.fiora/config.json` | 模型默认配置 | 入库（团队共享同一档位） |
| `<root>/.fiora/rules/` | 项目级规则 | 入库（规则随代码一起评审） |
| `<root>/.fiora/{files,findings,chains,evidence,runs,cache,sessions}/`、`audit-meta.json`、`tech.json`、`surface.json`、`hunt.md` | 账本与运行时状态 | 不入库（可重生成） |
| `<root>/fiora-report/` | `report.html` / `report.json` | 按需（交付物可入库） |
| `<root>/log/` | 工作台 Agent 运行时自己写的日志 | 不入库 |

对应的 `.gitignore` 片段：

```gitignore
.fiora/files/
.fiora/findings/
.fiora/chains/
.fiora/evidence/
.fiora/runs/
.fiora/cache/
.fiora/sessions/
.fiora/fiora.db
.fiora/audit-meta.json
.fiora/tech.json
.fiora/surface.json
.fiora/hunt.md
fiora-report/
log/
```

> 规则目录只有一个例外：`~/.fiora/rules/builtin/` 的副本被人工改过之后就不再随
> 二进制升级刷新（会被判为「已定制」），升级时若判不出来，旧文件会以
> `<name>.bak` 保留在原处，不丢字节。

## 配置文件

### `<root>/.fiora/config.json`（项目级，模型默认配置）

```json
{
  "defaultModel": "zai/glm-5.2",
  "budgetModel": "cheap-model",
  "thinkingLevel": "xhigh",
  "baseUrl": "https://gw.example.com/v1",
  "apiKeyEnv": "MY_KEY",
  "api": "openai-completions"
}
```

所有字段可选；命令行 `--model` / `--thinking` 优先于配置文件；缺字段自动补默认值。

### `~/.fiora/credentials.json`（用户级，chmod 600）

存放 API key。项目配置/ git/审计账本中**永不出现密钥**。真实环境变量永远优先于存储的 key。

### 规则文件（Semgrep YAML，改文件即生效）

```
~/.fiora/rules/builtin/*.yaml   内置规则的可编辑副本（同 id 覆盖内置）
~/.fiora/rules/*.yaml           用户级规则（跨项目）
<root>/.fiora/rules/*.yaml      项目级规则（随仓库 git 共享）
```

### `<root>/INFO.md`

仓库语义理解（业务 / 核心资产 / 信任边界），注入所有 AI 判定 prompt。写清它能明显提升判定质量。

---

## 环境变量

| 变量 | 说明 |
|---|---|
| `FIORA_HOME` | fiora 用户目录（默认 `~/.fiora`）：credentials/rules/runtime |
| `FIORA_PI_BIN` | 直接指定 pi 二进制（跳过 runtime 查找） |
| `FIORA_OPENGREP_BIN` | 直接指定 opengrep 二进制 |
| `PI_CODING_AGENT_DIR` | pi 的 agent 配置目录（models.json 路由写入此处） |

运行时查找顺序：`FIORA_*_BIN` → `~/.fiora/runtime/` → `PATH`。

---

## 能力族座次与实验室

```bash
# 能力族座次表：按 RCE/SSRF/AWF 等族聚合，按可达性档位排序
# （回答“还有哪些 RCE / 哪些无条件”；档位 0 无条件 > 1 网络 > 2 部署形态 > 3 供应链 > 4 工作流）
fiora family
fiora family --family rce          # 只看 RCE 族
fiora family --all --json          # 含非 TP + 机器可读

# trigger-prove 实验室脚手架：真代码 + 桩化重依赖 + canary + 正控 + 即用即毁
fiora lab scaffold --finding <id>  # 按发现自动填模板
fiora lab scaffold --sink pickle.loads --file path/to/mod.py
```

入库时的机械核查自动生效（无需手动调用，五族语义表见 `guard_check.rs`）：
- **定性降级**：RCE / SQLi / SSRF / 路径 / 模板注入五族：声称命中安全语义
  （参数化 / 白名单 / 路径围栏 / 过滤器 / weights_only=True 等）且未论证绕过
  → 自动封顶 HIGH 并在 impact 标注；RCE 另有无据降级与自明危险原语例外；
- **已知洞消歧**：sink 语境含 `CVE-YYYY-NNNNN` 标记 → 自动标注供披露前消歧。

## 典型工作流

```bash
# 首次全量审计
fiora init --model zai/glm-5.2 --api-key sk-xxx
fiora run

# 高并行大仓库（10 worker）
fiora process --workers 10 --max-cost-usd 50

# PR / 增量：只看变更后没审过的（账本天然增量）
# 精确口径：scan 仍全量跑一遍规则通道（几秒级）；增量发生在判定层：
# 已有结论的候选不重判、未变更文件不重调模型，账本是「谁审过什么」的唯一来源。
fiora scan && fiora evidence && fiora process && fiora report

# 补丁修复后验证
fiora verify diff --pre v1.2.0 --post v1.2.1

# 规则改动后回归（必须不掉分）：先跑零模型下限门禁，再跑判定通道
fiora eval --corpus corpus --rule-only --out rule-floor.json
fiora eval --corpus corpus --out metrics.json
```

## 退出码

`0` 成功；`1` 错误（原因见 stderr）。成本上限中断属可续跑的正常停止。

## 故障排查

| 现象 | 处理 |
|---|---|
| `pi binary not found` | `fiora init` 自动引导；或 `export FIORA_PI_BIN=$(which pi)` |
| `opengrep: download failed` | 网络到不了 GitHub 时：把 opengrep 二进制放到 `~/.fiora/runtime/opengrep` 或加入 PATH |
| 模型鉴权失败 | `fiora init --api-key <key>`；或确认 `--api-key-env` 指向的环境变量已设置 |
| 判定输出个别损坏 | 已内建容错：结论同义词归一、坏条目进拒答日志；整批失败时看 stderr |
| 想换模型重跑 | 改 `config.json` 或 `--model`，直接 `fiora process`，按稳定身份合并，旧结论不丢 |
