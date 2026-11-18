---
name: fiora
description: 证据挂载式 AI 代码审计插件（Agent 工作台背后的引擎），仓库级全链审计（扫描→AI 判定→复核→报告）。当用户要审计一个仓库/项目整体、要出安全审计报告、要漏洞复现与 PoC、审计评测打分、或明确提到 fiora 时使用。触发词：fiora、审计这个仓库/项目、安全审计报告、代码安全审计、RCE 分析、漏洞复现、PoC、安全评估报告。支持 Go/Python/Java/JS/TS。**定位**：fiora 负责扫描/判定/报告（纯确定性引擎）；环境启动与漏洞真值验证由调用方工作台 Agent（pi 或其他 coding agent）负责，验证方法见第二章。
---

# Fiora：Agent 工作台背后的代码审计插件

**产品定位**：fiora 是插件引擎，不是独立验证器。

```
工作台 Agent（你，pi 等 coding agent/coding agent）
 ├─ 调 fiora 扫描/判定 → 报告        ┐
 ├─ 审核报告（判定质量/座次/可信度）  │ 验证职责
 ├─ 启动环境逐一验证漏洞真值         │ 在你这边
 └─ fiora verify record 回填结论     ┘
fiora（纯确定性引擎）
 ├─ 扫描：规则下限（recall 100% 门禁）+ 语义上限（0day 狩猎）
 ├─ 判定：六问反驳 + RCE 机械核查 + 已知洞消歧
 └─ 报告：默认只给高危及以上 + 机器可读验证清单
```

设计公理：**规则通道=下限**（同类静态工具能挖的必须全挖到），**LLM 语义通道=上限**（狩猎协议挖组合缺陷与 0day）。工具负责查全，AI 负责判准，Agent 负责验实。

## 安装

```bash
# ① 预编译（推荐）：四平台 tarball 见 https://github.com/Ryze-T/fiora/releases
curl -fsSL https://github.com/Ryze-T/fiora/releases/latest/download/fiora-linux-x64.tar.gz | tar xz
export PATH="$PWD/fiora-linux-x64:$PATH"   # macos-arm64 / macos-x64 / linux-arm64 同理

# ② 或源码构建
cargo build --release && export PATH="$PWD/target/release:$PATH"
```

命令参考 → [docs/USAGE.md](docs/USAGE.md)；设计原则 → [DESIGN.md](DESIGN.md)。

---

# 第一章 · 调用章（fiora CLI 面）

**输出约定**：所有视图**默认只看高危及以上（CRITICAL/HIGH）**，要看全部必须显式 `--severity all`。低危仍落账（覆盖率不变），只是不进默认视图。

**深度永远全量**（覆盖率是产品承诺，不设档位、不问用户）；`--severity high|all` 是唯一资源阀。评测/复核/复现/验证一律只对高危及以上投入。

| 用户诉求 | 命令 |
|---|---|
| 完整审计一个仓库 | `fiora init --root <repo> --model <id>` → `fiora run --root <repo> --workers 4 [--severity high\|all]` |
| 只要规则扫描（免费、确定性） | `fiora scan --root <repo>` |
| 语义深挖（0day 狩猎，多轮回路） | `fiora explore --root <repo> --budget 10 --rounds 2`（线索进 `.fiora/hunt.md`） |
| 组合狩猎（A+B 成链的 super-0day） | `fiora compose --root <repo>`（run 在链组装后自动触发） |
| 查判定/看某个发现怎么判的 | `fiora trace <finding-id> --root <repo>`（fiora 原生审计轨迹） |
| 能力族座次（还有哪些 RCE/无条件的） | `fiora family [--family rce] [--severity all] [--json]` |
| 验证补丁是否修复（确定性差分） | `fiora verify diff --root <repo> --finding <id>`（pre/post 修订 shape 对照） |
| **回填验证结论**（Agent 验证后） | `fiora verify record --finding <id> --level live-prove\|trigger-prove\|code-proof\|disproved [--note ...]` |
| 生成复现材料起点 | `fiora lab scaffold --finding <id> [--lang python\|java\|go\|node]` |
| 项目画像（狩猎重点） | `fiora profile --root <repo>`（run 自动跑；`--refresh` 重提）|
| 环境体检 | `fiora doctor --root <repo>` |
| 规则库管理 | `fiora rules list` / `fiora rules add <file-or-dir> [--project]` |
| 按盲区起草规则（人工复核后入库） | `fiora draft-rules --root <repo> --model <id>` → `.fiora/rules-draft/draft.yaml` → `fiora rules add … --project` |
| 下限回归门禁（CI 用） | `fiora eval --corpus corpus --rule-only`（必须 recall 100%） |
| 生成报告 | `fiora report [--severity high\|all] [--out DIR] [--sarif f.sarif] [--fail-on high]`（HTML+JSON，默认高危） |
| CI 接入（需失败即红） | `fiora report --sarif fiora.sarif --fail-on high` → 有发现则退出码 1，SARIF 交 Code Scanning |

常用组合：

```bash
# 全链审计（init 一次，run 重复跑）
fiora init --root ~/code/proj --model openai/gpt-5.5
fiora run --root ~/code/proj --workers 4

# 审完看座次、挑重点、记审计轨迹
fiora family --root ~/code/proj
fiora trace 7b446197e54f --root ~/code/proj

# 报告（默认高危；--severity all 给全量）
fiora report --root ~/code/proj --out ~/code/proj/fiora-report
```

注意：

- 模型配置用 `fiora doctor --json` 读 config.json 的 models/profiles；API key 经 `fiora init --api-key`（或 `--api-key-env`）入钥匙链，**不要**手抄进 config.json；
- `--workers` 判定并行；大仓（>5k 文件）建议 4；
- 预算信息看 `fiora status` 的 cost 字段；
- 判定契约：TP 必有 impact + preconditions（含权限获取成本）+ repro_pack + 证据链；候选 100% 落账。

---

# 第二章 · 验证章（Agent 环境验证方法论）

**你的职责**：fiora 的判定是静态的（判定 ≠ 验证）。报告里的每条 TP 都需要你启动环境验证真值。fiora 给复现材料，你跑真值。

## 2.0 流程连续性（铁律：不问、直接做）+ 环境开关（docker）

**环境开关（先查再动）**：主动验证（动态部署 / canary 实测）**只在 docker 可用时启动**。
用 `fiora doctor` 的 `docker` 项（或 `activeVerification` 字段）判定；
detail 标「需 sudo」时用 `sudo docker` 起实验环境（doctor 已确认免密 sudo 可用）：

- **docker 可用** → 报告产出后立即进入主动验证（读清单 → 起环境 → 逐条验证 → 回填）→ 交付终表；
- **docker 不可用** → **不启动主动验证**（连尝试都不用）：交付报告 + 验证清单即止，
  在交付说明里注明「动态验证待环境就绪」，清单留给后续接力；
  **禁止代替用户安装 docker、禁止改动用户的环境**。装不装是用户的决策，
  你不提"我来帮你装"，最多在交付说明里客观写一句"主动验证需 docker"。

docker 可用时的连续性铁律（不问、直接做）：

```
报告产出 → 立即进入验证（读清单 → 起环境 → 逐条验证 → 回填）→ 交付终表
```

- **不要问用户"要不要复现/验证"**，那是流程的固定后半段，不是可选项；
- 只有两种情况才停下来找用户：被硬阻塞（缺凭据/缺资源/授权边界不明）、或全部验证完成；
- 环境验证是本职不是附加分：报告交付 = 报告 + 验证徽章 + 验证终表。

## 2.1 验证纪律（铁律）

1. **canary 无害化**：载荷只写标记文件/回调（`echo PWNED > /tmp/canary`），不取数据、不落 shell；
2. **一次性环境**：docker `--rm` / 用完即毁，不污染宿主机；真实代码**只读挂载**；
3. **正控往返**：先证正常数据路径通，再证攻击路径通。拦截缺失是安全缺陷，不是测试假象；
4. **桩化边界声明**：只桩非漏洞重依赖（torch/zmq/云 SDK），漏洞函数必须真实代码；实验记录里写明桩了什么；
5. **即用即毁**：实验完 `docker rm -f`，环境清单不留在世界上。

## 2.2 验证等级（诚实三级 + 证伪，回填用语）

| 等级 | 含义 | 回填 |
|---|---|---|
| `live-prove` | 真实执行实锤（载荷在目标上执行成功）| `fiora verify record --level live-prove` |
| `trigger-prove` | 触发实锤（真实代码加载执行，canary 无害化）| `--level trigger-prove` |
| `code-proof` | 代码级论证（静态证据链完整，未动态执行）| `--level code-proof` |
| `disproved` | 证伪（验证推翻判定）| `--level disproved --note <证据>` |

判定只能给到 code-proof；**live/trigger 级必须由你跑出来**。不夸大：跑不出来说跑不出来。

## 2.3 验证就绪清单（机器可读入口）

`fiora report` 同时产出 `report.json`，内含 `verificationChecklist`：每条 TP 一条
验证任务（族/档位/CWE/前置/repro 材料/建议验证等级/打法提示）。**优先按清单驱动
验证**，不要从 HTML 手工抓。

## 2.4 lab 模式（实战沉淀的标准流程；需 docker，见 2.0 开关）

```bash
fiora lab scaffold --finding <id> --out /tmp/xxx-lab    # 生成起点材料
# 产物：README（纪律清单）+ Dockerfile + stub_loader.py + lab.py + run.sh
# ⚠️ 模板是起点不是终点：按目标栈改桩边界、补依赖、填载荷，当场修模板 bug
REPO_PATH=<repo> bash run.sh                            # 一次性容器跑实验
```

同构流程（实战验证的打法）：

1. **加载真实代码**：`importlib` 按文件加载被测模块，绕开包 `__init__` 的重依赖链；
2. **桩化重依赖**：通用 `MetaPathFinder` 拦缺失模块，属性访问全返占位对象；
3. **构造攻击载荷**：按 sink 语义（pickle REDUCE gadget / 路径穿越 / 注入串）；
4. **canary 断言**：载荷执行 → 标记文件落盘 → `[RCE ]` 实锤；
5. **正控往返**：正常 encode/decode 等值校验，证通道语义真实。

## 2.5 组合链验尸（"能不能 XX 触发"类问题）

被问"能否外部请求/SSRF/组合触发"时，逐链验尸并给死因：

```
候选链 → 字节级语义分析（协议格式匹配吗？）→ 解码器路径（经过目标 sink 吗？）→ 通/断 + 死因
```

每条候选链给死因，结论才立得住。「断」和「通」同样是有价值的审计产出。

## 2.6 报告审核要点（拿到报告先看什么）

1. **RCE 定性查 loader 语义**：impact 声称 RCE 的，看有没有引用 sink 语义（`weights_only`/白名单/过滤器）。无据 RCE 已被机械降级，但你要复核降级是否合理；
2. **已知洞标注**：impact 带「已知洞消歧：CVE-xxxx」的，先消歧再决定是否单独披露；
3. **座次优先**：`fiora family` 档位 0-1 的先验（无条件 > 网络可达）；
4. **判级可信度**：live-prove > trigger-prove > code-proof > 未验证（判定 ≠ 验证）；
5. **前置条件原文读**：账本 preconditions 是可达性的唯一真源，别只看 severity。

## 2.7 验证结论回填

```bash
fiora verify record --root <repo> --finding <id> \
  --level trigger-prove --note "lab 实测：canary PWNED 落盘，正控往返通过"

# 复验推翻了初判级就一并校正（不校正报告永远按初判级展示）：
fiora verify record --root <repo> --finding <id> --level code-proof \
  --severity medium --note "复核降级：触发面限于构建期"
```

回填后报告自动带验证徽章；disproved 的发现不要删，保留并标注（审计轨迹完整 = 可信度）。

---

## 输出与文风

- 报告文风：中文短句分点（每句 ≤25 字），先结论后细节；
- 报告产物落**可见目录** `fiora-report/`；账本数据在 `.fiora/`；
- 对用户汇报时给座次与验证等级，不要倾倒全量清单。
