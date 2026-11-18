# Changelog

本项目的显著变更记录。版本号遵循 [SemVer](https://semver.org/)：
0.x 阶段 minor = 破坏性/大功能，patch = 修复与小改进。

## [Unreleased]

## [0.2.0] — 2026-11-17

#### 评测基线（L5 全链 · 双冷跑 · 2026-11-17）

口径：`fiora eval --corpus corpus --model volc/ep-20261103154833-2j9wl`（默认
thinking；33 案例 / 36 条期望；含 revalidate 全流水线）。此后的任何改动
**不得低于本基线**（recall 必须持平、precision 不得掉出区间）。

| 指标 | 冷跑 1 | 冷跑 2 | 口径说明 |
|---|---|---|---|
| recall | **100%（36/36）** | **100%（36/36）** | 全链（规则+语义→判定→评分） |
| precision | **86%** | **86%** | 含 6 条未标注判定入分母（标注边界内下限） |
| AI-only 期望 | 1/1 | 1/1 | 规则不可见、必须靠语义/判定拿下的期望 |
| token 消耗 | 991,447 | 1,543,907 | 金额 provider 未回报（$n/a 为诚实标注）|
| 用时 | 18.5 min | 17.0 min | macos-arm64 |

稳定性判读：**分数维度双跑完全一致**（recall/precision/AI-only 逐项相同）；
token 消耗有 ~±28% 方差（LLM 采样路径不同），成本按区间看，不按点值。
无模型故障（两跑均 exit 0，无作废/无 refusal 异常）。


- **opengrep 自举下载加钉值校验**（供应链）：官方只发 cosign `.sig/.cert` 不发
  SHA256SUMS，此前 165MB 二进制直下不验字节，镜像/CDN/缓存投毒不可检出。现在
  源码内钉死 v2.0.0 四平台资产的 SHA-256（TOFU 锚定进评审），下载后逐字节校验、
  不符即拒装；`FIORA_OPENGREP_SHA256` 可供手动放置/新版本自证覆盖；无法钉值的
  移动目标（latest/API 发现）降为兜底并**显式告警未校验**（附 cosign 验签指引）。
  双态实测：正确钉值 → `(bootstrapped, sha256 已校验)`；错误钉值 → 全部候选拒装、
  runtime 目录不留残留；
- **多模型职责核实**：协议执行是 pi 运行时的契约（openai-completions /
  openai-responses / anthropic-messages / google-generative-ai 均在 pi 词表内实证），
  fiora 只做 models.json 路由 + 自洽凭据注入 + `--api` 覆盖，不重复做协议级
  兼容测试，文档如实声明职责边界；

### Added（环境开关：主动验证按 docker 能力启停）
- **`init`/`doctor` 环境自检含 node + docker**：node 是必需项（pi 运行时硬依赖，
  ✗ 时 doctor 退出码 1）；docker 是**能力项**，缺失只关闭「主动验证」，不判环境坏、
  不影响退出码。`doctor --json` 新增 `activeVerification` 字段（Agent 的动态验证开关）
  与每项 `required` 标记；
- **SKILL.md 验证章按 docker 开关分流**：docker 可用 → 报告后立即主动验证；
  不可用 → 不启动主动验证（连尝试都不用），交付报告+清单并注明「动态验证待环境
  就绪」。铁律：**禁止代替用户安装 docker 或改动用户环境**，装不装是用户的决策。

- **两个验证通道互踩数据**：`verify diff`（补丁态确定性对照）与 `verify record`
  （Agent 实测真值）写同一个 `finding.verification` 槽，工作台 Agent 跑一次
  `verify diff`，4 条 live-prove 实测记录被整体冲成 `fix-check/persisting`，
  status 验证覆盖率归零（第二轮动态验证实测事故）。现在差分结论独立落
  `.fiora/diffs/<id>.json`，finding 的实测记录永不被确定性通道触碰；
  `verify record` 的 `--severity` 校正同批落地。

### Added（工作台 Agent 实测补的两个入口）
- **`fiora verify record --severity <LEVEL>`**：复验结论常推翻判定层初判级（实测
  HIGH 应降 MEDIUM），此前无校正入口、报告永远按初判级展示；回填时一并校正；
- **`fiora status` 验证覆盖率视图**：`verify: X/N 已回填（live-prove · trigger-prove ·
  code-proof · disproved · 未验证）`，判定 ≠ 验证，交付口必须一眼看到验了几条。

### Fixed（工作台 Agent 实测批次：pi×SKILL.md 驱动 CLI 场景，2026-11-17）
- **`fiora report --out <目录>` 直接报错**：SKILL/文档契约写的是 `--out DIR`，
  实现却把 `--out` 当文件路径写，撞上「Is a directory (os error 21)」（工作台
  Agent 实测）。现在目录（已存在或以 / 结尾）就写 `report.html + report.json` 进去；
- **验证清单不随复验修正更新**：repro 材料被复验推翻后（实测：原触发前置经
  负控证明不可复现，真前置是另一个配置门），
  `verificationChecklist` 仍下发旧前置，照清单盲跑得假阴性。现在清单每条
  带 `verdictNotes`（复验修正/判定备注）与 `verification`（已回填结论），
  Agent 接力前先看到最新真值，不重复劳动；
- **lab 桩模板不支持子类化**：`stub_loader` 的桩属性返回实例，真实代码里
  `class CMakeExtension(stubbed.Extension)` 直接 `TypeError`（工作台实测当场修）。
  桩改为「可继承占位类 + 宽松元类」：子类化/实例化/调用链/isinstance 全通，
  `get()` 探针语义保持 None 且类级/实例级都能调；
- **类别词表归一**：判定层自由措辞产生 `pathtraversal/path_traversal/path-traversal`
  同概念三写法，报告分组与身份锚点被打散。入库单点保守归一（分隔符统一 +
  已观测同义变体），类别参与 finding_id 推导，旧账本同发现 id 会变化（0.x 接受）。

### Fixed（零知识外部用户实测批次，2026-11-17）
- **六个模型命令在标准安装下全部静默失效**：`init --api-key` 把 key 存进
  `~/.fiora/credentials.json` 后，只有判定通道把凭据注入 spawn 环境
  （`spawn_env → with_env`），`explore / compose / draft-rules / refine /
  enrich / localize` 裸 spawn，pi 报「No API key found for \<provider\>」直接
  退出，这六个通道整体空转，而且空输出被读成「会话成功、无发现」。实测
  实测：explore 的 plan 会话输出为空、759 个 sweep 会话全部「完成」且 0 产出。
  现在 `support::model_runner` 单点装配（pi 二进制 + 凭据注入，覆盖 CLI
  --model 与配置默认模型两个 provider），六个通道全部换用；
- **pi 非零退出被无视**：缺 key 时 pi exit 1 + stdout 仅 138 字节 session 头 +
  stderr 说明真相，`run()` 只在「stdout 完全为空」时才报错，于是「没跑」被
  当成「跑了、无发现」。现在非零退出必错（带 stderr 摘录）、零回合会话
  （无任何 message_end）必错、空 stderr 也如实标注 `<no stderr>`；
- **explore 的覆盖核算是假账**：`swept N modules` 在发牌时就计数，会话失败
  也照报（实测 5 分钟「扫过 6067 模块」，实际每个会话都死于缺 key）。现在
  只有交回逐模块覆盖账或带回发现的会话才计入 swept，失败/空手会话分别计
  `sessions_failed / sessions_unverified` 并在输出与 hunt.md 里如实列出；
- **证据装配 O(n²) 回归**（「无损精简批次」删全仓索引缓存留下的）：
  `cmd_evidence` 逐文件调 `pre_assemble`，而它每次都把全仓 tree-sitter 解析
  一遍，6k 文件级仓库 × 395 次 ≈ 255 万次解析（实测 12 个/分钟，纯
  evidence 阶段就要 ~1.5 小时）。现在一次收集全部候选、一次建索引；已装配
  （evidence_id 已在）的候选跳过，断点续跑不再全量重算；
- **opengrep 自举下载在 API 限流下全灭**：唯一可靠路径是未鉴权
  api.github.com 发现资产名（共享出口 IP 常态性 403），而降级直链把版本与
  命名配反了（`latest` 用 v1.33.1 的 manylinux 名、钉 v1.33.1 用 v2.0.0 的
  linux 名），实测 4 个候选全 404，`init` 卡在「download failed」。现在
  两代命名 × 全部 flavor 都进候选链（API → latest → 钉版本），命名按
  os/arch 别名枚举（含 macOS v2.0.0 的 `osx_arm64` 与旧版 `osx_aarch64`）；
- **`fiora doctor` 有 ✗ 也 exit 0**：CI 里 `fiora doctor && fiora run` 会带
  病运行。现在自检不健康即非零退出（JSON 的 `healthy` 字段不变）；
- **Node 版本门槛文档性错误**：pi 1.4.0 的 engines 是 `node >=22.19.0`，
  README/TUTORIAL 却写 ≥18/≥20，按文档装 node 18/20 会在运行时才炸。
  三处统一为 ≥22.19，并把 runtime.rs 的安装提示同步；
- **大仓库探索预算无预估**：`fiora run` 的 auto 预算 = 未覆盖文件/8 的会话数
  + 一半机动（大仓实测 1139 个模型会话），启动前没有任何成本提示。现在
  auto 预算 >20 会先报数并提示 `--explore <N>` 收敛 / `--explore 0` 跳过
  （旗标原本就有，但文档从没提）；USAGE 补 `--explore` 说明；
- **同 id 重复候选永远合不进账**：opengrep 的多 pattern 分支会重复命中同一行，
  同 (slug,file,line) 的候选被记成两条；账本合并只填第一条的 evidence_id，
  第二条从此每次 run 都重新装配、还拖着全仓索引重建（实测 17 条孤儿，
  每次 `fiora run`/`evidence` 白付 ~12 秒）。现在 normalize 源头归一
  （同 id 只留一条），账本合并填平所有同 id 条目并去重，顺带修正
  `fiora scan` 的候选计数（1201 → 1184，此前虚高 17）；
### Fixed（规则通道可信度批次：一条中文 message 曾让全部规则失效）
- **非 ASCII 规则文件让整次扫描静默失败**：OpenGrep 内嵌解释器按默认 ascii codec
  读 `--config` 文件，规则里任何一个中文字符（`message` 常是中文）都会抛
  `UnicodeDecodeError`，整次扫描 exit 2 + 空 stdout， 87 条规则一条都没跑，
  而 CLI 只看到「解析失败」。物化前统一转成 ASCII-only YAML（非 ASCII 标量写
  `\uXXXX` / 星平面写 `\UXXXXXXXX`，语义等价，仅丢注释）；转码失败直接报错，
  不带病上阵。`LANG` / `LC_ALL` / `PYTHONUTF8` / `PYTHONIOENCODING` 均无效，
  只能在数据侧解决；
- **OpenGrep 的错误不再被当成「干净扫描」**：规则被拒时 OpenGrep 仍 exit 0 并输出
  格式正确的 JSON（只是不含该规则的结果），此前会被读成「0 发现」。现在
  `errors[]` 里任何 `level=error` 条目都判为扫描失败并带上原文摘录（空 stderr 也
  不再输出空白错误），`level=warn` 打印「N 条分析告警」并逐条给出
  `文件:行 — 原因`（只报数字等于让操作者自己猜哪个文件没分析完）；
- **内置规则 `floor-sqli-ruby` 一直是被拒的**：`$M.where("... #{x} ...")` 在 Ruby
  pattern 里是语法错误（插值里不能省略表达式），整条规则从未生效。改成
  `pattern-regex` 匹配 `where("<含插值>"）` 的真实形态，并注明为什么不写成
  pattern；
- **修好的内置规则被旧副本遮蔽**：`init` 会把内置规则复制成 `~/.fiora/rules/builtin/`
  的可编辑副本（它们优先级更高），于是新版二进制里的规则修复永远被旧副本投票
  否决。新增 `sync_builtin_copies`：按 `.corpus-state` 记录「我们上次写进去的
  内容哈希」，未被改动的副本随二进制升级刷新，被人工改过的保留并逐条提示
  （旧版本安装无状态可查，先备份成 `<name>.bak` 再刷新，不丢字节）；
- **「同 id 高级覆盖低级」此前只是内存里的说法**：OpenGrep 对多个 `--config`
  目录取**并集**，同 id 不会互相覆盖；而物化把三级文件原样全落下去，于是团队
  既收窄不了、也关不掉一条内置规则（实测：用户级改写 + 内置版本同时命中）。
  现在级别裁决在内存里做完，物化只落**胜者**，被遮蔽的规则根本不到引擎手上；
- **同一级目录里嵌套同名文件会互相覆盖**：规则名此前取裸文件名，`builtin/x.yaml`
  与顶层 `x.yaml` 在物化时写到同一个目标路径，后写的赢。改用相对路径命名并建父
  目录；
- **陈旧物化文件继续参与扫描**：每级物化目录在写入前清空，上一次运行留下的
  文件不能凭残留继续生效（规则删除后仍然命中）；
- **规则通道候选只增不减**：候选 id 是 (slug, file, line)，规则被删除或收窄后
  旧候选永远留在账本里，成为报告里的幽灵行、并继续被付费判定。规则通道改为对
  本轮扫到的文件持权威（`replace_rule_candidates`），语义通道候选仍按增量合并，
  `note` / `evidence_id` 对仍命中的 id 保留；顺带修掉「同一行被数两次」，
  内置语料与用户副本此前都进了引擎，`fiora scan` 的候选计数是真实值的两倍。

### Added（诚实性 / CI 集成 / 语言覆盖批次）
- **SARIF 2.1.0 导出**：`report --sarif <FILE>`，误报不进结果，按 `(file,line,id)`
  确定性排序，`partialFingerprints.fioraFindingId/v1` 让行号漂移不改身份，
  `enclosing_fn` 落 `logicalLocations`，规则条目带 CWE + `security-severity`；
- **eval 输出诚实化**：per-case 与汇总行单独打印「未标注判定 N 条」，precision 的
  分母包含语料未标注的真实问题，读作标注边界内的下限；
- **eval 匹配口径**：同文件 + sink 命中后，类别只要同关注面（access / injection /
  execution）即算命中，判定层写 `session-exposure`、基准写
  `broken-access-control` 不再记漏报；跨关注面仍严格区分；
- **eval 类别词表**：授权面单独成族（`authz`：missing-authorization /
  broken-access-control / idor / permission…），超族把鉴权+授权并为 `auth-mega`；
  判定层换个叫法不再记成漏报（真阳性被词表选择吃掉）；
- **语料真实化（Node）**：8 个 JS 案例补齐 `package.json`（真实依赖 + start 脚本，
  判定层不再以「服务无法启动」推翻可达性）；`broken-access-js` 补登录写入路径，
  `dumpSessions` 泄的是真实会话，且如实标注 `visible_to_rule: true`（规则确实
  命中「路由无中间件」这一层）；
- **provider 错误不再伪装成「模型拒绝」**：pi 在鉴权失败/限流时仍然 exit 0
  且事件流合法，只是 content 为空。`parse_event_stream` 现在收集
  `stopReason=error` 的 `errorMessage`，空回答 + 有错误直接 `PiError::Failed`；
  `fiora eval` 进一步把「模型/运行时故障」与「质量下降」分开记账，出现硬故障
  就作废本次评分并退出非零（此前会把 key 失效读成召回归零）；
- **零模型交付物不再挂假作者**：`run --no-ai` 的报告此前直接读账本里的
  `audit-meta.json`，把上一轮 AI 的模型名写成这份 HTML 的生成者。现在
  「本次交付方式」与「判定结论来自哪一轮」分开写：零模型交付署名
  `零模型交付（scan + evidence）`，并注明「其中 N 条判定结论来自账本既有记录
  （模型 X），未再次调用模型」；没有判定结论时明说「未产生任何判定结论」。
  新增 CLI 溯源契约测试（`crates/fiora-cli/tests/provenance.rs`）；
- **语言分派收敛到单点**：调用链索引此前有两处 `if rel.ends_with(..)` 分派，
  未知后缀（`.rb`、`.jsx`…）落到 TypeScript 语法上硬解，静默产垃圾符号。
  现在只有 `grammar_for()` 一个分派点，`.jsx/.tsx` 走 TSX 语法（TypeScript 语法
  不认 JSX 标签），不支持的扩展名如实进 `unparsed` 而不是猜着解析；
- **契约违约走专用修复轮**：判定输出是合法 JSON 但违反契约（真阳性缺 impact /
  PoC / 身份锚点）时，此前复用「不是 JSON」的修复提示，模型原样重发，一份真阳性
  被降级成 refusal（实测两个 open-redirect 案例双双重演）。现在把违规点回传，
  并要求「补不齐就诚实降级为 uncertain」，两例复验均转为 1/1 命中、0 refusal；
- **缺字段的发现走同一条修复轮**：模型偶尔漏写必填字段（实测：`severity`
  漏了、其余全对），此时回复是**合法 JSON**，走不到「不是 JSON」的修复分支，
  逐条反序列化失败直接把一条真阳性丢进 refusal 日志（`py-api` 案例两轮复现：
  2 条期望全丢）。现在这类「合法 JSON + 缺字段」与结构性违约同等对待，把 serde
  的原话回传，让模型补字段；只在修复结果确实少了 refusal 时才采用，修不回来就
  保留原输出并照实记 refusal，不静默放过。新增回归测试
  `a_finding_missing_a_required_field_gets_one_repair_round`（去掉修复轮即失败）；
- **反泄漏契约不再被缩写绕过**：判定输出写 `conclusion: "tp"` 时此前只做校验、
  再用原始字符串比 `"true-positive"`，身份锚点 / 证据 / impact / PoC 四道门被跳过；
  现在以解析后的结论为准（`tp` 与 `true-positive` 同权）；
- **删掉全局可变状态**：`CHAIN_CACHE`（`Mutex<Option<(root, CallIndex)>>`）是
  「每文件重建索引」时代的遗留，现在 `pre_assemble` 一次接收全部候选，索引在函数内
  构建一次即可，不再有跨调用缓存与锁中毒风险；
- **删掉只写不读的 `Finding.created_at`**（时间已在 run / analysis 记录里，报告与
  SARIF 都不读它）；
- **CWE 映射可辩护**：SARIF 规则条目只按 category/slug 精确/最长匹配取 CWE
  （`cwe_from_category`），不再拿描述关键词猜；`nosqli` 不再被 `sqli` 抢成 CWE-89，
  `brute-force` 不会被 `rce` 抢成代码注入；结果级启发式 CWE 单独标为 `cweHint`；
- **CI 门禁退出码**：`report --fail-on <LEVEL>`（`all|info|low|medium|high|critical`），
  与展示口径共用同一套 `severity_threshold`；非法值报错而非静默降级；
- **审计溯源落到账本**：新增 `AuditMeta`（`.fiora/audit-meta.json`，append-only 记录
  阶段/模型/严重度范围），报告的 method/agent/scope/方法说明由账本推出，
  零模型跑就说零模型，不再硬编码「沙箱实测」；
- **Kotlin 独立抽取器**：`.kt` 改走 `tree-sitter-kotlin-ng`；此前用 Java grammar 解析
  Kotlin 会静默抽出错误函数表（调用链断裂且不报错）；
- **覆盖优先的 explore 预算**：`sweep_sessions()` 先按未覆盖模块数算盲扫会话，
  hypothesis 用额外预算（`sweep + ceil(sweep/2)`），`hypotheses_dropped` 显式报告；
- **评测口径可测化**：`ExpectedFinding.visible_to_rule`（`false` = 单文件规则看不见，
  如跨层租户越权/路由挂载缺鉴权）不进规则下限分母；候选通道 `precision` 报 `n/a`
  而非硬编码 1.0；新增 2 例「规则不可见」语料，CI 校验标注诚实性（规则若命中它们即失败）。

### Changed（无损精简批次：只合并重复实现，不减能力）
四项的共同点是「同一件事被写了多遍」，公开 CLI 契约、判定协议、报告版式、语料与
门禁全部不变。每一项都用逐字节对比证明行为等价，不是「看着差不多」。
- **evidence：五种语言的抽取器收敛成一次遍历 + 一张差异表**（`callchain.rs`
  1678 → 1371 行，-307）：`struct LangSpec` 把语言差异从五份控制流下沉成五张常量表，
  `enum Sigil` 把语义不对称写成类型，`RecvThenArgs`（Go 保留接收者污点）/
  `ArgsOnly`（Python 只留实参）/ `Bare`（JVM/Kotlin/TS 调用即 source）是**故意的
  不对称**，此前散落在五份 `if` 里靠人读；五个 `expr_from*` 收成一个 `expr_of`。
  验证：33 个语料案例各跑 `scan` + `evidence`，重构前后 `.fiora/` 产物逐字节一致
  （仅 `audit-meta.json` 时间戳不同）。
- **CLI：一个仓库句柄替代十八处同样的三行前奏**（`support.rs` 112 行，
  `commands/*` 净 -9）：`Repo::open` 收掉 canonicalize + `.fiora` + 开账本，
  `findings/surface/config/write_json` 各归一处；此前 `list_finding_ids` →
  `load_finding` 的循环在 6 个命令里各写一遍、`surface.json` 手读 3 处。
  这一项几乎不省行数，价值在「四种读取各只有一份实现」，不假装是行数胜利。
- **判定提示词变成提示词文件**（`prompts.rs` 506 → 277，-229）：内置文案搬到
  `crates/fiora-processor/assets/prompts/*.md`，`include_str!` 编译期内嵌，与用户
  覆盖（`<fiora_home>/prompts/*.md`）从此是同一种产物；`prompts.rs` 只剩装配。
  验证：临时 dump 全部 13 个渲染结果（两档 severity、全部画像车道）`diff -r` 无差异，
  用于 dump 的临时测试已删除。
- **实验室载荷模板变成文件**（`lab.rs` 405 → 146，-259）：14 个产物（README、
  4 个 Dockerfile、桩加载器、4 个探针主体、4 个 run.sh）落到
  `crates/fiora-cli/assets/lab/`，探针主体读起来像探针而不是转义块。
  验证：`fiora lab scaffold --sink os.system --file pkg/x.py` 四种语言各跑一遍，
  20 个产物 `diff -r` 一致。
- **报告渲染：一份外壳，不是六份**（`fiora-report/src/lib.rs` 841 → 866，+25）：
  卡片头部收成 `card_shell`（真阳性卡与误报否决卡本只有判定徽章与卡体不同）、
  表格头收成 `table`、mermaid 容器 / 节点 / 连线各收成一个函数、严重度徽章收成
  `sev_chip`（并把同源的 `sev_class` + `sev_label` 两个 match 合并为 `sev_marks`）、
  验证徽章收成 `chip_with_stamp`、列表项收成 `li` / `li_list`、`file:line` 收成
  `loc`、「标签 + 可复制代码块」收成 `code_step`；`deployment_matrix` 的
  「形态 → 处置建议」从 `match label` 改为数据表。**行数是涨的**，共享 helper 带注释，
  但每类拼装从 2~15 处重复降到 1 处实现，改版式时不会再漏改某一张卡。
  验证：6 份真实报告（NodeGoat 36 条发现、`rce-eval-js`、`cmdi-taint-args-go`、
  `xss-node-innerhtml`、`openredirect-node`、`render_demo` 样例）重构前后渲染产物
  逐字节一致（`generated_at` 时间戳归一化后 `cmp`）。
- 合计：四项无损合并把 `src` 从 14930 压到 14126（**-804**）；同一批次之后又落了
  三处诚实性修复（评测 severity 口径、缺字段修复轮、报告渲染合并），当前
  14930 → 14235（**-695**，其中报告合并本身 +25、缺字段修复轮 +24，两者都是
  「用十几行换一处唯一实现 / 一次可修机会」，不假装是行数胜利）；测试数
  132 → 137（新增的是判定协议的负向测试，不是凑数）；`fmt --check` /
  `clippy -D warnings` / `eval --rule-only` 35/35 全绿。

### Changed（精简 / 单一实现批次）
- 删除第二套规则引擎（`generated.rs` + `generated-matchers.json` + 示例编译契约）：
  模型起草规则改走 `fiora draft-rules` → 标准 Semgrep YAML → 三级注册表校验 →
  人工 review 后 `rules add --project` 入库，**只有一套规则引擎**；
- 删除 `fiora probe`（与 `explore`/`scan` 职责重叠且无独有产出）；
- 时间戳统一到 `fiora_core::util::now_iso()`（删除 `verdict::chrono_lite` 别名）；
- 账本瘦身：`Candidate` 去掉 `tech_tags/priority/session_id`，`FileRecord` 去掉
  `digest/tech_tags`，`init_file(path)` 单参数，写而不读的字段全部移除；
- 文档与实现对齐：删掉不存在的 `--diff` / `rules stats` 表述（移入路线图）、
  `gen-rules` → `draft-rules`、README 测试数对齐实际。

### Fixed（全链评测驱动的效果批次）
- **汇点身份按「调用了谁」比对**：`cmdi-taint-args-go` 的 finding 写
  `(*exec.Cmd).Run`（声明类型），期望 token 写 `c.Run`（变量名），同一行同一调用
  被记成漏报。现在 sink 匹配多一条「末段相同」分支（`sink_tail`），前缀仍严格区分；
  `score_with_evidence` 的回落仍然只对**空** `sink_symbol` 生效，否则靠措辞
  蒙混也能命中；
- **eval 默认在 `--severity all` 范围测量**：交付口默认只看高危，但测量不该继承
  交付过滤器，判定层把一条真阳性评成 MEDIUM 时会被挡在账本外，记成漏报，测的
  其实是「两个过滤器是否一致」。`fiora eval --severity high` 仍可复现旧的交付口径；
- **语料入口真实化（本轮两例）**：`openredirect-node` 补 `app.js` 把 handler 挂到
  `/login/callback`（此前 `package.json` 的 `main: app.js` 指向不存在的文件，判定层
  有权说「入口只能推断」）；`xss-node-innerhtml` 补 `public/index.html` +
  `/api/profile` 路由（此前仓库没有任何 HTML 页面、`render()` 无调用点，判定层
  正确推翻了一条无源的 HIGH 级 DOM XSS，那是语料缺入口，不是判定层错了）；
- **畸形判定输出：给解析器原话，不做字符手术**：修复提示此前只说「不是合法 JSON」，
  模型原样重发同一份括号错位输出，一次修复机会白扔；现在把 serde 的
  `line/column + 原因` 喂回去。拒绝路径也**不**再尝试「删一个括号让解析通过」，
  实测那样能救回同批另一条无关发现，却把真正的真阳性吞掉；「救回一条别的」
  掩盖「丢了一条」比明确拒绝更糟。refusal 现在带解析器原话，坏在哪个字符可查；
- 截断容错：大批次判定输出被 token 上限截断时，逐对象抢救已写完的 finding
  （此前整批记为拒答、全部丢失）；
- TP 身份锚点强制：sink_symbol/enclosing_fn 为空的 true-positive 被契约拒绝
  （稳定 id 无法锚定，评测与报告也无法挂证据）；
- 评测口径：finding 通道与规则通道共用类别等价判定（归一化子串 ∪ 同族 ∪ rce
  超族），TP 无 sink_symbol 时回落到证据骨架的权威 sink；precision 分母改用
  命中发现的去重计数（一个发现匹配多条同族期望不再推高到 200%）。

### Changed
- 语料真实化：go-webapp 路由接线（入口可达）、真实形态凭据值、py-api 补全
  引用函数、tls 案例加调用方；headerinjection-go 重定位为 openredirect-go
  （Go net/http 净化 CRLF，真实风险是开放重定向，新增 floor-openredirect-go 规则）。

### 效果（全链评测；本批语料 33 案例 / 36 条期望）

**先说清这批数字是怎么来的**：涨的不是模型，是本轮修掉的**测量缺陷**，语料不成立
（入口没接线，判定层有权以「不可达」推翻）、汇点身份按 owner 拼写比对（同一个调用
被记成漏报）、eval 继承了交付口的 severity 过滤器（中危真阳性被记成漏报）、契约违约
复用「不是 JSON」的修复提示（真阳性被降级成 refusal）。修完之后才敢报下面这组数。

- **规则下限（确定性）**：recall **100%（35/35）**，零模型，逐次稳定，CI 门禁。这一行
  是函数，不是采样，每次跑都是这个值；
- **全链（采样，有区间）**：清空 `.fiora` 后连续五次全量跑得 recall
  **36/36 · 35/36 · 36/36 · 34/36 · 36/36**、precision **82% · 73% · 77% · 69% · 84%**、
  未标注判定 **8 · 13 · 11 · 15 · 7 条**、tokens **42~45 万**。前四次是修完语料/
  汇点/severity 之后、修「缺字段」之前的读数；第五次是修完之后的读数。
  两次非满分的成因不同，一次是模型输出格式，一次是引擎缺陷：
  `rce-eval-js`（第二次）模型把判定写成括号错位的 JSON，修复轮又写坏一次，按纪律
  记 refusal（不做字符级补救）；`py-api`（第四次）模型漏写 `severity`，合法 JSON
  走不到结构修复分支，两条真阳性被丢进 refusal 日志，这是引擎缺陷，已修
  （见 Added「缺字段的发现走同一条修复轮」），修复后重跑该案例得 2/2（单次观测，另有回归测试锁定行为）。
  所以**确定性部分**（规则下限）与**采样部分**（全链）在这里分开陈述：前者是函数，
  后者是区间，区间下沿由模型的输出格式决定，不是能力上限；
- 汇点身份修复的效果可以正面复验：`cmdi-taint-args-go` 修复前单例 4 次命中 2 次，
  修复后三次全量跑连续命中；
- precision 只能读作**标注边界内的下限**：分母里含语料没标注的真实弱点（未标注
  8~13 条，随跑次浮动，如 `dos`、`info-disclosure`、`logic`），不是绝对精度；
- **AI-only 期望**：五次全量跑均 **1/1**（规则看不见的多租户越权），这一通道
  同样受采样影响，写「五次观测」而不是「稳定 100%」；
- 冷启动复验（清空 `.fiora` 后重跑，不复用任何缓存判定；单次观测）：8 个案例
  （5 个 Node/Go + deser-java + ssti-py-jinja + tenant-spoof-go）全部 recall 100%，
  多租户越权仍是 1/1；
- 成本：单次全量 42~48 万 tokens，网关不回报金额 → 报告 `n/a/TP`（旧版把未记账
  写成 `$0.000`）；
- 语料诚实性：AI-only 期望 1 例，`broken-access-js` 如实标 `visible_to_rule: true`
  （规则确实命中「路由无中间件」这一层），标签跟测量走，不跟愿望走。

### 效果（历史，上一版口径）
- 规则下限：recall 100%（CI 门禁，不变）；
- 全链：recall 94%→97%（32/34 实测，+1 例经身份锚点契约修复后单例复验 100%；
  剩余 1 例 log-injection 实为语料入口未接线，本期已修）· precision 89%；
- 真实仓库验证：OWASP NodeGoat（2084★）全链审计命中其设计埋设的全部
  OWASP Top 10 漏洞面（13 条 TP：RCE/SSRF CRITICAL，NoSQL 注入/越权/明文密码/
  会话密钥硬编码/三类 XSS 等）。

### Removed（开源清理批次）
- 移除 OpenShell 沙箱自举（`ensure_openshell`）：环境验证已归 Agent 工作台
  （DESIGN.md §6 重定位），init/doctor 不再安装/检查第三方沙箱运行时；
- 移除零调用死代码：`deploy_prompt`（部署 Agent prompt 残留）、`exec_repro`
  （无调用方且执行模型生成命令）、`load_prompt_override`、`default_prompts_dir`、
  `Ledger::merge_tech_tags`、`Ledger::load_run`；
- 仓库卫生：预编译 tar.gz 与 corpus 运行态（484 个可再生文件）移出 git。

### Fixed
- **报告离线承诺落地**：mermaid 10.9.1 内嵌（仅含图报告携带）、移除 Google Fonts
  CDN 引用；此前离线打开时攻击链图不渲染。契约测试补离线性断言；
- 报告页内跳转：攻击链卡片带锚点、`getElementById` 解析目标、无空 href。

### Changed
- `localize` 继承容错回路（此前单批损坏会中断整个命令，现在逐条抢救）；
- refine/enrich 的坏批次不再整批丢弃（合法条目保留）。

### Added
- `PiRequest::simple` 构造器与 `run_json_with_repair` 容错回路（全 CLI 共用）；
- refine/enrich/localize 收敛为单一批次处理器（agent.rs 608→573 行，-191 行重复）；
- 开源配套：SECURITY.md / CONTRIBUTING.md / 本文件 / release 工作流 / fmt+clippy+recall 三门禁 CI。

## [0.1.0] — 2026-11 初版

核心闭环交付：双通道候选（OpenGrep 规则 + 语义探索）→ 证据预装配 →
triage/judge/revalidate 三段式判定 → 漏洞链 → 单文件 HTML 报告；
`verify diff` 确定性差分 + `verify record` 验证回填；`fiora eval` 评测回归
（语料，规则通道 recall 100% CI 门禁）；explore 并行会话与 hunt
plan/execute 分离；compose 组合狩猎；五族语义 guard 表与已知洞消歧。
