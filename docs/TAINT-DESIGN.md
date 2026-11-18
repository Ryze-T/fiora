# 层 2 设计：轻量调用链引擎（cross-function taint / call-chain）

> 状态：设计定稿，待实现。层 1（opengrep taint 规则）已交付并入 builtin。
> 实测边界驱动本设计：opengrep taint 同函数 ✅ / 跨函数 ❌（精确 source 复验）。

## 1. 目标与非目标

**目标**：把「source → 中转 → sink」的追踪从函数内扩展到**同仓库 2~3 跳**，产出两类消费物：

1. **候选确证**：候选附带 `call_chain`（from→to 逐跳 file:line + quality），
   判定从"从零追链"变"确认/修正预追链"（省 token、稳 verdict）；
2. **挖掟能力**：覆盖 pattern/taint 都够不着的形态，自定义包装函数
   （`runCmd(x)` 内部才调 `exec.Command`）、工厂构造（他处 new、此处 Run）、
   getter 间接流。

**非目标**（刻意不做，精度换速度）：
完整 points-to / 虚分派解析 / 跨仓库 / 泛型实例化展开 / 并发别名。
误报收口由 LLM 判定层承担（判定契约本来就是干这个的）。

## 2. 架构

```
fiora-evidence（新模块 callchain）
  ① 解析层    tree-sitter（go 起步）→ 函数清单（名字/形参/收发器/调用点）
  ② 索引层    调用图：caller fn → (callee name, arg positions, file:line)
               解析规则：同包直呼 → 跨包限定名 → 同名唯一候选 → 接口方法留 inferred
  ③ 摘要层    函数摘要（每函数一条）：
               - param_i → sink_k          （形参 i 流到 sink k）
               - source_j → retval         （source 流到返回值）
               - param_i → call_arg(callee, m) （形参透传）
  ④ 组合层    候选 sink 反向 BFS 2~3 跳：
               sink ← 摘要 ← 调用点实参 ← 上层摘要 ← … ← source
               产出 CallChain { hops: [{from, to, file, line, quality}] }
```

## 3. 数据结构（fiora-core types 增量）

```rust
pub struct CallHop { pub from: String, pub to: String, pub file: String,
                     pub line: u32, pub quality: ChainQuality }
pub enum ChainQuality { Traced, Inferred }   // 语义：Traced=名字+参数位闭合，Inferred=启发式
pub struct CallChain { pub hops: Vec<CallHop>, pub complete: bool }  // complete=source端已闭合
```

- 挂载点：`Evidence.call_chain: Option<CallChain>`（schema 已有位置，实现它）。
- quality 诚实分级与验证三级同构：Traced 可信、Inferred 仅供 judge 参考。

## 4. 与各层的接口

| 消费者 | 输入 | 效果 |
|---|---|---|
| fiora-evidence 装配 | 候选 sink | 预追链写入 evidence.call_chain |
| judge 协议 | evidence 中的 chain | 「确认或修正这条链」替代「自己从零追」；chain.complete=false 的候选必须人工补链 |
| 语义探索 | 未闭合链/Inferred 跳 | 作为狩猎假设来源（"这个 Inferred 跳值得看"）|
| 层 1 taint 规则 | （反向）候选含链 → taint-verified 标记 | triage 优先级信号 |

## 5. 语言与里程碑（✅ 全部交付）

- ✅ M1：Go，解析+索引+摘要+组合，9 例校准验收（包装/跨包/双层/工厂/字段注入/
  双助手/getter/双层 getter/三跳透传）全过；
- ✅ M2：Python，保守推断（同名直呼 + 模块路径），2 例验收全过；
- ✅ M3：Java/TS，方法/箭头函数/字段注入形态，2 例验收全过。
实现注记：语言差异只在抽取层（tree-sitter per-lang → 统一 IR）；
复合表达式（数组/对象/推导式/三元）必须分解，否则字段注入传播断链
（TS `c.args=[...c.args, a]` 实测教训）。

## 6. 验收（用漏挖型校准语料，层 2 前后 recall 对比）

专挑 pattern/taint 必漏的形态各 3 例：

1. 包装函数：`runCmd(x)` 在 util 包内调 `exec.Command`，调用方带污点；
2. 工厂构造：`newCmd()` 返回 `*exec.Cmd`，调用方 `c.Args=...; c.Run()`；
3. getter 间接流：`cfg.UserInput()` 透传三跳到 sink。

**验收线**：这 9 例中 call_chain quality=Traced ≥ 7，且判定层引用链证据后
verdict 漂移显著下降（对照实验：同批 finding 有链/无链各判一次）。

## 7. 风险与对策

| 风险 | 对策 |
|---|---|
| 同名误配（Go 接口/工厂）| quality 降级 Inferred，宁可漏标不假标 |
| 仓库大索引慢 | 索引只建"候选 sink 两跳可达"的子图（按需展开，非全仓全图）|
| 树解析失败的文件 | 跳过并在 evidence 标注 `chain: unavailable`（诚实降级）|
