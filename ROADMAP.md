# Fiora 待办（持久化提醒）

## ✅ 异构栈试点 ×3， 已全部攻克（2026-11-03）

**目标**：证明部署+验证流水线的泛化性（机制层已证，过程层需多样栈实证）。

| 试点 | 选型候选 | 证明什么 | 状态 |
|---|---|---|---|
| Node | n8n（npm 工作区真实应用） | ✅ 部署 Agent 修启动至健康 + 鉴权边界探针 + 8 条踩坑 |
| Java + DB | Keycloak + Postgres（多沙箱互联） | ✅ schema 真实迁移入跨沙箱 PG（tcp 通道实证） |
| Go 源码编译 | Caddy（go install → 静态二进制 → 服务） | ✅ 全链打通（工具链自动升级场景也覆盖） |

**验收**：每个试点 `fiora verify-env --agent` 全自动到健康 + ≥1 条 PoC 实锤 + boot recipe 沉淀。
**完成即兑现泛化性承诺**（DESIGN.md §6.0 的 B 门槛）。

> 注：`verify-env` / `prove` 命令已随 2026-11 引擎化重定位移除（环境验证归 Agent 工作台，
> 见 DESIGN.md §6）；本节作为历史验收记录与适配知识保留。

### 🎯 攻克记录：OpenShell 网络/沙箱边界的三大根因（全部实证修复）

1. **规则冲突静默拒策略**：同 host:port 的多条规则必须设置一致，否则更新被拒（表现为
   "Policy unchanged"），试点失败时叠加变体规则反而把策略毒化了。
   **修**：每 host:port 一条规则、设置一致；换协议先 `--remove-endpoint` 再加；多端点用一条 YAML 规则。
2. **IPv6 socket 绕过 IPv4 合成映射**（Java/Go 默认 IPv6 优先）：AF_INET6（含 IPv4-mapped）
   连接 EACCES，IPv4 直连正常（对照实验：AF_INET6 denied / AF_INET PONG）。
   **修**：强制 IPv4（Java `-Djava.net.preferIPv4Stack=true`；Python 天然 AF_INET）。
3. **argv[0] 精确匹配 + 二进制路径漂移**：Go 工具链自动升级后以
   `pkg/mod/.../toolchain@*/bin/go` 新路径执行，旧规则失配。
   **修**：`--binary` 支持 glob（文档示例 `'/usr/lib/postgresql/*/bin/psql'`），
   工具链类用 `.../toolchain@*/bin/go` 通配。
+ 文件系统公理：可写=工作区+/tmp；`/opt` 默认只读（组件自改目录要显式加 read_write）。


## 其他已知未做项（不阻塞主线）

- 部署 Agent 硬化：当前 host 驱动 pi + 指令审计；in-sandbox pi（Agent 本体进沙箱）为终极形态
- L5 评测语料：ARVO / CyberGym 真实漏洞导入
- 分布式 executor（多机 fan-out，接口已留）
- 增量扫描（只重跑变更文件的规则通道）：当前增量发生在判定层，扫描每轮全量；
  真做需要把文件内容哈希记进账本并在规则集版本变化时整体失效

## 异构栈试点结果实录（2026-11-03，泛化性验证）

| 试点 | 结果 | 正向证据 | 卡点（工具集成 gap） |
|---|---|---|---|
| A Node（n8n） | ✅ 完整 | 部署 Agent 自主修启动至健康；鉴权边界探针 200/200/401；**8 条踩坑沉淀 boot recipe** | — |
| B Java+DB（Keycloak+PG） | ◐ 半闭环 | Postgres 沙箱就绪、Keycloak 启动至 DB 验证阶段；**身份层 4 条知识**（root 镜像/uid 无 passwd/GID 0 拒绝/自定义 run_as_user 破坏 supervisor） | ① OpenShell 裸 TCP 跨沙箱代理匹配粒度（IPv6-mapped 合成 IP 不回配主机名规则）；② 自定义策略覆盖默认后 bind 权限丢失 |
| C Go 源码编译（Caddy） | ◐ 半闭环 | 镜像/身份/PATH/网络白名单配方齐；Go 模块网络面打通至工具链下载（规则生效实证） | ③ 合成 IP 跨策略版本轮换（198.18.0.2→0.6）致主机名规则失配 |

**结论**：部署/验证**过程**在三种异构栈上泛化成立（同一套配方方法论产出各自 boot recipe）；
两个卡点同属 OpenShell 网络代理边界（合成 IP 匹配），记为适配层待办，
建议上游反馈 + 本地用「策略定稿后一次性加载」规避。

### 试点沉淀的通用 boot recipe 知识（任何项目适用）

1. 沙箱可写范围 = 工作区 + /tmp（/opt、/var/lib 默认只读，数据目录必须落 /tmp 或工作区）；
2. 镜像身份必须 uid:gid 均非 0 且 uid 有 passwd 条目（root 镜像加 USER 层；postgres 需裸 initdb 绕过假定 root 的 entrypoint）；
3. 策略按 argv[0] 真实路径匹配（符号链接不算数，java 在 JVM 目录下）；
4. 网络默认全禁，白名单按主机名:端口:协议（rest=TLS 终结，tcp=透传）逐二进制放行；
5. 非登录 shell 不加载 profile（用绝对路径，如 /usr/local/go/bin/go）；
6. 策略变更后合成 IP 会轮换，规则尽量一次配齐再启动依赖网络的构建。
