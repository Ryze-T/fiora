# 系统配置 Prompt（交给 Agent 执行）

把下面整段 prompt 丢给你的 coding agent（pi 等），它会把 fiora 配置到可用状态。
fiora 审计阶段的行为契约见 [SKILL.md](../SKILL.md)。

---

你是系统配置工作台 Agent。任务：在本机把 **fiora 代码审计系统**配置到可用状态，
交付一份配置终表。按顺序执行，每步的验收标准都要真的跑出来，不许口头确认。

**0. 收集配置项**（缺什么就问用户，不要猜）
- 平台自己探（`uname -s -m`）；
- 模型三件：判定模型 id（如 `openai/gpt-5.5`）、API key、自定义网关时的
  `base_url` + 协议（`openai-completions` / `anthropic-messages` 等）；
- key 只在第 3 步注入凭据库，不写入任何项目文件、聊天记录或日志。

**1. 安装二进制**（按平台选包：`fiora-linux-x64` / `fiora-linux-arm64` /
`fiora-macos-x64` / `fiora-macos-arm64`）

```bash
curl -fsSL https://github.com/Ryze-T/fiora/releases/latest/download/<平台包>.tar.gz | tar xz
curl -fsSL https://github.com/Ryze-T/fiora/releases/latest/download/SHA256SUMS.txt -O
sha256sum -c SHA256SUMS.txt        # macOS 用 shasum -a 256 -c
export PATH="$PWD/<平台包>:$PATH"  # 或挪去 /usr/local/bin
```

验收：`fiora --version` 有输出。拉不到 release 时退源码构建
（`cargo build --release`，产物 `target/release/fiora`）。

**2. 前置：Node.js ≥ 22.19**（硬前提，内嵌 Agent 运行时需要）
`node --version` 不满足就装（nvm / apt / brew 均可）。docker **不必装**：
它只是「动态验证」的能力项，装不装由用户决定，**不要代装**。

**3. 初始化**

```bash
cd <目标仓库>
fiora init --model <模型 id> --api-key <key> [--base-url <网关> --api <协议>]
# key 想留在用户环境：先 export MY_KEY=… 再 --api-key-env MY_KEY
```

init 自动完成：三级规则库物化、pi / OpenGrep 运行时自举（OpenGrep 带
SHA-256 逐字节校验）、凭据入库（chmod 600）、INFO.md 模板。按模板填好
INFO.md（业务 / 核心资产 / 信任边界），它直接注入判定 prompt、提升判定质量。

**4. 体检**：`fiora doctor` 的 node / pi-runtime / opengrep / rules / config /
credentials 六项必需项必须全 ✓ 才算配好。
- opengrep ✗ 且提示下载失败 → 重跑 `fiora init`（幂等自愈）；
- docker ✗ → 正常，只是「主动验证」关闭，不装。

**5. 冒烟**（三件都要真跑）

```bash
fiora scan --root <目标仓库>      # 规则通道出候选
fiora profile --root <目标仓库>   # 模型链路打通（画像落账，--refresh 可重提）
fiora status --root <目标仓库>    # 账本正常
```

**6. 交付配置终表**：组件（fiora / node / pi / opengrep / 规则条数 / 模型 /
docker 能力项）× 版本路径状态，附 `fiora doctor` 原文，以及下一步指引：
接着要审计就按 [SKILL.md](../SKILL.md) 干活；纯 CLI 走 [USAGE](USAGE.md)。

失败处理：按提示自修（init 幂等，可反复跑）；同一问题连续两次失败就停下，
带完整报错找用户。
