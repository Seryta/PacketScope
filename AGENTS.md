# Multi-Agent Protocol

本文件是 PacketScope 仓库内**多个 AI agent 协作的持久化契约**。新加入的 agent
读完本文件就能立即开工，不需要靠口头交接。本文件随 git 跟踪，跨机器跨克隆始终
存在；动态的往返信件放在 gitignored 的 `reviews/` 目录里。

**Protocol version: 1**（不向后兼容的变更要 bump，并在末尾 Changelog 留痕）

---

## 1. 设计原则

1. **窄通道**：agent 之间只通过 `reviews/*.md` 文件交换信息，**不读对方的 chat
   transcript**。
2. **结构化**：信件格式固定（见 §4），便于机器/人快速 diff。
3. **单向 + 一轮一封**：reviewer 写 findings → coder 写 response → reviewer 看
   response + 新代码写下一轮 findings。**不要在同一封信里来回改**。
4. **避免自污染**：每个 agent 只读"输入"（对方的最新一封），不读自己的旧信件，
   也不读对方更早的历史信件——防止被自己/对方的旧思路锁死。

---

## 2. 角色

| Role | 读 | 写 | 工作内容 |
| --- | --- | --- | --- |
| **reviewer** | 当前 HEAD 源码 + `reviews/vX.Y-roundN.response.md`（若是首轮则无） | `reviews/vX.Y-round(N+1).md` | 审计代码，给 findings |
| **coder** | 当前 HEAD 源码 + `reviews/vX.Y-roundN.md`（最新一封 findings） | 源码 + `reviews/vX.Y-roundN.response.md` | 修代码，逐条回复 |

**计划中的扩展角色**（暂未启用，命名先占住）：

- `security-reviewer` — 安全专项审计，独立的 finding 命名前缀 `S-NNN`
- `test-author` — 补测试，独立的 finding 命名前缀 `T-NNN`
- `doc-writer` — 同步文档，独立的 finding 命名前缀 `D-NNN`

新角色启用时在本文件 §2 加一行，不改协议主体。

---

## 3. 文件布局

```
PacketScope/
├── AGENTS.md                          ← 本文件，tracked
├── reviews/                           ← gitignored
│   ├── v0.6-round1.md                 ← reviewer 写
│   ├── v0.6-round1.response.md        ← coder 写
│   ├── v0.6-round2.md
│   ├── v0.6-round2.response.md
│   └── ...
```

**命名规则**：`v<milestone>-round<N>.md` / `v<milestone>-round<N>.response.md`

- `milestone`：跟项目 VERSION 走（当前 v0.6）。同一个 milestone 内可以多轮。
- `N`：从 1 起，每轮 +1。
- response 文件名 = findings 文件名 + `.response.md`。

---

## 4. 信件格式

### 4.1 Findings letter（reviewer → coder）

必备结构：

```markdown
# Review: vX.Y round N

- Reviewer: <model + session id 或简称>
- Date: YYYY-MM-DD
- Scope: 本轮审什么（全量？某模块？回归 round N-1 的修复？）
- Base commit: <git hash>
- 总评：≤ 3 行

## 本轮临时约束（可选，覆盖本文件 §5 的标准规则）
- ...

## Findings

### F-NNN [P0|P1|P2|P3] <一句话标题>
- File: path/to/file.kt:line   ← 必填，精确到行号最好
- Issue: 评估到的问题，给证据（引用代码片段或行为）
- Suggested: 具体改什么。给方案 A/B 时标 **推荐**
- Status: open                  ← reviewer 写出来时永远 open

### F-NNN+1 ...

## 不在 findings 范围的观察（可选）
- ...
```

**Finding 编号**：`F-NNN`，零填充 3 位，**在本封信内**单调递增；跨信件不复用，
所以下一轮从 `F-001` 重新开始，不接着 round1 编号。如要引用上轮的 finding，写
`v0.6-round1.F-007`。

**优先级**：

- **P0** — 上架/发版前必修，或者是正确性 bug
- **P1** — 用户能感知的体验/性能问题
- **P2** — 工程细节，影响维护性
- **P3** — 可以放进 backlog，争议留给 reviewer 判断

### 4.2 Response letter（coder → reviewer）

逐条对应 findings letter 的每个 F-NNN，**不许漏**。格式：

```markdown
# Response: vX.Y round N

- Coder: <model + session id 或简称>
- Date: YYYY-MM-DD
- Input: reviews/vX.Y-roundN.md

## F-NNN: <status>
- Commit: <hash> 或 "—"（无 commit）
- Notes: ≤ 3 行，说改了什么或为什么没改

## F-NNN+1: ...
```

**status** 取值：

| 值 | 含义 |
| --- | --- |
| `fixed` | 已修，commit 列出来 |
| `partially-fixed` | 改了一部分，剩下的部分说明为什么留待下一轮 |
| `deferred` | 同意改但本轮不做，给出 deferred 到哪个 milestone |
| `wontfix` | 拒绝修，必须给理由 |
| `needs-discussion` | 有歧义或与你判断冲突，写下反驳理由——下一轮 reviewer 回应 |

**禁止静默跳过任何 finding**。

---

## 5. 标准规则（除非信件 §临时约束 覆盖，否则默认生效）

### 5.1 处理顺序与提交

- 顺序：P0 → P1 → P2 → P3
- 一条 finding 可拆多个 commit；**不要**把无关 finding 合并成一个 commit
- commit message 格式：`<type>(<scope>): <subject>` + body + 可选 footer
- **不带 Claude / AI co-author 等任何 AI 相关声明**（用户全局约定）
- `git add <specific-files>`，**不要** `git add .` / `git add -A`
- **不要 push**，除非用户明确指示

### 5.2 构建与测试

- 项目规则：**不在宿主机直接构建**，全走 docker（见 README §构建）
- docker 命令带 `--user $(id -u):$(id -g)` 避免产出 root-owned 文件
- 每条 finding 改完跑一次相关测试或 `assembleDebug`，确认没回退后再下一条
- 不允许 `--no-verify` 跳 pre-commit hook

### 5.3 阅读纪律（防污染）

- 只读：
  1. 当前 HEAD 源码
  2. **最新一封**对方的信件（reviewer 读 response，coder 读 findings）
  3. 本 AGENTS.md
- **不读**：
  - 对方的 chat transcript
  - 自己上一轮的信件（避免循环辩护）
  - 对方更早历史信件（如要回溯背景，应通过当前最新信件里的引用 `v0.6-round1.F-007` 跳查）

### 5.4 冲突 / 拿不准

- 标 `needs-discussion`，写下反驳理由
- **不要**硬改、不要静默跳过
- 下一轮 reviewer 会回应；如还谈不拢，用户介入仲裁

---

## 6. 启动 prompt（直接复制给新 agent）

### 6.1 启动 reviewer

```
读仓库根的 AGENTS.md，
然后读 reviews/ 目录里最新的 vX.Y-roundN.response.md（若是首轮则跳过），
查看当前代码状态，按 AGENTS.md §4.1 写 reviews/vX.Y-round(N+1).md。
```

### 6.2 启动 coder

```
读仓库根的 AGENTS.md，
然后读 reviews/ 目录里最新的 vX.Y-roundN.md，
按 AGENTS.md §5 工作流程修代码 + 写 reviews/vX.Y-roundN.response.md。
全部 docker 构建，commit 不带 Claude 声明。
```

把 `X.Y` 和 `N` 换成实际版本号和轮次即可。

---

## Changelog

- **v1** (2026-05-16): initial protocol. 角色：reviewer / coder。
