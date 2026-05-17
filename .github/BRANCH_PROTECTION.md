# GitHub Branch Protection 配置

仓库首次推到 GitHub 公开后，到 **Settings → Branches → Add branch ruleset**
按下面配置 `master`，避免任何人（包括自己）直接 push 跳过 review +
CI 守约定。

## 推荐规则集

新建 ruleset，target = `master`，启用：

- **Restrict deletions**：✅ —— 防止误删 master
- **Require linear history**：✅ —— 拒 merge commit，逼用 PR squash / rebase
- **Require a pull request before merging**：✅
  - **Required approvals**：`1`
  - **Dismiss stale pull request approvals when new commits are pushed**：✅
  - **Require approval of the most recent reviewable push**：✅
- **Require status checks to pass**：✅
  - **Require branches to be up to date before merging**：✅
  - Status check：`verify`（来自 `.github/workflows/ci.yml` 的 job 名）
- **Block force pushes**：✅ —— 唯一例外是 v0.6-round0 HIST-002 那一次重组
  推送，需要临时关或自己 bypass

## Solo dev 折中

Required approvals = 1 在 solo 项目下意味着自己点不到 "Approve"
（GitHub 禁止 PR 作者 approve 自己）。两种选择：

1. **保留 approvals = 1**：每次重要 PR 找一个外部 reviewer，逼自己写
   清楚 PR 描述
2. **设 approvals = 0**：但仍要求 status check 通过 — 至少 CI 必须绿才
   能 merge

我用方案 2（solo dev 务实选择），可以随仓库规模扩大切换到方案 1。

## Bypass list

Settings → Branches → Ruleset → Bypass list 加自己（owner），允许：

- 紧急修复直 push（生产 outage 这种场景）
- HIST 重组那种"代码层面 ok 但要 force push" 操作

每次 bypass 都会留 audit log。

## 验证

配完后：

1. Push 一个 master 直推应该被拒（除非在 bypass list 内）
2. 提个 PR 看 status check 自动出现 "verify" 项，需要绿才能 merge
3. PR merge 后 master 历史保持 linear（无合并提交，rebase 或 squash）

参考链接：

- [GitHub: About protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub: Rulesets vs branch protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
