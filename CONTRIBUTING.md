# Contributing to PacketScope

Quick rules. 完整背景见 [`ARCHITECTURE.md`](ARCHITECTURE.md) +
[`ANDROID_PITFALLS.md`](ANDROID_PITFALLS.md)。

---

## 1. 提交前自检 checklist

任何 PR 提交前过一遍：

### 文本 / i18n
- [ ] 新加的所有 user-facing 文本走 `R.string` / `R.plurals`
- [ ] 任何含 `%d` 的字符串想想是不是该用 `<plurals>`（"1 packets" 是错的）
- [ ] `values/strings.xml` 不带首尾空白；间距在调用点用 `Spacer` / 拼接补
- [ ] `values/` + `values-zh/` 的 key **一一对应**
- [ ] 测试断言用 `context.getString(R.string.xxx)`，不硬编码中文 / 英文

### 错误处理
- [ ] core 层抛的 Exception 用 sealed `ErrorXxx` 类型，不持有 user-facing 字符串
- [ ] UI 层 @Composable helper 把 sealed error 映射到 `stringResource`
- [ ] 错误测试断言 `e.error is X.Y`，不断 `e.message.contains(...)`

### Android 平台
- [ ] 加 `ContentResolver` / 落盘 → 看 `res/xml/data_extraction_rules.xml`
      要不要 exclude
- [ ] 加 `ForegroundService` → 加 `foregroundServiceType` + type-permission
- [ ] 加通知 → smallIcon 纯 fillColor 不用 strokeWidth；channel name locale 更新
- [ ] 升 `compileSdk` → 测试 `@Config(sdk=...)` 同步 + 重录 Roborazzi 基线

### 数据 / 性能
- [ ] `data class` 含 `ByteArray` → 想 equals 语义；没 `copy()` 就去 `data`
- [ ] `Field("...", ...)` 第一参数走 `FieldNames.X`，不写字面量
- [ ] `layer.protocol == "X"` 走 `Protocols.X`，不写字面量
- [ ] filter / 热路径上 `lowercase()` 在构造时缓存，不每次匹配重算

### 安全
- [ ] 敏感 ByteArray 释放前 `fill(0)`（不依赖 GC）
- [ ] `load()` 替换路径也走 `clear()` 复用，不内联 map clear

### Baseline 守护
- [ ] 新 lint issue 入 `app/lint-baseline.xml` 时，必须先升
      `LintBaselineGuardTest.maxAllowedIssues` 并在 commit message 写清
      来源。建议优先修代码消除 issue 而非提高上限。
- [ ] 新 detekt issue 入 `config/detekt/detekt-baseline.xml` 时，必须先升
      `DetektBaselineGuardTest.maxAllowedIssues` 并在 commit message
      写清来源。

### Commit
- [ ] commit message 格式：`<type>(<scope>): <subject>` + body
- [ ] body 引用 review finding：`review v0.X-roundN F-NNN`
- [ ] **不带 Claude / AI 任何 co-author 声明**
- [ ] 一条 finding 可拆多 commit，不同 finding 不合并

---

## 2. 本地验证

```bash
# 静态分析
./gradlew :app:lintDebug detekt

# 单测
./gradlew :app:testDebugUnitTest

# UI 视觉回归
./gradlew verifyRoborazziDebug
# UI 改了文本 / API / SDK 时先重录基线：
./gradlew recordRoborazziDebug
```

所有命令走 docker（项目规则，不在宿主直接构建）：

```bash
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$PWD":/work -w /work \
  -v "$HOME/.gradle-docker":/work/.gradle-cache \
  -e GRADLE_USER_HOME=/work/.gradle-cache \
  mingc/android-build-box:latest \
  ./gradlew assembleDebug
```

详见 [README §构建](README.md#构建)。

---

## 3. 推送 / 镜像

仓库主仓在 **GitHub** (`https://github.com/Seryta/PacketScope`)。
项目可能配置了私有镜像（不公开），公开贡献者只需关注 GitHub。

本地最小 remote 配置：

```bash
git remote -v
# github   https://github.com/Seryta/PacketScope.git (fetch/push)
```

单 remote 即可参与开发。如果你想同时推到自己的私有镜像，本地额外加
remote：

```bash
git remote add mirror https://your-private-git/path/to/PacketScope.git
git push github master && git push mirror master
```

**不**配置单 remote 双 push URL（`git remote set-url --add --push`）——
一边失败另一边部分推完会让状态混乱。**两条显式 `git push` 命令**更清楚。

CI 只跑在 GitHub（`.github/workflows/ci.yml`）。

发版 tag push：见 [RELEASE.md §6 GitHub Releases](RELEASE.md#github-releases-推荐自动化路径)。

## 4. Review 协议

仓库用 reviewer / coder 多 agent 协作协议，见 [`AGENTS.md`](AGENTS.md)。
信件在 `reviews/`（gitignore），commit message 引用 finding 编号永存。

---

## 5. 提问 / 异议

- 平台陷阱型 → 加进 [`ANDROID_PITFALLS.md`](ANDROID_PITFALLS.md)
- 架构边界型 → 加进 [`ARCHITECTURE.md`](ARCHITECTURE.md)
- 跟当前约定有冲突 → 别静默改，开 review letter 标 `needs-discussion`
